import { lookup } from 'node:dns/promises';
import { Agent } from 'undici';
import { TransportError } from './errors.js';
import type { RciRequestControls, RciSession } from './rci.js';
import { RemoteSession, type RemoteSessionOptions } from './remote-session.js';
import type { EdgePool } from './edge-pool.js';

export interface FallbackRemoteSessionOptions extends RemoteSessionOptions {
  resolveDns?: (hostname: string) => Promise<readonly string[]>;
  createAgent?: (ip: string) => Agent;
  maxFallbackAttempts?: number;
}

async function defaultResolveDns(hostname: string): Promise<readonly string[]> {
  return (await lookup(hostname, { all: true, verbatim: true })).map(result => result.address);
}

export function defaultCreateAgent(ip: string, tlsOptions?: Record<string, unknown>): Agent {
  const isIpv6 = ip.includes(':');
  return new Agent({
    connect: {
      rejectUnauthorized: true,
      ...tlsOptions,
      lookup: (_hostname, _options, callback) => {
        const cb = typeof _options === 'function' ? _options : callback;
        const opts = typeof _options === 'object' && _options !== null ? _options : {};
        if (opts.all) {
          cb(null, [{ address: ip, family: isIpv6 ? 6 : 4 }]);
        } else {
          cb(null, ip, isIpv6 ? 6 : 4);
        }
      }
    }
  });
}

export class FallbackRemoteSession implements RciSession {
  private readonly resolveDns: (hostname: string) => Promise<readonly string[]>;
  private readonly createAgent: (ip: string) => Agent;
  private readonly now: () => number;
  private readonly maxFallbackAttempts: number;
  private readonly activeAgents = new Set<Agent>();

  constructor(
    private readonly inner: RemoteSession,
    private readonly pool: EdgePool,
    private readonly opts: FallbackRemoteSessionOptions
  ) {
    this.resolveDns = opts.resolveDns ?? defaultResolveDns;
    this.createAgent = opts.createAgent ?? defaultCreateAgent;
    this.now = opts.now ?? Date.now;
    this.maxFallbackAttempts = opts.maxFallbackAttempts ?? 2;
  }

  get activeAgentCount(): number {
    return this.activeAgents.size;
  }

  effectiveTimeoutMs(requestedMs: number): number {
    return Math.min(this.opts.timeoutMs ?? 10_000, requestedMs);
  }

  async request(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
    controls: RciRequestControls = {}
  ): Promise<Response> {
    const totalTimeoutMs = this.effectiveTimeoutMs(controls.timeoutMs ?? Number.POSITIVE_INFINITY);
    const deadline = this.now() + totalTimeoutMs;

    try {
      return await this.inner.request(method, path, body, controls);
    } catch (error) {
      if (!(error instanceof TransportError)) {
        throw error;
      }
      if (controls.signal?.aborted) {
        throw error;
      }
      const remainingMs = deadline - this.now();
      if (remainingMs <= 0) {
        throw error;
      }

      return await this.fallback(method, path, body, controls, deadline, error);
    }
  }

  private async fallback(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
    controls: RciRequestControls,
    deadline: number,
    originalError: TransportError
  ): Promise<Response> {
    const hostname = new URL(this.opts.endpoint).hostname;
    let resolvedIps: readonly string[] = [];
    try {
      resolvedIps = await this.resolveDns(hostname);
    } catch {
      // DNS resolution failed; pool might still have candidates
    }

    for (const ip of resolvedIps) {
      this.pool.observe(ip);
    }

    const attempted = new Set<string>(resolvedIps);
    const candidates = this.pool.candidates(attempted, this.maxFallbackAttempts);

    if (candidates.length === 0) {
      throw originalError;
    }

    let lastTransportError = originalError;

    for (const candidateIp of candidates) {
      const candidateRemainingMs = deadline - this.now();
      if (candidateRemainingMs <= 0 || controls.signal?.aborted) {
        throw lastTransportError;
      }

      const agent = this.createAgent(candidateIp);
      this.activeAgents.add(agent);
      let succeeded = false;

      try {
        const baseFetch = this.opts.fetch ?? fetch;
        const fallbackFetch: typeof fetch = (input, init) => {
          return baseFetch(input, {
            ...init,
            dispatcher: agent as unknown as NonNullable<RequestInit['dispatcher']>
          });
        };

        const tempSession = new RemoteSession({
          ...this.opts,
          fetch: fallbackFetch,
          timeoutMs: candidateRemainingMs,
        });

        const tempControls: RciRequestControls = { timeoutMs: candidateRemainingMs };
        if (controls.signal !== undefined) {
          tempControls.signal = controls.signal;
        }

        const response = await tempSession.request(method, path, body, tempControls);

        this.pool.recordSuccess(candidateIp);
        succeeded = true;
        agent.close()
          .catch(() => undefined)
          .finally(() => this.activeAgents.delete(agent));

        return response;
      } catch (fallbackError) {
        if (!succeeded) {
          agent.destroy()
            .catch(() => undefined)
            .finally(() => this.activeAgents.delete(agent));
        }

        if (fallbackError instanceof TransportError) {
          if (controls.signal?.aborted) {
            throw fallbackError;
          }
          this.pool.recordFailure(candidateIp);
          attempted.add(candidateIp);
          lastTransportError = fallbackError;
        } else {
          throw fallbackError;
        }
      }
    }

    throw lastTransportError;
  }

  async close(): Promise<void> {
    const agents = [...this.activeAgents];
    this.activeAgents.clear();
    await Promise.allSettled(agents.map(a => a.close()));
  }
}
