import { createHash, randomBytes } from 'node:crypto';
import { AuthError, RemoteCapabilityError, TransportError } from './errors.js';
import { redactText } from '../security/redact.js';
import type { RciRequestControls } from './rci.js';

export interface RemoteSessionOptions {
  endpoint: string; login: string; password: string; routerId: string;
  timeoutMs?: number; attempts?: number; fetch?: typeof globalThis.fetch;
  sleep?: (ms: number) => Promise<void>; random?: () => number;
  now?: () => number;
}

type Challenge = { scheme: string; params: Record<string, string> };
type AuthorizationState =
  | { kind: 'none' }
  | { kind: 'basic' }
  | { kind: 'digest'; challenge: Challenge; cnonce: string; nonceCount: number };
const hash = (algorithm: string, value: string): string =>
  createHash(algorithm.replace('-sess', '').toLowerCase()).update(value).digest('hex');

function retryable(method: string, body: unknown): boolean {
  if (method === 'GET') return true;
  if (method !== 'POST' || !body || typeof body !== 'object' || Array.isArray(body)) return false;
  const entries = Object.entries(body as Record<string, unknown>);
  return entries.length === 1 && entries[0]?.[0] === 'show' &&
    typeof entries[0][1] === 'object' && entries[0][1] !== null;
}

export function parseChallenges(header: string): Challenge[] {
  const starts = [...header.matchAll(/(?:^|,\s*)(Digest|Basic)\s+/gi)];
  return starts.map((match, index) => {
    const start = (match.index ?? 0) + match[0].length;
    const end = starts[index + 1]?.index ?? header.length;
    const params: Record<string, string> = {};
    for (const item of header.slice(start, end).matchAll(/([\w-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g)) {
      params[item[1]!.toLowerCase()] = item[2] ?? item[3] ?? '';
    }
    return { scheme: match[1]!.toLowerCase(), params };
  });
}

export function digestAuthorization(opts: {
  challenge: Challenge; username: string; password: string; method: string; uri: string;
  cnonce?: string; nonceCount?: number;
}): string {
  const p = opts.challenge.params;
  const realm = p['realm']; const nonce = p['nonce'];
  if (!realm || !nonce) throw new AuthError('Remote Digest challenge is missing realm or nonce.');
  const algorithm = (p['algorithm'] ?? 'MD5').toUpperCase();
  if (!['MD5', 'MD5-SESS', 'SHA-256', 'SHA-256-SESS'].includes(algorithm)) {
    throw new AuthError(`Remote Digest algorithm ${algorithm} is not supported.`);
  }
  const cnonce = opts.cnonce ?? randomBytes(12).toString('hex');
  const nc = (opts.nonceCount ?? 1).toString(16).padStart(8, '0');
  let ha1 = hash(algorithm, `${opts.username}:${realm}:${opts.password}`);
  if (algorithm.endsWith('-SESS')) ha1 = hash(algorithm, `${ha1}:${nonce}:${cnonce}`);
  const ha2 = hash(algorithm, `${opts.method}:${opts.uri}`);
  const qops = (p['qop'] ?? '').split(',').map(v => v.trim().toLowerCase());
  const qop = qops.includes('auth') ? 'auth' : undefined;
  if (p['qop'] && !qop) throw new AuthError('Remote Digest challenge does not offer qop=auth.');
  const response = qop
    ? hash(algorithm, `${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : hash(algorithm, `${ha1}:${nonce}:${ha2}`);
  const fields = [`username="${opts.username.replace(/["\\]/g, '\\$&')}"`, `realm="${realm}"`,
    `nonce="${nonce}"`, `uri="${opts.uri}"`, `response="${response}"`, `algorithm=${algorithm}`];
  if (p['opaque']) fields.push(`opaque="${p['opaque']}"`);
  if (qop) fields.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`);
  return `Digest ${fields.join(', ')}`;
}

export class RemoteSession {
  private authorization: AuthorizationState | null = null;
  private handshake: {
    promise: Promise<Response | null>;
    controller: AbortController;
    waiters: number;
    settled: boolean;
  } | null = null;
  private rciAccessProven = false;
  constructor(private readonly opts: RemoteSessionOptions) {}

  effectiveTimeoutMs(requestedMs: number): number {
    return Math.min(this.opts.timeoutMs ?? 10_000, requestedMs);
  }

  async request(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown, controls: RciRequestControls = {}): Promise<Response> {
    const base = new URL(this.opts.endpoint);
    const url = path === '/rci/' ? base : new URL(path, base.origin);
    const deadline = this.now() + this.effectiveTimeoutMs(
      controls.timeoutMs ?? Number.POSITIVE_INFINITY
    );

    if (this.authorization === null) {
      const existing = this.handshake;
      if (existing) {
        await this.waitForHandshake(existing, deadline, method, url, controls.signal);
      } else {
        const controller = new AbortController();
        const sharedDeadline = this.now() + (this.opts.timeoutMs ?? 10_000);
        const discoveryIsOperational = method === 'GET';
        const discoveryUrl = discoveryIsOperational
          ? url
          : new URL('/rci/show/version', base.origin);
        const flight = { promise: Promise.resolve<Response | null>(null), controller,
          waiters: 0, settled: false };
        flight.promise = this.discoverAuthorization(discoveryIsOperational ? method : 'GET',
          discoveryUrl, discoveryIsOperational ? body : undefined, sharedDeadline,
          controller.signal, discoveryIsOperational).finally(() => {
          flight.settled = true;
          if (this.handshake === flight) this.handshake = null;
        });
        this.handshake = flight;
        const direct = await this.waitForHandshake(flight, deadline, method, url, controls.signal);
        if (direct && discoveryIsOperational) return this.classify(direct, method, url);
      }
    }

    let response = await this.send(method, url, body, deadline, true, controls.signal);
    if (response.status === 401) {
      this.acceptChallenge(response, method, url);
      response = await this.send(method, url, body, deadline, true, controls.signal);
    }
    return this.classify(response, method, url);
  }

  private async waitForHandshake(flight: NonNullable<RemoteSession['handshake']>, deadline: number,
    method: string, url: URL, signal?: AbortSignal): Promise<Response | null> {
    flight.waiters += 1;
    try {
      return await this.withinDeadline(flight.promise, deadline, method, url, signal);
    } finally {
      flight.waiters -= 1;
      if (flight.waiters === 0 && !flight.settled) flight.controller.abort();
    }
  }

  private async discoverAuthorization(method: string, url: URL, body: unknown, deadline: number,
    signal?: AbortSignal, allowRetry = true): Promise<Response | null> {
    const response = await this.send(method, url, body, deadline, false, signal, allowRetry);
    if (response.status !== 401) {
      this.authorization = { kind: 'none' };
      return response;
    }
    this.acceptChallenge(response, method, url);
    return null;
  }

  private acceptChallenge(response: Response, method: string, url: URL): void {
    const offered = parseChallenges(response.headers.get('www-authenticate') ?? '');
    const digest = offered.find(c => c.scheme === 'digest');
    const basic = offered.find(c => c.scheme === 'basic');
    if (digest) this.authorization = {
      kind: 'digest', challenge: digest, cnonce: randomBytes(12).toString('hex'), nonceCount: 0
    };
    else if (basic) this.authorization = { kind: 'basic' };
    else throw this.authError('HTTP 401 without a supported Digest or Basic challenge', method, url);
  }

  private async send(method: string, url: URL, body: unknown, deadline: number, authenticate = true,
    signal?: AbortSignal, allowRetry = true): Promise<Response> {
    // A failed transport does not tell us whether the router applied a POST.
    // Retry only GET and the known read-only `show` dispatcher form.
    const attempts = allowRetry && retryable(method, body) ? this.opts.attempts ?? 5 : 1;
    const authorization = authenticate ? this.authorizationHeader(method, url) : null;
    for (let attempt = 1; ; attempt++) {
      const remaining = deadline - this.now();
      if (remaining <= 0) throw this.transportError('request deadline exceeded', method, url);
      const headers: Record<string, string> = { accept: 'application/json' };
      if (authorization) headers['authorization'] = authorization;
      if (body !== undefined) headers['content-type'] = 'application/json';
      try {
        return await (this.opts.fetch ?? fetch)(url, { method, headers,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: signal === undefined
            ? AbortSignal.timeout(Math.max(1, Math.ceil(remaining)))
            : AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, Math.ceil(remaining)))]),
          redirect: 'manual' });
      } catch (cause) {
        if (signal?.aborted) throw this.transportError('request cancelled', method, url);
        if (deadline <= this.now()) throw this.transportError('request deadline exceeded', method, url);
        if (attempt >= attempts) throw this.transportError(`failed after ${attempts} attempts: ${redactText((cause as Error).message)}`, method, url);
        const base = 1000 * 2 ** (attempt - 1);
        const delay = base * (1 + (this.opts.random ?? Math.random)() * 0.25);
        const left = deadline - this.now();
        if (delay >= left) throw this.transportError('request deadline exceeded during retry backoff', method, url);
        await this.retryDelay(delay, signal, method, url);
      }
    }
  }

  private async retryDelay(ms: number, signal: AbortSignal | undefined,
    method: string, url: URL): Promise<void> {
    if (signal?.aborted) throw this.transportError('request cancelled during retry backoff', method, url);
    const sleeper = (this.opts.sleep ?? (delayMs => new Promise(resolve => setTimeout(resolve, delayMs))))(ms);
    if (!signal) return sleeper;
    await new Promise<void>((resolve, reject) => {
      const abort = (): void => reject(this.transportError(
        'request cancelled during retry backoff', method, url
      ));
      signal.addEventListener('abort', abort, { once: true });
      sleeper.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
    });
  }

  private authorizationHeader(method: string, url: URL): string | null {
    const state = this.authorization;
    if (state === null || state.kind === 'none') return null;
    if (state.kind === 'basic') return `Basic ${Buffer.from(`${this.opts.login}:${this.opts.password}`).toString('base64')}`;
    state.nonceCount += 1;
    return digestAuthorization({ challenge: state.challenge, username: this.opts.login,
      password: this.opts.password, method, uri: `${url.pathname}${url.search}`,
      cnonce: state.cnonce, nonceCount: state.nonceCount });
  }

  private async withinDeadline<T>(promise: Promise<T>, deadline: number, method: string, url: URL,
    signal?: AbortSignal): Promise<T> {
    const remaining = deadline - this.now();
    if (remaining <= 0) throw this.transportError('request deadline exceeded while waiting for authentication', method, url);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort: (() => void) | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_resolve, reject) => {
          timer = setTimeout(() => reject(this.transportError(
            'request deadline exceeded while waiting for authentication', method, url
          )), remaining);
          if (signal) {
            abort = () => reject(this.transportError('request cancelled while waiting for authentication', method, url));
            signal.addEventListener('abort', abort, { once: true });
          }
        })
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (signal && abort) signal.removeEventListener('abort', abort);
    }
  }

  private now(): number { return (this.opts.now ?? Date.now)(); }
  private classify(res: Response, method: string, url: URL): Response {
    const candidateStartupPath = url.pathname === '/rci/more' &&
      url.searchParams.get('filename') === 'startup-config';
    if (res.status === 403 && (url.pathname.startsWith('/ci/') ||
        (candidateStartupPath && this.rciAccessProven))) {
      throw new RemoteCapabilityError(
        `[router=${this.opts.routerId} operation=${method} endpoint=${url.hostname} ` +
          `class=remote-capability] The remote proxy denied ${url.pathname} with HTTP 403.`
      );
    }
    if (res.status === 401 || res.status === 403) throw this.authError(`authentication failed with HTTP ${res.status}`, method, url);
    if (res.ok && url.pathname.startsWith('/rci/') && !candidateStartupPath) this.rciAccessProven = true;
    return res;
  }
  private authError(reason: string, operation: string, url: URL): AuthError {
    return new AuthError(`[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=auth] ${reason}`);
  }
  private transportError(reason: string, operation: string, url: URL): TransportError {
    return new TransportError(`[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=transport] ${reason}`);
  }
}
