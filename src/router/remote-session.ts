import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes } from 'node:crypto';
import { channel } from 'node:diagnostics_channel';
import { lookup as systemLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import type { Socket } from 'node:net';
import { isIP } from 'node:net';
import type { ConnectionOptions } from 'node:tls';
import { Agent, buildConnector, fetch as undiciFetch, type Dispatcher } from 'undici';
import { AuthError, RemoteCapabilityError, TransportError } from './errors.js';
import { EdgePool, canonicalIp } from './edge-pool.js';
import { redactText } from '../security/redact.js';
import type { RciRequestControls } from './rci.js';

export interface RemoteSessionOptions {
  endpoint: string; login: string; password: string; routerId: string;
  timeoutMs?: number; attempts?: number; fetch?: typeof globalThis.fetch;
  sleep?: (ms: number) => Promise<void>; random?: () => number;
  now?: () => number;
}

type LookupCallback = (...args: [
  error: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number
]) => void;
type Lookup = (hostname: string, options: LookupOptions, callback: LookupCallback) => void;

interface RemoteSessionDependencies {
  lookup?: Lookup;
  ca?: ConnectionOptions['ca'];
  edgePool?: EdgePool;
  onPinnedAgent?: (agent: Agent, ip: string) => void;
}

type OwnerToken = object;

interface SendContext {
  readonly owner: OwnerToken;
  readonly origin: string;
  readonly attempted: Set<string>;
  active: boolean;
  correlationComplete: boolean;
}

interface NormalAttempt {
  readonly selected: Set<string>;
  readonly supplied: Set<string>;
  readonly observation: Set<string>;
  correlationComplete: boolean;
}

interface RequestBinding {
  readonly context: SendContext;
  readonly attempt: NormalAttempt;
}

interface ConnectorRecord {
  readonly owner: OwnerToken;
  readonly supplied: Set<string>;
  lookupSucceeded: boolean;
  observationClaimed: boolean;
}

interface BodySnapshot {
  readonly provided: boolean;
  readonly serialized: string | null;
}

const requestCreation = new AsyncLocalStorage<RequestBinding>();
const connectorCreation = new AsyncLocalStorage<ConnectorRecord>();
const requestBindings = new WeakMap<object, RequestBinding>();
const socketConnectors = new WeakMap<object, ConnectorRecord>();
const errorConnectors = new WeakMap<object, ConnectorRecord>();
let diagnosticsInstalled = false;

function objectValue(value: unknown): object | null {
  return (typeof value === 'object' && value !== null) || typeof value === 'function'
    ? value as object
    : null;
}

function messageField(message: unknown, key: string): unknown {
  return typeof message === 'object' && message !== null
    ? (message as Record<string, unknown>)[key]
    : undefined;
}

function sameOrigin(value: unknown, expected: string): boolean {
  if (value === undefined) return true;
  try {
    return new URL(String(value)).origin === expected;
  } catch {
    return false;
  }
}

function copyConnectorEvidence(record: ConnectorRecord, attempt: NormalAttempt): void {
  for (const ip of record.supplied) attempt.supplied.add(ip);
  if (record.lookupSucceeded && !record.observationClaimed) {
    record.observationClaimed = true;
    for (const ip of record.supplied) attempt.observation.add(ip);
  }
}

function installDiagnosticsBridge(): void {
  if (diagnosticsInstalled) return;
  diagnosticsInstalled = true;

  channel('undici:request:create').subscribe(message => {
    try {
      const binding = requestCreation.getStore();
      const request = objectValue(messageField(message, 'request'));
      if (binding === undefined || request === null || !binding.context.active) return;
      if (!sameOrigin(messageField(request, 'origin'), binding.context.origin)) return;
      requestBindings.set(request, binding);
    } catch {
      // Diagnostics must never alter the request being observed.
    }
  });

  channel('undici:client:sendHeaders').subscribe(message => {
    try {
      const request = objectValue(messageField(message, 'request'));
      const socket = objectValue(messageField(message, 'socket'));
      if (request === null || socket === null) return;
      const binding = requestBindings.get(request);
      const connector = socketConnectors.get(socket);
      if (binding === undefined || connector === undefined || !binding.context.active ||
          binding.context.owner !== connector.owner) return;
      const remoteAddress = canonicalIp((socket as Socket).remoteAddress ?? '');
      if (remoteAddress === null ||
          (connector.supplied.size > 0 && !connector.supplied.has(remoteAddress))) return;
      copyConnectorEvidence(connector, binding.attempt);
      binding.attempt.selected.add(remoteAddress);
      binding.context.attempted.add(remoteAddress);
      binding.attempt.correlationComplete = true;
    } catch {
      // Malformed and unmanaged messages are intentionally ignored.
    }
  });

  channel('undici:request:error').subscribe(message => {
    try {
      const request = objectValue(messageField(message, 'request'));
      const error = objectValue(messageField(message, 'error'));
      if (request === null || error === null) return;
      const binding = requestBindings.get(request);
      const connector = errorConnectors.get(error);
      if (binding === undefined || connector === undefined || !binding.context.active ||
          binding.context.owner !== connector.owner) return;
      copyConnectorEvidence(connector, binding.attempt);
      for (const ip of connector.supplied) binding.context.attempted.add(ip);
      binding.attempt.correlationComplete = true;
    } catch {
      // Error text, request headers and request bodies are never inspected.
    }
  });
}

installDiagnosticsBridge();

type Challenge = { scheme: string; params: Record<string, string> };
type AuthorizationState =
  | { kind: 'none' }
  | { kind: 'basic' }
  | { kind: 'digest'; challenge: Challenge; cnonce: string; nonceCount: number };
const hash = (algorithm: string, value: string): string =>
  createHash(algorithm.replace('-sess', '').toLowerCase()).update(value).digest('hex');

function isReplaySafe(method: string, url: URL, body: BodySnapshot,
  allowRetry: boolean): boolean {
  if (!allowRetry) return false;
  if (method === 'GET') return true;
  if (method !== 'POST' || url.pathname !== '/rci/' || url.search !== '' ||
      body.serialized === null) return false;
  let value: unknown;
  try {
    value = JSON.parse(body.serialized);
  } catch {
    return false;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const entries = Object.entries(value as Record<string, unknown>);
  const show = entries[0]?.[1];
  return entries.length === 1 && entries[0]?.[0] === 'show' &&
    typeof show === 'object' && show !== null && !Array.isArray(show);
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
  const qops = (p['qop'] ?? '').split(',').map(value => value.trim().toLowerCase());
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
  private readonly owner: OwnerToken = {};
  private readonly pool: EdgePool;
  private readonly normalAgent: Agent;
  private readonly lookup: Lookup;
  private readonly cleanup = new Set<Promise<void>>();

  constructor(
    private readonly opts: RemoteSessionOptions,
    private readonly dependencies: RemoteSessionDependencies = {}
  ) {
    this.pool = dependencies.edgePool ?? new EdgePool(
      opts.now === undefined ? {} : { now: opts.now }
    );
    this.lookup = dependencies.lookup ?? systemLookup as Lookup;
    const connector = buildConnector({
      rejectUnauthorized: true,
      ...(dependencies.ca === undefined ? {} : { ca: dependencies.ca }),
      lookup: this.observedLookup.bind(this)
    });
    this.normalAgent = new Agent({ connect: (options, callback) => {
      const record: ConnectorRecord = {
        owner: this.owner,
        supplied: new Set(),
        lookupSucceeded: false,
        observationClaimed: false
      };
      connectorCreation.run(record, () => {
        try {
          connector(options, (error, socket) => {
            if (error !== null) {
              errorConnectors.set(error, record);
              callback(error, null);
            } else {
              socketConnectors.set(socket, record);
              callback(null, socket);
            }
          });
        } catch (error) {
          if (error instanceof Error) {
            errorConnectors.set(error, record);
            callback(error, null);
          } else {
            throw error;
          }
        }
      });
    } });
  }

  effectiveTimeoutMs(requestedMs: number): number {
    return Math.min(this.opts.timeoutMs ?? 10_000, requestedMs);
  }

  async request(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown,
    controls: RciRequestControls = {}): Promise<Response> {
    const base = new URL(this.opts.endpoint);
    const url = path === '/rci/' ? base : new URL(path, base.origin);
    const deadline = this.now() + this.effectiveTimeoutMs(
      controls.timeoutMs ?? Number.POSITIVE_INFINITY
    );
    if (controls.signal?.aborted) {
      throw this.transportError('request cancelled before it started', method, url);
    }
    const bodySnapshot: BodySnapshot = {
      provided: body !== undefined,
      serialized: body === undefined ? null : JSON.stringify(body) ?? null
    };

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
          discoveryUrl, discoveryIsOperational
            ? bodySnapshot
            : { provided: false, serialized: null }, sharedDeadline,
          controller.signal, discoveryIsOperational).finally(() => {
          flight.settled = true;
          if (this.handshake === flight) this.handshake = null;
        });
        // Every caller can independently leave the shared flight. Keep the
        // flight's eventual rejection observed when the final waiter cancels.
        void flight.promise.catch(() => undefined);
        this.handshake = flight;
        const direct = await this.waitForHandshake(flight, deadline, method, url, controls.signal);
        if (direct && discoveryIsOperational) return this.classify(direct, method, url);
      }
    }

    let response = await this.send(method, url, bodySnapshot, deadline, true, controls.signal);
    if (response.status === 401) {
      this.acceptChallenge(response, method, url);
      response = await this.send(method, url, bodySnapshot, deadline, true, controls.signal);
    }
    return this.classify(response, method, url);
  }

  private observedLookup(hostname: string, options: LookupOptions, callback: LookupCallback): void {
    const record = connectorCreation.getStore();
    this.lookup(hostname, options, (...args) => {
      const [error, address] = args;
      try {
        if (record !== undefined && error === null) {
          record.lookupSucceeded = true;
          const values = Array.isArray(address) ? address.map(item => item.address) : [address];
          for (const value of values) {
            const ip = canonicalIp(value);
            if (ip !== null) record.supplied.add(ip);
          }
        }
      } catch {
        // Forward the real resolver result even if passive bookkeeping fails.
      }
      callback(...args);
    });
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

  private async discoverAuthorization(method: string, url: URL, body: BodySnapshot, deadline: number,
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
    const digest = offered.find(challenge => challenge.scheme === 'digest');
    const basic = offered.find(challenge => challenge.scheme === 'basic');
    if (digest) this.authorization = {
      kind: 'digest', challenge: digest, cnonce: randomBytes(12).toString('hex'), nonceCount: 0
    };
    else if (basic) this.authorization = { kind: 'basic' };
    else throw this.authError('HTTP 401 without a supported Digest or Basic challenge', method, url);
  }

  private async send(method: string, url: URL, body: BodySnapshot, deadline: number,
    authenticate = true,
    signal?: AbortSignal, allowRetry = true): Promise<Response> {
    const replaySafe = isReplaySafe(method, url, body, allowRetry);
    const attempts = replaySafe ? this.opts.attempts ?? 5 : 1;
    const authorization = authenticate ? this.authorizationHeader(method, url) : null;
    const context: SendContext = {
      owner: this.owner,
      origin: url.origin,
      attempted: new Set(),
      active: true,
      correlationComplete: true
    };

    try {
      for (let attemptNumber = 1; ; attemptNumber += 1) {
        const remaining = deadline - this.now();
        if (remaining <= 0) throw this.transportError('request deadline exceeded', method, url);
        const headers: Record<string, string> = { accept: 'application/json' };
        if (authorization) headers['authorization'] = authorization;
        if (body.provided) headers['content-type'] = 'application/json';
        const attempt: NormalAttempt = {
          selected: new Set(),
          supplied: new Set(),
          observation: new Set(),
          correlationComplete: false
        };
        const timeout = AbortSignal.timeout(Math.max(1, Math.ceil(remaining)));
        const attemptSignal = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);

        try {
          const response = await this.fetch(url, {
            method,
            headers,
            ...(body.provided ? { body: body.serialized } : {}),
            signal: attemptSignal,
            redirect: 'manual'
          }, this.normalAgent, { context, attempt });
          this.finishNormalAttempt(attempt, 'success');
          return response;
        } catch (cause) {
          const finalAttempt = attemptNumber >= attempts;
          const interrupted = signal?.aborted || timeout.aborted || deadline <= this.now();
          if (!finalAttempt) {
            this.finishNormalAttempt(attempt, interrupted ? 'neutral' : 'failure');
          }
          context.correlationComplete &&= attempt.correlationComplete;
          if (signal?.aborted) throw this.transportError('request cancelled', method, url);
          if (timeout.aborted || deadline <= this.now()) {
            throw this.transportError('request deadline exceeded', method, url);
          }
          if (finalAttempt) {
            const original = this.transportError(
              `failed after ${attempts} attempts: ${redactText(this.causeMessage(cause))}`,
              method,
              url
            );
            if (!replaySafe || !context.correlationComplete) {
              this.finishNormalAttempt(attempt, 'failure');
              throw original;
            }
            return await this.fallback(
              method, url, body, headers, deadline, signal, context, attempt, original
            );
          }
          const base = 1000 * 2 ** (attemptNumber - 1);
          const delay = base * (1 + (this.opts.random ?? Math.random)() * 0.25);
          const left = deadline - this.now();
          if (delay >= left) {
            throw this.transportError('request deadline exceeded during retry backoff', method, url);
          }
          await this.retryDelay(delay, signal, method, url);
        }
      }
    } finally {
      context.active = false;
    }
  }

  private finishNormalAttempt(attempt: NormalAttempt,
    outcome: 'success' | 'failure' | 'neutral'): void {
    for (const ip of attempt.observation) this.pool.observe(ip);
    if (!attempt.correlationComplete || outcome === 'neutral') return;
    const healthSet = attempt.selected.size > 0 ? attempt.selected : attempt.supplied;
    for (const ip of healthSet) {
      if (outcome === 'success') this.pool.recordSuccess(ip);
      else this.pool.recordFailure(ip);
    }
  }

  private async fallback(method: string, url: URL, body: BodySnapshot,
    headers: Record<string, string>, deadline: number, signal: AbortSignal | undefined,
    context: SendContext, normalAttempt: NormalAttempt, original: TransportError): Promise<Response> {
    if (signal?.aborted) throw this.transportError('request cancelled', method, url);
    const now = this.now();
    // The clock read is the last synchronous admission boundary before pool evidence is committed.
    if (signal?.aborted) throw this.transportError('request cancelled', method, url);
    if (deadline <= now) {
      throw this.transportError('request deadline exceeded', method, url);
    }
    this.finishNormalAttempt(normalAttempt, 'failure');
    const candidates = this.pool.candidates(context.attempted, 2);
    if (candidates.length === 0) throw original;
    let lastError = original;

    for (const ip of candidates) {
      if (signal?.aborted) throw this.transportError('request cancelled', method, url);
      let remaining = deadline - this.now();
      if (remaining <= 0) throw this.transportError('request deadline exceeded', method, url);
      if (signal?.aborted) throw this.transportError('request cancelled', method, url);
      remaining = deadline - this.now();
      if (remaining <= 0) throw this.transportError('request deadline exceeded', method, url);

      let agent: Agent | undefined;
      let timeout: AbortSignal | undefined;
      try {
        const candidateAgent = this.createPinnedAgent(ip);
        agent = candidateAgent;
        try {
          this.dependencies.onPinnedAgent?.(candidateAgent, ip);
        } catch {
          // Test-only observation cannot alter the production request.
        }
        timeout = AbortSignal.timeout(Math.max(1, Math.ceil(remaining)));
        const attemptSignal = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
        const response = await this.fetch(url, {
          method,
          headers,
          ...(body.provided ? { body: body.serialized } : {}),
          signal: attemptSignal,
          redirect: 'manual'
        }, candidateAgent);
        this.pool.recordSuccess(ip);
        this.trackCleanup(() => candidateAgent.close());
        return response;
      } catch (cause) {
        if (agent !== undefined) {
          const failedAgent = agent;
          this.trackCleanup(() => failedAgent.destroy());
        }
        if (signal?.aborted) throw this.transportError('request cancelled', method, url);
        if (timeout?.aborted) throw this.transportError('request deadline exceeded', method, url);
        if (deadline <= this.now()) throw this.transportError('request deadline exceeded', method, url);
        this.pool.recordFailure(ip);
        lastError = this.transportError(
          `pool fallback failed: ${redactText(this.causeMessage(cause))}`,
          method,
          url
        );
      }
    }
    throw lastError;
  }

  private createPinnedAgent(ip: string): Agent {
    const family = isIP(ip);
    const lookup: Lookup = (_hostname, options, callback) => {
      if (options.all) callback(null, [{ address: ip, family }]);
      else callback(null, ip, family);
    };
    return new Agent({ connect: buildConnector({
      rejectUnauthorized: true,
      ...(this.dependencies.ca === undefined ? {} : { ca: this.dependencies.ca }),
      lookup
    }) });
  }

  private fetch(url: URL, init: Omit<RequestInit, 'dispatcher'>, dispatcher: Dispatcher,
    binding?: RequestBinding): Promise<Response> {
    const fetcher = (this.opts.fetch ?? undiciFetch) as unknown as (
      input: URL,
      options: Omit<RequestInit, 'dispatcher'> & { dispatcher: Dispatcher }
    ) => Promise<Response>;
    const invoke = (): Promise<Response> => fetcher(url, { ...init, dispatcher });
    if (binding === undefined) return invoke();
    let result: Promise<Response> | undefined;
    requestCreation.run(binding, () => { result = invoke(); });
    return result!;
  }

  private trackCleanup(action: () => Promise<void>): void {
    let cleanup: Promise<void>;
    try {
      cleanup = action();
    } catch {
      return;
    }
    let tracked: Promise<void>;
    tracked = cleanup.catch(() => undefined).finally(() => this.cleanup.delete(tracked));
    this.cleanup.add(tracked);
  }

  private async retryDelay(ms: number, signal: AbortSignal | undefined,
    method: string, url: URL): Promise<void> {
    if (signal?.aborted) {
      throw this.transportError('request cancelled during retry backoff', method, url);
    }
    const sleeper = (this.opts.sleep ??
      (delayMs => new Promise(resolve => setTimeout(resolve, delayMs))))(ms);
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
    if (state.kind === 'basic') {
      return `Basic ${Buffer.from(`${this.opts.login}:${this.opts.password}`).toString('base64')}`;
    }
    state.nonceCount += 1;
    return digestAuthorization({ challenge: state.challenge, username: this.opts.login,
      password: this.opts.password, method, uri: `${url.pathname}${url.search}`,
      cnonce: state.cnonce, nonceCount: state.nonceCount });
  }

  private async withinDeadline<T>(promise: Promise<T>, deadline: number, method: string, url: URL,
    signal?: AbortSignal): Promise<T> {
    if (signal?.aborted) {
      throw this.transportError('request cancelled while waiting for authentication', method, url);
    }
    const remaining = deadline - this.now();
    if (remaining <= 0) {
      throw this.transportError('request deadline exceeded while waiting for authentication', method, url);
    }
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
            abort = () => reject(this.transportError(
              'request cancelled while waiting for authentication', method, url
            ));
            signal.addEventListener('abort', abort, { once: true });
          }
        })
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (signal && abort) signal.removeEventListener('abort', abort);
    }
  }

  private causeMessage(cause: unknown): string {
    return cause instanceof Error ? cause.message : String(cause);
  }

  private now(): number { return (this.opts.now ?? Date.now)(); }

  private classify(response: Response, method: string, url: URL): Response {
    const candidateStartupPath = url.pathname === '/rci/more' &&
      url.searchParams.get('filename') === 'startup-config';
    if (response.status === 403 && (url.pathname.startsWith('/ci/') ||
        (candidateStartupPath && this.rciAccessProven))) {
      throw new RemoteCapabilityError(
        `[router=${this.opts.routerId} operation=${method} endpoint=${url.hostname} ` +
          `class=remote-capability] The remote proxy denied ${url.pathname} with HTTP 403.`
      );
    }
    if (response.status === 401 || response.status === 403) {
      throw this.authError(`authentication failed with HTTP ${response.status}`, method, url);
    }
    if (response.ok && url.pathname.startsWith('/rci/') && !candidateStartupPath) {
      this.rciAccessProven = true;
    }
    return response;
  }

  private authError(reason: string, operation: string, url: URL): AuthError {
    return new AuthError(
      `[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=auth] ${reason}`
    );
  }

  private transportError(reason: string, operation: string, url: URL): TransportError {
    return new TransportError(
      `[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=transport] ${reason}`
    );
  }
}
