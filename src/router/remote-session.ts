import { createHash, randomBytes } from 'node:crypto';
import { AuthError, RemoteCapabilityError, TransportError } from './errors.js';
import { redactText } from '../security/redact.js';

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
  private handshake: Promise<Response | null> | null = null;
  constructor(private readonly opts: RemoteSessionOptions) {}

  async request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const base = new URL(this.opts.endpoint);
    const url = path === '/rci/' ? base : new URL(path, base.origin);
    const deadline = this.now() + (this.opts.timeoutMs ?? 10_000);

    if (this.authorization === null) {
      const existing = this.handshake;
      if (existing) {
        await this.withinDeadline(existing, deadline, method, url);
      } else {
        const handshake = this.discoverAuthorization(method, url, body, deadline);
        this.handshake = handshake;
        try {
          const direct = await this.withinDeadline(handshake, deadline, method, url);
          if (direct) return this.classify(direct, method, url);
        } finally {
          if (this.handshake === handshake) this.handshake = null;
        }
      }
    }

    let response = await this.send(method, url, body, deadline);
    if (response.status === 401) {
      this.acceptChallenge(response, method, url);
      response = await this.send(method, url, body, deadline);
    }
    return this.classify(response, method, url);
  }

  private async discoverAuthorization(method: string, url: URL, body: unknown, deadline: number): Promise<Response | null> {
    const response = await this.send(method, url, body, deadline, false);
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

  private async send(method: string, url: URL, body: unknown, deadline: number, authenticate = true): Promise<Response> {
    // A failed transport does not tell us whether the router applied a POST.
    // Retry only GET and the known read-only `show` dispatcher form.
    const attempts = retryable(method, body) ? this.opts.attempts ?? 5 : 1;
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
          signal: AbortSignal.timeout(Math.max(1, Math.ceil(remaining))), redirect: 'manual' });
      } catch (cause) {
        if (deadline <= this.now()) throw this.transportError('request deadline exceeded', method, url);
        if (attempt >= attempts) throw this.transportError(`failed after ${attempts} attempts: ${redactText((cause as Error).message)}`, method, url);
        const base = 1000 * 2 ** (attempt - 1);
        const delay = base * (1 + (this.opts.random ?? Math.random)() * 0.25);
        const left = deadline - this.now();
        if (delay >= left) throw this.transportError('request deadline exceeded during retry backoff', method, url);
        await (this.opts.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms))))(delay);
      }
    }
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

  private async withinDeadline<T>(promise: Promise<T>, deadline: number, method: string, url: URL): Promise<T> {
    const remaining = deadline - this.now();
    if (remaining <= 0) throw this.transportError('request deadline exceeded while waiting for authentication', method, url);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_resolve, reject) => {
          timer = setTimeout(() => reject(this.transportError(
            'request deadline exceeded while waiting for authentication', method, url
          )), remaining);
        })
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private now(): number { return (this.opts.now ?? Date.now)(); }
  private classify(res: Response, method: string, url: URL): Response {
    if (res.status === 403 && url.pathname.startsWith('/ci/')) {
      throw new RemoteCapabilityError(
        `[router=${this.opts.routerId} operation=${method} endpoint=${url.hostname} ` +
          `class=remote-capability] The remote proxy denied ${url.pathname} with HTTP 403.`
      );
    }
    if (res.status === 401 || res.status === 403) throw this.authError(`authentication failed with HTTP ${res.status}`, method, url);
    return res;
  }
  private authError(reason: string, operation: string, url: URL): AuthError {
    return new AuthError(`[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=auth] ${reason}`);
  }
  private transportError(reason: string, operation: string, url: URL): TransportError {
    return new TransportError(`[router=${this.opts.routerId} operation=${operation} endpoint=${url.hostname} class=transport] ${reason}`);
  }
}
