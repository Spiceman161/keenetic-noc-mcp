import { createHash, randomBytes } from 'node:crypto';
import { AuthError, RemoteCapabilityError, TransportError } from './errors.js';
import { redactText } from '../security/redact.js';

export interface RemoteSessionOptions {
  endpoint: string; login: string; password: string; routerId: string;
  timeoutMs?: number; attempts?: number; fetch?: typeof globalThis.fetch;
  sleep?: (ms: number) => Promise<void>; random?: () => number;
}

type Challenge = { scheme: string; params: Record<string, string> };
const hash = (algorithm: string, value: string): string =>
  createHash(algorithm.replace('-sess', '').toLowerCase()).update(value).digest('hex');

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
  private authorization: string | null = null;
  constructor(private readonly opts: RemoteSessionOptions) {}

  async request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const base = new URL(this.opts.endpoint);
    const url = path === '/rci/' ? base : new URL(path, base.origin);
    let response = await this.send(method, url, body);
    if (response.status !== 401) return this.classify(response, method, url);
    const offered = parseChallenges(response.headers.get('www-authenticate') ?? '');
    const digest = offered.find(c => c.scheme === 'digest');
    const basic = offered.find(c => c.scheme === 'basic');
    if (digest) this.authorization = digestAuthorization({ challenge: digest, username: this.opts.login,
      password: this.opts.password, method, uri: `${url.pathname}${url.search}` });
    else if (basic) this.authorization = `Basic ${Buffer.from(`${this.opts.login}:${this.opts.password}`).toString('base64')}`;
    else throw this.authError('HTTP 401 without a supported Digest or Basic challenge', method, url);
    response = await this.send(method, url, body);
    return this.classify(response, method, url);
  }

  private async send(method: string, url: URL, body?: unknown): Promise<Response> {
    const attempts = this.opts.attempts ?? 5;
    for (let attempt = 1; ; attempt++) {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (this.authorization) headers['authorization'] = this.authorization;
      if (body !== undefined) headers['content-type'] = 'application/json';
      try {
        return await (this.opts.fetch ?? fetch)(url, { method, headers,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000), redirect: 'manual' });
      } catch (cause) {
        if (attempt >= attempts) throw this.transportError(`failed after ${attempts} attempts: ${redactText((cause as Error).message)}`, method, url);
        const base = 1000 * 2 ** (attempt - 1);
        await (this.opts.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms))))(base * (1 + (this.opts.random ?? Math.random)() * 0.25));
      }
    }
  }
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
