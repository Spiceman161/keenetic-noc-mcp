import { createHash } from 'node:crypto';
import { AuthError, TransportError } from './errors.js';
import type { RciRequestControls } from './rci.js';

export interface SessionOptions {
  host: string;
  login: string;
  password: string;
  timeoutMs?: number;
}

/**
 * The Keenetic LAN handshake: MD5 over the credential triple, then SHA256 over
 * the challenge concatenated with that digest. Both digests are lowercase hex.
 */
export function deriveAuthKey(
  login: string,
  realm: string,
  password: string,
  challenge: string
): string {
  const md5 = createHash('md5').update(`${login}:${realm}:${password}`).digest('hex');
  return createHash('sha256').update(`${challenge}${md5}`).digest('hex');
}

const DEFAULT_TIMEOUT_MS = 10_000;

export class Session {
  private readonly opts: SessionOptions;
  /** The router randomises the cookie name, so both parts are stored verbatim. */
  private cookie: string | null = null;
  /** Set while an authentication is in flight so concurrent callers share it. */
  private authInFlight: {
    promise: Promise<void>;
    controller: AbortController;
    waiters: number;
    settled: boolean;
  } | null = null;

  constructor(opts: SessionOptions) {
    this.opts = opts;
  }

  effectiveTimeoutMs(requestedMs: number): number {
    return Math.min(this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, requestedMs);
  }

  /**
   * Lazy authentication: the first 401 drives the handshake, then the call
   * replays exactly once. The session is a 300-second sliding window, so an
   * idle gap between agent turns routinely expires it.
   */
  async request(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown, controls: RciRequestControls = {}): Promise<Response> {
    const timeoutMs = this.effectiveTimeoutMs(controls.timeoutMs ?? Number.POSITIVE_INFINITY);
    const deadline = Date.now() + timeoutMs;
    const first = await this.send(method, path, body, controls.signal, deadline);
    if (first.status !== 401) return first;

    await this.ensureAuthenticated(controls.signal, deadline);

    const second = await this.send(method, path, body, controls.signal, deadline);
    if (second.status === 401) {
      throw new AuthError(
        `The router rejected credentials for user "${this.opts.login}" after ` +
          `re-authenticating for ${method} ${path}.`
      );
    }
    return second;
  }

  private async ensureAuthenticated(signal: AbortSignal | undefined, deadline: number): Promise<void> {
    if (!this.authInFlight) {
      const controller = new AbortController();
      const flight = { promise: Promise.resolve(), controller, waiters: 0, settled: false };
      flight.promise = this.authenticate(controller.signal).finally(() => {
        flight.settled = true;
        if (this.authInFlight === flight) this.authInFlight = null;
      });
      this.authInFlight = flight;
    }
    const flight = this.authInFlight;
    flight.waiters += 1;
    try {
      await this.withinDeadline(flight.promise, signal, deadline);
    } finally {
      flight.waiters -= 1;
      if (flight.waiters === 0 && !flight.settled) flight.controller.abort();
    }
  }

  protected async send(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown,
    signal?: AbortSignal, deadline = Date.now() + (this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)): Promise<Response> {
    if (signal?.aborted) throw new TransportError('Router request was cancelled before it started.');
    const headers: Record<string, string> = {};
    if (this.cookie) headers['cookie'] = this.cookie;
    if (body !== undefined) headers['content-type'] = 'application/json';

    const url = `http://${this.opts.host}${path}`;
    // Built stepwise rather than with a ternary: under exactOptionalPropertyTypes
    // an explicit `body: undefined` is not the same as omitting the property.
    const init: RequestInit = {
      method,
      headers,
      signal: signal === undefined
        ? AbortSignal.timeout(Math.max(1, deadline - Date.now()))
        : AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, deadline - Date.now()))]),
      redirect: 'manual'
    };
    if (body !== undefined) init.body = JSON.stringify(body);

    let res: Response;
    try {
      res = await fetch(url, init);
    } catch (cause) {
      throw new TransportError(`${method} ${url} failed: ${(cause as Error).message}.`);
    }
    this.captureCookie(res);
    return res;
  }

  private async withinDeadline<T>(promise: Promise<T>, signal: AbortSignal | undefined, deadline: number): Promise<T> {
    const timeout = AbortSignal.timeout(Math.max(1, deadline - Date.now()));
    const combined = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
    if (combined.aborted) throw new TransportError('Router request was cancelled or exceeded its deadline.');
    return new Promise<T>((resolve, reject) => {
      const abort = (): void => reject(new TransportError('Router request was cancelled or exceeded its deadline.'));
      combined.addEventListener('abort', abort, { once: true });
      promise.then(resolve, reject).finally(() => combined.removeEventListener('abort', abort));
    });
  }

  protected captureCookie(res: Response): void {
    const set = res.headers.getSetCookie();
    for (const raw of set) {
      const pair = raw.split(';', 1)[0];
      if (pair && pair.includes('=')) this.cookie = pair;
    }
  }

  protected async authenticate(signal?: AbortSignal): Promise<void> {
    const deadline = Date.now() + (this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const probe = await this.send('GET', '/auth', undefined, signal, deadline);
    if (probe.status === 200) return;

    const realm = probe.headers.get('X-NDM-Realm');
    const challenge = probe.headers.get('X-NDM-Challenge');
    if (!realm || !challenge) {
      throw new AuthError(
        `The router at ${this.opts.host} did not return an X-NDM-Challenge. ` +
          'This endpoint does not use the LAN challenge scheme - remote access over ' +
          'KeenDNS is not supported in this version.'
      );
    }

    const password = deriveAuthKey(this.opts.login, realm, this.opts.password, challenge);
    const res = await this.send('POST', '/auth', { login: this.opts.login, password }, signal, deadline);
    if (res.status !== 200) {
      throw new AuthError(
        `The router rejected credentials for user "${this.opts.login}" (HTTP ${res.status}).`
      );
    }
  }
}
