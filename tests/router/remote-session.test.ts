import { describe, expect, it, vi } from 'vitest';
import { digestAuthorization, parseChallenges, RemoteSession } from '../../src/router/remote-session.js';
import { AuthError, RciError, RemoteCapabilityError, TransportError } from '../../src/router/errors.js';
import { EdgePool } from '../../src/router/edge-pool.js';
import { Rci } from '../../src/router/rci.js';
import {
  RciTransportCollector,
  runWithRciTransportCollector
} from '../../src/telemetry/rci-transport.js';

const opts = { endpoint: 'https://rci.example.test/rci/', login: 'agent', password: 'not-a-real-password', routerId: 'lab' };

function seededFallbackGuard() {
  const edgePool = new EdgePool();
  edgePool.observe('192.0.2.200');
  const pinned = vi.fn((_agent: unknown, _ip: string): void => undefined);
  return { dependencies: { edgePool, onPinnedAgent: pinned }, pinned };
}

describe('remote Digest authentication', () => {
  it('parses multiple challenges and prefers Digest', async () => {
    const body: Record<string, unknown> = { show: { version: {} } };
    const fetch = vi.fn()
      .mockImplementationOnce(() => {
        delete body['show'];
        body['system'] = { configuration: { save: {} } };
        return Promise.resolve(new Response('', { status: 401, headers: { 'www-authenticate': 'Basic realm="proxy", Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5' } }));
      })
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));
    await new RemoteSession({ ...opts, fetch }).request('POST', '/rci/', body);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]![1].headers).not.toHaveProperty('authorization');
    expect(fetch.mock.calls[1]![1].headers.authorization).toMatch(/^Digest /);
    expect(fetch.mock.calls[1]![1].body).toBe('{"show":{"version":{}}}');
    expect(fetch.mock.calls[1]![0].toString()).not.toContain(opts.password);
  });

  it('uses Basic only when Digest is not offered', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(new Response('', { status: 401, headers: { 'www-authenticate': 'Basic realm="proxy"' } }))
      .mockResolvedValueOnce(new Response('{}'));
    await new RemoteSession({ ...opts, fetch }).request('GET', '/rci/show/version');
    expect(fetch.mock.calls[1]![1].headers.authorization).toBe(`Basic ${Buffer.from('agent:not-a-real-password').toString('base64')}`);
  });

  it('queues concurrent first requests behind one Digest challenge', async () => {
    let releaseChallenge!: (response: Response) => void;
    const challenge = new Promise<Response>(resolve => { releaseChallenge = resolve; });
    const fetch = vi.fn()
      .mockImplementationOnce(() => challenge)
      .mockResolvedValue(new Response('{}', { status: 200 }));
    const session = new RemoteSession({ ...opts, fetch });

    const first = session.request('GET', '/rci/show/version');
    const second = session.request('GET', '/rci/show/system');
    expect(fetch).toHaveBeenCalledTimes(1);
    releaseChallenge(new Response('', { status: 401, headers: {
      'www-authenticate': 'Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5'
    } }));
    await Promise.all([first, second]);

    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls.slice(1).every(call => call[1].headers.authorization.startsWith('Digest '))).toBe(true);
    expect(fetch.mock.calls[1]![1].headers.authorization).toContain('uri="/rci/show/version"');
    expect(fetch.mock.calls[2]![1].headers.authorization).toContain('uri="/rci/show/system"');
  });

  it('keeps shared cold-auth evidence with the initiating call and does not cross-attribute', async () => {
    let releaseChallenge!: (response: Response) => void;
    const challenge = new Promise<Response>(resolve => { releaseChallenge = resolve; });
    const fetch = vi.fn()
      .mockImplementationOnce(() => challenge)
      .mockResolvedValue(new Response('{}', { status: 200 }));
    const session = new RemoteSession({ ...opts, fetch });
    const firstCollector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const secondCollector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const first = runWithRciTransportCollector(firstCollector,
      () => session.request('GET', '/rci/show/version'));
    const second = runWithRciTransportCollector(secondCollector,
      () => session.request('GET', '/rci/show/system'));
    expect(fetch).toHaveBeenCalledTimes(1);
    releaseChallenge(new Response('', { status: 401, headers: {
      'www-authenticate': 'Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5'
    } }));
    await Promise.all([first, second]);
    expect(firstCollector.seal()).toMatchObject({
      remote_requests: 1,
      shared_auth_waits: 0,
      normal_attempts: 2
    });
    expect(secondCollector.seal()).toMatchObject({
      remote_requests: 1,
      shared_auth_waits: 1,
      normal_attempts: 1
    });
  });

  it('accounts for a rejected shared-auth join as transport failure without copying attempts', async () => {
    let rejectFlight!: (error: Error) => void;
    const flight = new Promise<Response>((_resolve, reject) => { rejectFlight = reject; });
    const session = new RemoteSession({ ...opts, fetch: vi.fn().mockReturnValueOnce(flight), attempts: 1 });
    const initiator = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const joiner = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const first = runWithRciTransportCollector(initiator,
      () => session.request('GET', '/rci/show/version'));
    const second = runWithRciTransportCollector(joiner,
      () => session.request('GET', '/rci/show/system'));
    rejectFlight(new Error('synthetic transport failure'));
    await expect(first).rejects.toBeInstanceOf(TransportError);
    await expect(second).rejects.toBeInstanceOf(TransportError);
    expect(joiner.seal()).toMatchObject({
      shared_auth_waits: 1, normal_attempts: 0, correlation_complete: null,
      terminal_reasons: { transport_failure: 1 }
    });
  });

  it('accounts for final HTTP responses before auth or capability classification throws', async () => {
    for (const response of [
      new Response('', { status: 401 }),
      new Response('', { status: 403 })
    ]) {
      const session = new RemoteSession({ ...opts, fetch: vi.fn().mockResolvedValue(response), attempts: 1 });
      const collector = new RciTransportCollector({
        connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
      });
      await expect(runWithRciTransportCollector(collector,
        () => session.request('GET', '/rci/show/version'))).rejects.toBeInstanceOf(AuthError);
      expect(collector.seal()).toMatchObject({ terminal_reasons: { normal_response: 1 } });
    }
  });

  it('reports replay-unsafe and incomplete-correlation terminal evidence without changing retry policy', async () => {
    const rejected = () => Promise.reject(new Error('synthetic transport failure'));
    const replayUnsafe = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const unsafeSession = new RemoteSession({ ...opts, fetch: vi.fn(rejected), attempts: 5 });
    await expect(runWithRciTransportCollector(replayUnsafe,
      () => unsafeSession.request('POST', '/rci/', { system: { configuration: { save: {} } } })))
      .rejects.toBeInstanceOf(TransportError);
    expect(replayUnsafe.seal()).toMatchObject({
      normal_attempts: 1, fallback_considered: 1,
      terminal_reasons: { fallback_replay_unsafe: 1 }
    });

    const incomplete = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const incompleteSession = new RemoteSession({ ...opts, fetch: vi.fn(rejected), attempts: 1 });
    await expect(runWithRciTransportCollector(incomplete,
      () => incompleteSession.request('GET', '/rci/show/version'))).rejects.toBeInstanceOf(TransportError);
    expect(incomplete.seal()).toMatchObject({
      normal_attempts: 1, fallback_considered: 1,
      terminal_reasons: { fallback_correlation_incomplete: 1 }
    });
  });

  it('keeps a shared initial handshake alive when one caller cancels', async () => {
    let releaseChallenge!: (response: Response) => void;
    const challenge = new Promise<Response>(resolve => { releaseChallenge = resolve; });
    const fetch = vi.fn()
      .mockImplementationOnce(() => challenge)
      .mockResolvedValue(new Response('{}', { status: 200 }));
    const session = new RemoteSession({ ...opts, fetch, attempts: 1 });
    const controller = new AbortController();
    const first = session.request('GET', '/rci/show/version', undefined, {
      signal: controller.signal
    });
    const second = session.request('GET', '/rci/show/system');
    controller.abort();
    await expect(first).rejects.toBeInstanceOf(TransportError);
    releaseChallenge(new Response('', { status: 401, headers: {
      'www-authenticate': 'Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5'
    } }));
    await expect(second).resolves.toMatchObject({ status: 200 });
  });

  it('never shares a cold active POST as the authorization-discovery flight', async () => {
    let releaseDiscovery!: (response: Response) => void;
    const discovery = new Promise<Response>(resolve => { releaseDiscovery = resolve; });
    const fetch = vi.fn()
      .mockImplementationOnce(() => discovery)
      .mockResolvedValue(new Response('{}'));
    const session = new RemoteSession({ ...opts, fetch, attempts: 1 });
    const controller = new AbortController();
    const active = session.request('POST', '/rci/tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, { signal: controller.signal });
    const passive = session.request('GET', '/rci/show/system');
    expect(fetch.mock.calls[0]![0].toString()).toContain('/rci/show/version');
    controller.abort();
    await expect(active).rejects.toBeInstanceOf(TransportError);
    releaseDiscovery(new Response('', { status: 401, headers: {
      'www-authenticate': 'Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5'
    } }));
    await expect(passive).resolves.toMatchObject({ status: 200 });
    expect(fetch.mock.calls.some(call => call[1].method === 'POST')).toBe(false);
  });

  it('matches the RFC 2617 MD5 example', () => {
    const challenge = parseChallenges('Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')[0]!;
    const value = digestAuthorization({ challenge, username: 'Mufasa', password: 'Circle Of Life', method: 'GET', uri: '/dir/index.html', cnonce: '0a4f113b', nonceCount: 1 });
    expect(value).toContain('response="6629fae49393a05397450978507c4ef1"');
  });
});

describe('remote failure policy', () => {
  it('does not start a cold request when the caller signal is already aborted', async () => {
    const fetch = vi.fn();
    const controller = new AbortController();
    controller.abort();
    await expect(new RemoteSession({ ...opts, fetch }).request(
      'GET', '/rci/show/version', undefined, { signal: controller.signal }
    )).rejects.toBeInstanceOf(TransportError);
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([401, 403])('classifies HTTP %s as auth and does not retry', async status => {
    const fetch = vi.fn().mockResolvedValue(new Response('', { status }));
    const guard = seededFallbackGuard();
    await expect(new RemoteSession({ ...opts, fetch }, guard.dependencies)
      .request('GET', '/rci/show/version')).rejects.toBeInstanceOf(AuthError);
    expect(fetch).toHaveBeenCalledTimes(status === 401 ? 1 : 1);
    expect(guard.pinned).not.toHaveBeenCalled();
  });

  it('distinguishes a remote proxy denial of config export from RCI authentication', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('', { status: 403 }));
    const guard = seededFallbackGuard();
    await expect(
      new RemoteSession({ ...opts, fetch }, guard.dependencies).request('GET', '/ci/startup-config.txt')
    ).rejects.toBeInstanceOf(RemoteCapabilityError);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(guard.pinned).not.toHaveBeenCalled();
  });

  it('distinguishes denial of the candidate RCI startup path from bad credentials', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('{}', { status: 200 }))
      .mockResolvedValueOnce(new Response('', { status: 403 }));
    const guard = seededFallbackGuard();
    const session = new RemoteSession({ ...opts, fetch }, guard.dependencies);
    await session.request('GET', '/rci/show/version');
    await expect(
      session.request('GET', '/rci/more?filename=startup-config')
    ).rejects.toBeInstanceOf(RemoteCapabilityError);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(guard.pinned).not.toHaveBeenCalled();
  });

  it('keeps an initial candidate-path 403 classified as authentication failure', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('', { status: 403 }));
    const guard = seededFallbackGuard();
    await expect(
      new RemoteSession({ ...opts, fetch }, guard.dependencies)
        .request('GET', '/rci/more?filename=startup-config')
    ).rejects.toBeInstanceOf(AuthError);
    expect(guard.pinned).not.toHaveBeenCalled();
  });

  it('retries transport errors at most five times', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('ECONNRESET password=not-a-real-password'));
    const sleep = vi.fn().mockResolvedValue(undefined);
    await expect(new RemoteSession({ ...opts, fetch, sleep, random: () => 0 }).request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(sleep).toHaveBeenCalledTimes(4);
  });

  it('does not retry a mutating POST after an ambiguous transport failure', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('{}'))
      .mockRejectedValueOnce(new Error('ECONNRESET'));
    const sleep = vi.fn().mockResolvedValue(undefined);
    await expect(new RemoteSession({ ...opts, fetch, sleep }).request(
      'POST', '/rci/', { system: { configuration: { save: {} } } }
    )).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]![0].toString()).toContain('/rci/show/version');
    expect(fetch.mock.calls[1]![1].method).toBe('POST');
    expect(sleep).not.toHaveBeenCalled();
  });

  it('does not retry an active diagnostic POST after an ambiguous transport failure', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('{}'))
      .mockRejectedValueOnce(new Error('ECONNRESET'));
    const sleep = vi.fn().mockResolvedValue(undefined);
    await expect(new RemoteSession({ ...opts, fetch, sleep }).request(
      'POST', '/rci/tools/ping', { host: '192.0.2.1', packetsize: 84, count: 1 }
    )).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]![0].toString()).toContain('/rci/show/version');
    expect(fetch.mock.calls[1]![1].method).toBe('POST');
    expect(sleep).not.toHaveBeenCalled();
  });

  it('passes caller cancellation to the initial HTTP request', async () => {
    const fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      await new Promise((_resolve, reject) => init?.signal?.addEventListener('abort',
        () => reject(init.signal?.reason), { once: true }));
      return new Response('{}');
    });
    const controller = new AbortController();
    const pending = new RemoteSession({ ...opts, fetch }).request('POST', '/rci/tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('does not retry a GET after caller cancellation aborts fetch', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      await new Promise((_resolve, reject) => init?.signal?.addEventListener('abort',
        () => reject(init.signal?.reason), { once: true }));
      return new Response('{}');
    });
    const controller = new AbortController();
    const pending = new RemoteSession({ ...opts, fetch, sleep }).request(
      'GET', '/rci/tools/ping', undefined, { signal: controller.signal }
    );
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
    expect(sleep).not.toHaveBeenCalled();
  });

  it('interrupts retry backoff when the caller cancels', async () => {
    let beginSleep!: () => void;
    const sleeping = new Promise<void>(resolve => { beginSleep = resolve; });
    const fetch = vi.fn().mockRejectedValue(new Error('ECONNRESET'));
    const sleep = vi.fn(() => sleeping);
    const controller = new AbortController();
    const pending = new RemoteSession({ ...opts, fetch, sleep }).request(
      'GET', '/rci/tools/ping', undefined, { signal: controller.signal }
    );
    await vi.waitFor(() => expect(sleep).toHaveBeenCalledOnce());
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
    beginSleep();
  });

  it('uses one deadline for attempts and retry backoff', async () => {
    let now = 0;
    const fetch = vi.fn().mockRejectedValue(new Error('ECONNRESET'));
    const sleep = vi.fn(async (ms: number) => { now += ms; });
    await expect(new RemoteSession({
      ...opts, fetch, sleep, random: () => 0, timeoutMs: 1_500, now: () => now
    }).request('GET', '/rci/show/version')).rejects.toThrow(/deadline/i);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledTimes(1);
  });
});

describe('remote replay-safety gate', () => {
  async function warmedSession(fetch: ReturnType<typeof vi.fn>, attempts = 2): Promise<RemoteSession> {
    fetch.mockResolvedValueOnce(new Response('{}'));
    const session = new RemoteSession({
      ...opts,
      fetch: fetch as typeof globalThis.fetch,
      attempts,
      sleep: async () => undefined
    });
    await session.request('GET', '/rci/show/version');
    fetch.mockClear();
    return session;
  }

  it('retries only an exact single-root POST /rci/ show object', async () => {
    const fetch = vi.fn();
    const session = await warmedSession(fetch);
    fetch.mockRejectedValue(new Error('synthetic transport failure'));
    await expect(session.request('POST', '/rci/', { show: { version: {} } }))
      .rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('reuses one immutable body snapshot when the caller mutates it during backoff', async () => {
    const body: Record<string, unknown> = { show: { version: {} } };
    const fetch = vi.fn().mockResolvedValueOnce(new Response('{}'));
    const sleep = vi.fn(async () => {
      delete body['show'];
      body['system'] = { configuration: { save: {} } };
    });
    const session = new RemoteSession({
      ...opts, fetch, attempts: 2, sleep, random: () => 0
    });
    await session.request('GET', '/rci/show/version');
    fetch.mockClear();
    fetch.mockRejectedValue(new Error('synthetic transport failure'));

    await expect(session.request('POST', '/rci/', body)).rejects.toBeInstanceOf(TransportError);

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.map(call => call[1].body)).toEqual([
      '{"show":{"version":{}}}', '{"show":{"version":{}}}'
    ]);
    expect(JSON.stringify(fetch.mock.calls.map(call => call[1].body)))
      .not.toContain('configuration');
  });

  it.each([
    ['write', '/rci/', { system: { configuration: { save: {} } } }],
    ['multi-root', '/rci/', { show: {}, system: {} }],
    ['null show', '/rci/', { show: null }],
    ['array show', '/rci/', { show: [] }],
    ['malformed body', '/rci/', 'show'],
    ['alternate path', '/rci/other', { show: {} }],
    ['query path', '/rci/?mode=show', { show: {} }],
    ['active diagnostic', '/rci/tools/ping', { host: '192.0.2.1' }]
  ])('does not retry unsafe POST form %s', async (_name, path, body) => {
    const fetch = vi.fn();
    const session = await warmedSession(fetch);
    fetch.mockRejectedValue(new Error('synthetic transport failure'));
    await expect(session.request('POST', path, body)).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('does not retry DELETE but retains ordinary GET polling retries', async () => {
    const deleteFetch = vi.fn();
    const deleteSession = await warmedSession(deleteFetch);
    deleteFetch.mockRejectedValue(new Error('synthetic transport failure'));
    await expect(deleteSession.request('DELETE', '/rci/tools/ping'))
      .rejects.toBeInstanceOf(TransportError);
    expect(deleteFetch).toHaveBeenCalledOnce();

    const getFetch = vi.fn();
    const getSession = await warmedSession(getFetch);
    getFetch.mockRejectedValue(new Error('synthetic transport failure'));
    await expect(getSession.request('GET', '/rci/tools/ping'))
      .rejects.toBeInstanceOf(TransportError);
    expect(getFetch).toHaveBeenCalledTimes(2);
  });

  it('does not retry the allowRetry=false authentication-discovery request', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('synthetic transport failure'));
    const session = new RemoteSession({ ...opts, fetch, attempts: 5, sleep: async () => undefined });
    await expect(session.request('POST', '/rci/tools/ping', { host: '192.0.2.1' }))
      .rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]![0].toString()).toContain('/rci/show/version');
  });

  it('stops transport fallback on an HTTP application response', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 500 }));
    const guard = seededFallbackGuard();
    const response = await new RemoteSession({ ...opts, fetch }, guard.dependencies)
      .request('GET', '/rci/show/version');
    expect(response.status).toBe(500);
    expect(fetch).toHaveBeenCalledOnce();
    expect(guard.pinned).not.toHaveBeenCalled();
  });

  it('does not convert a parsed semantic RCI failure into another transport attempt', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('{}'))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        status: [{ status: 'error', code: 'synthetic', ident: 'rci', message: 'rejected' }]
      })));
    const guard = seededFallbackGuard();
    const session = new RemoteSession({ ...opts, fetch }, guard.dependencies);
    await expect(new Rci(session).post({ show: { version: {} } })).rejects.toBeInstanceOf(RciError);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(guard.pinned).not.toHaveBeenCalled();
  });
});
