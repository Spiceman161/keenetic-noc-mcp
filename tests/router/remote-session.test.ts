import { describe, expect, it, vi } from 'vitest';
import { digestAuthorization, parseChallenges, RemoteSession } from '../../src/router/remote-session.js';
import { AuthError, RemoteCapabilityError, TransportError } from '../../src/router/errors.js';

const opts = { endpoint: 'https://rci.example.test/rci/', login: 'agent', password: 'not-a-real-password', routerId: 'lab' };

describe('remote Digest authentication', () => {
  it('parses multiple challenges and prefers Digest', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('', { status: 401, headers: { 'www-authenticate': 'Basic realm="proxy", Digest realm="proxy", nonce="abc", qop="auth", algorithm=MD5' } }))
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));
    await new RemoteSession({ ...opts, fetch }).request('POST', '/rci/', { show: { version: {} } });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]![1].headers).not.toHaveProperty('authorization');
    expect(fetch.mock.calls[1]![1].headers.authorization).toMatch(/^Digest /);
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
    await expect(new RemoteSession({ ...opts, fetch }).request('GET', '/rci/show/version')).rejects.toBeInstanceOf(AuthError);
    expect(fetch).toHaveBeenCalledTimes(status === 401 ? 1 : 1);
  });

  it('distinguishes a remote proxy denial of config export from RCI authentication', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('', { status: 403 }));
    await expect(
      new RemoteSession({ ...opts, fetch }).request('GET', '/ci/startup-config.txt')
    ).rejects.toBeInstanceOf(RemoteCapabilityError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('distinguishes denial of the candidate RCI startup path from bad credentials', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response('{}', { status: 200 }))
      .mockResolvedValueOnce(new Response('', { status: 403 }));
    const session = new RemoteSession({ ...opts, fetch });
    await session.request('GET', '/rci/show/version');
    await expect(
      session.request('GET', '/rci/more?filename=startup-config')
    ).rejects.toBeInstanceOf(RemoteCapabilityError);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('keeps an initial candidate-path 403 classified as authentication failure', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('', { status: 403 }));
    await expect(
      new RemoteSession({ ...opts, fetch }).request('GET', '/rci/more?filename=startup-config')
    ).rejects.toBeInstanceOf(AuthError);
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
