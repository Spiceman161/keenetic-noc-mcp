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

  it('matches the RFC 2617 MD5 example', () => {
    const challenge = parseChallenges('Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')[0]!;
    const value = digestAuthorization({ challenge, username: 'Mufasa', password: 'Circle Of Life', method: 'GET', uri: '/dir/index.html', cnonce: '0a4f113b', nonceCount: 1 });
    expect(value).toContain('response="6629fae49393a05397450978507c4ef1"');
  });
});

describe('remote failure policy', () => {
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

  it('retries transport errors at most five times', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('ECONNRESET password=not-a-real-password'));
    const sleep = vi.fn().mockResolvedValue(undefined);
    await expect(new RemoteSession({ ...opts, fetch, sleep, random: () => 0 }).request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(sleep).toHaveBeenCalledTimes(4);
  });
});
