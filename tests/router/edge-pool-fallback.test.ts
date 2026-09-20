import { describe, expect, it, vi } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent } from 'undici';
import { EdgePool } from '../../src/router/edge-pool.js';
import {
  defaultCreateAgent,
  FallbackRemoteSession,
  type FallbackRemoteSessionOptions
} from '../../src/router/fallback-session.js';
import { createClient, createRemoteClient, defaultEdgePool } from '../../src/router/client.js';
import { RemoteSession, type RemoteSessionOptions } from '../../src/router/remote-session.js';
import {
  AuthError,
  RciError,
  RemoteCapabilityError,
  TransportError
} from '../../src/router/errors.js';

const baseOpts: FallbackRemoteSessionOptions = {
  endpoint: 'https://router.keendns.example/rci/',
  login: 'admin',
  password: 'test-password',
  routerId: 'lab-router',
  timeoutMs: 10_000,
  attempts: 1,
  sleep: () => Promise.resolve()
};

function createMockAgent(): Agent {
  return {
    close: vi.fn().mockResolvedValue(undefined),
    destroy: vi.fn().mockResolvedValue(undefined)
  } as unknown as Agent;
}

describe('EdgePool unit tests', () => {
  it('observe() records new IPs and updates lastSeen without duplicates (Criteria 10, 11)', () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });

    expect(pool.size()).toBe(0);

    pool.observe('192.0.2.1');
    expect(pool.size()).toBe(1);
    const entry1 = pool.getEntry('192.0.2.1');
    expect(entry1).toBeDefined();
    expect(entry1?.ip).toBe('192.0.2.1');
    expect(entry1?.firstSeen).toBe(1_000);
    expect(entry1?.lastSeen).toBe(1_000);

    currentTime = 2_000;
    pool.observe('192.0.2.1');
    expect(pool.size()).toBe(1);
    expect(pool.getEntry('192.0.2.1')?.lastSeen).toBe(2_000);
    expect(pool.getEntry('192.0.2.1')?.firstSeen).toBe(1_000);
  });

  it('candidates() excludes already-attempted IPs (Criterion 4)', () => {
    const pool = new EdgePool({ now: () => 1_000 });
    pool.observe('192.0.2.1');
    pool.observe('192.0.2.2');
    pool.observe('198.51.100.1');
    pool.observe('198.51.100.2');

    // Exclude via Set
    const excludedSet = new Set(['192.0.2.1', '192.0.2.2']);
    const c1 = pool.candidates(excludedSet, 5);
    expect(c1).toEqual(['198.51.100.1', '198.51.100.2']);

    // Exclude via Array
    const c2 = pool.candidates(['192.0.2.1', '198.51.100.1'], 5);
    expect(c2).toEqual(['192.0.2.2', '198.51.100.2']);

    // When all are excluded, returns empty array
    const cAll = pool.candidates(new Set(['192.0.2.1', '192.0.2.2', '198.51.100.1', '198.51.100.2']));
    expect(cAll).toEqual([]);
  });

  it('candidates() excludes stale IPs older than 2 hours (Criterion 5)', () => {
    let currentTime = 10_000_000;
    const pool = new EdgePool({ now: () => currentTime, staleThresholdMs: 2 * 60 * 60 * 1000 });

    pool.observe('192.0.2.1'); // seen at 10_000_000

    // Advance time by 2 hours and 1 millisecond
    currentTime += 2 * 60 * 60 * 1000 + 1;
    pool.observe('198.51.100.1'); // fresh at 17_200_001

    const candidates = pool.candidates();
    expect(candidates).toEqual(['198.51.100.1']);
    expect(candidates).not.toContain('192.0.2.1');

    // Advance further so all are stale
    currentTime += 2 * 60 * 60 * 1000 + 1;
    expect(pool.candidates()).toEqual([]);
  });

  it('candidates() ranks recent success ahead of untried and recent failure (Criterion 6)', () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });

    // Edge 1: Recent success
    pool.observe('192.0.2.1');
    currentTime = 2_000;
    pool.recordSuccess('192.0.2.1');

    // Edge 2: Untried / unknown
    currentTime = 3_000;
    pool.observe('192.0.2.2');

    // Edge 3: Recent failure
    currentTime = 4_000;
    pool.observe('192.0.2.3');
    currentTime = 5_000;
    pool.recordFailure('192.0.2.3');

    // Edge 4: Earlier success
    currentTime = 6_000;
    pool.observe('192.0.2.4');
    currentTime = 7_000;
    pool.recordSuccess('192.0.2.4');

    // Priority:
    // Tier 1 (recent success): 192.0.2.4 (lastSuccess=7000) > 192.0.2.1 (lastSuccess=2000)
    // Tier 2 (untried): 192.0.2.2 (lastSeen=3000)
    // Tier 3 (recent failure): 192.0.2.3 (lastFailure=5000)
    const ranked = pool.candidates(new Set(), 10);
    expect(ranked).toEqual(['192.0.2.4', '192.0.2.1', '192.0.2.2', '192.0.2.3']);
  });

  it('candidates() breaks ties deterministically on IP string (Criterion 6)', () => {
    const pool = new EdgePool({ now: () => 1_000 });
    pool.observe('192.0.2.20');
    pool.observe('192.0.2.10');
    pool.observe('192.0.2.30');

    // All untried with same timestamp -> sorted by IP localeCompare
    const candidates = pool.candidates(new Set(), 10);
    expect(candidates).toEqual(['192.0.2.10', '192.0.2.20', '192.0.2.30']);
  });

  it('candidates() returns at most limit entries (Criterion 11)', () => {
    const pool = new EdgePool({ now: () => 1_000 });
    pool.observe('192.0.2.1');
    pool.observe('192.0.2.2');
    pool.observe('192.0.2.3');

    expect(pool.candidates(new Set(), 2)).toHaveLength(2);
    expect(pool.candidates(new Set(), 1)).toHaveLength(1);
    expect(pool.candidates(new Set(), 0)).toHaveLength(0);
  });

  it('candidates() returns empty when pool is empty (Criterion 14)', () => {
    const pool = new EdgePool();
    expect(pool.candidates()).toEqual([]);
  });

  it('pool caps at maxEntries and evicts oldest by lastSeen (Criterion 11)', () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime, maxEntries: 3 });

    pool.observe('192.0.2.11'); // lastSeen = 1000
    currentTime = 2_000;
    pool.observe('192.0.2.12'); // lastSeen = 2000
    currentTime = 3_000;
    pool.observe('192.0.2.13'); // lastSeen = 3000

    expect(pool.size()).toBe(3);

    // Adding 4th entry evicts 192.0.2.11 (oldest lastSeen)
    currentTime = 4_000;
    pool.observe('192.0.2.14');
    expect(pool.size()).toBe(3);
    expect(pool.getEntry('192.0.2.11')).toBeUndefined();
    expect(pool.getEntry('192.0.2.12')).toBeDefined();
    expect(pool.getEntry('192.0.2.13')).toBeDefined();
    expect(pool.getEntry('192.0.2.14')).toBeDefined();
  });

  it('recordSuccess() and recordFailure() update timestamps without removing entry (Criteria 6, 12)', () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });

    pool.recordSuccess('192.0.2.1');
    expect(pool.size()).toBe(1);
    expect(pool.getEntry('192.0.2.1')?.lastSuccess).toBe(1_000);

    currentTime = 2_000;
    pool.recordFailure('192.0.2.1');
    expect(pool.size()).toBe(1);
    expect(pool.getEntry('192.0.2.1')?.lastFailure).toBe(2_000);

    // Success after failure restores edge ranking to Tier 1
    currentTime = 3_000;
    pool.recordSuccess('192.0.2.1');
    expect(pool.getEntry('192.0.2.1')?.lastSuccess).toBe(3_000);
    expect(pool.getEntry('192.0.2.1')?.lastFailure).toBe(2_000);
    // lastSuccess > lastFailure -> Tier 1
    expect(pool.candidates()).toEqual(['192.0.2.1']);
  });

  it('failure for one profile does not globally poison an otherwise healthy edge (Criterion 12)', () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });

    // Profile A observes and fails on 192.0.2.1
    pool.observe('192.0.2.1');
    pool.recordFailure('192.0.2.1');

    // The edge is still in the pool and eligible if no other edges exist
    expect(pool.candidates()).toEqual(['192.0.2.1']);

    // Profile B later succeeds through 192.0.2.1
    currentTime = 2_000;
    pool.recordSuccess('192.0.2.1');

    // Edge is now in Tier 1 with lastSuccess > lastFailure
    const entry = pool.getEntry('192.0.2.1');
    expect(entry?.lastSuccess).toBe(2_000);
    expect(entry?.lastFailure).toBe(1_000);
    expect(pool.candidates()).toEqual(['192.0.2.1']);
  });

  it('state is purely memory-only and starts clean (Criterion 15)', () => {
    const pool1 = new EdgePool();
    pool1.observe('192.0.2.100');
    expect(pool1.size()).toBe(1);

    const pool2 = new EdgePool();
    expect(pool2.size()).toBe(0);
    expect(pool2.candidates()).toEqual([]);
  });
});

describe('FallbackRemoteSession integration tests', () => {
  it('Criterion 1: First DNS address succeeds -> no pool fallback', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"status":"ok"}', { status: 200 }));
    const inner = new RemoteSession({ ...baseOpts, fetch: fetchMock });
    const pool = new EdgePool();
    pool.observe('198.51.100.99'); // alternative edge

    const resolveDnsMock = vi.fn().mockResolvedValue(['192.0.2.1', '192.0.2.2']);
    const createAgentMock = vi.fn();

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fetchMock,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    const response = await fallbackSession.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);

    // A successful ordinary request learns the live DNS answers, but never
    // creates a fallback Agent.
    expect(resolveDnsMock).toHaveBeenCalledWith('router.keendns.example');
    expect(pool.getEntry('192.0.2.1')).toBeDefined();
    expect(pool.getEntry('192.0.2.2')).toBeDefined();
    expect(createAgentMock).not.toHaveBeenCalled();
    expect(fallbackSession.activeAgentCount).toBe(0);
  });

  it('learns an alternate from successful normal traffic for a later transport fallback', async () => {
    const pool = new EdgePool();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"first":true}', { status: 200 }))
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(new Response('{"recovered":true}', { status: 200 }));
    const inner = new RemoteSession({ ...baseOpts, attempts: 1, fetch: fetchMock });
    const alternateAgent = createMockAgent();
    const createAgentMock = vi.fn().mockReturnValue(alternateAgent);
    const resolveDnsMock = vi.fn()
      // The ordinary successful request sees an edge absent from the later
      // failed DNS answer. Candidate 3cdd78f never consumes this response.
      .mockResolvedValueOnce(['192.0.2.1', '192.0.2.2', '198.51.100.3'])
      .mockResolvedValueOnce(['192.0.2.1', '192.0.2.2'])
      .mockResolvedValueOnce(['192.0.2.1', '192.0.2.2']);
    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      attempts: 1,
      fetch: fetchMock,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    await expect(session.request('GET', '/rci/show/version')).resolves.toHaveProperty('status', 200);
    expect(pool.getEntry('198.51.100.3')).toBeDefined();

    await expect(session.request('GET', '/rci/show/version')).resolves.toHaveProperty('status', 200);
    expect(createAgentMock).toHaveBeenCalledWith('198.51.100.3');
    expect(alternateAgent.close).toHaveBeenCalledOnce();
    expect(alternateAgent.destroy).not.toHaveBeenCalled();
    expect(session.activeAgentCount).toBe(0);
  });

  it('does not delay a successful response when its DNS observation is cancelled', async () => {
    const controller = new AbortController();
    let resolveDns!: (addresses: readonly string[]) => void;
    const pendingDns = new Promise<readonly string[]>(resolve => { resolveDns = resolve; });
    const pool = new EdgePool();
    const inner = {
      effectiveTimeoutMs: (requestedMs: number) => Math.min(10_000, requestedMs),
      request: vi.fn().mockResolvedValue(new Response('{"ok":true}', { status: 200 }))
    } as unknown as RemoteSession;
    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      resolveDns: vi.fn().mockReturnValue(pendingDns),
      createAgent: vi.fn()
    });

    const request = session.request('GET', '/rci/show/version', undefined, { signal: controller.signal });
    await vi.waitFor(() => expect(resolveDns).toBeTypeOf('function'));
    controller.abort();

    await expect(request).resolves.toHaveProperty('status', 200);
    resolveDns(['198.51.100.3']);
    await Promise.resolve();
    expect(pool.getEntry('198.51.100.3')).toBeUndefined();
    expect(session.activeAgentCount).toBe(0);
  });

  it('Criterion 2: First DNS address fails, second succeeds -> existing failover only', async () => {
    // Inner RemoteSession retries GET requests up to 5 times.
    // 1st attempt fails with network error, 2nd attempt succeeds.
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce(new Response('{"status":"ok"}', { status: 200 }));

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 5,
      fetch: fetchMock,
      sleep: () => Promise.resolve()
    });
    const pool = new EdgePool();
    const resolveDnsMock = vi.fn().mockResolvedValue([]);
    const createAgentMock = vi.fn();

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    const response = await fallbackSession.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);

    // Handled entirely by existing failover in RemoteSession; the successful
    // ordinary request observes DNS but never enters the pool fallback path.
    expect(resolveDnsMock).toHaveBeenCalledWith('router.keendns.example');
    expect(createAgentMock).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('Criterion 3: Both current DNS addresses fail -> previously observed alternative edge recovers request', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.50'); // previously observed edge

    // Inner session always fails
    const innerFetchMock = vi.fn().mockRejectedValue(new Error('ETIMEDOUT'));
    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: innerFetchMock
    });

    const resolveDnsMock = vi.fn().mockResolvedValue(['192.0.2.1', '192.0.2.2']);
    const fallbackFetchMock = vi.fn().mockResolvedValue(new Response('{"recovered":true}', { status: 200 }));
    const mockAgent = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;
    const createAgentMock = vi.fn().mockReturnValue(mockAgent);

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fallbackFetchMock,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    const response = await fallbackSession.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);

    // DNS resolved and observed
    expect(resolveDnsMock).toHaveBeenCalledWith('router.keendns.example');
    expect(pool.getEntry('192.0.2.1')).toBeDefined();
    expect(pool.getEntry('192.0.2.2')).toBeDefined();

    // Agent created for alternative edge
    expect(createAgentMock).toHaveBeenCalledWith('198.51.100.50');
    // Success recorded in pool
    expect(pool.getEntry('198.51.100.50')?.lastSuccess).toBeDefined();
  });

  it('Criterion 4: Already attempted addresses are not attempted twice', async () => {
    const pool = new EdgePool();
    pool.observe('192.0.2.1');
    pool.observe('192.0.2.2');
    pool.observe('198.51.100.1');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    const resolveDnsMock = vi.fn().mockResolvedValue(['192.0.2.1', '192.0.2.2']);
    const mockAgent = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;
    const createAgentMock = vi.fn().mockReturnValue(mockAgent);
    const fallbackFetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fallbackFetchMock,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    await fallbackSession.request('GET', '/rci/show/version');

    // 192.0.2.1 and 192.0.2.2 were in DNS resolution, so excluded from fallback candidates
    expect(createAgentMock).toHaveBeenCalledTimes(1);
    expect(createAgentMock).toHaveBeenCalledWith('198.51.100.1');
    expect(createAgentMock).not.toHaveBeenCalledWith('192.0.2.1');
    expect(createAgentMock).not.toHaveBeenCalledWith('192.0.2.2');
  });

  it('Criterion 5: Stale cached addresses are not used', async () => {
    let currentTime = 10_000_000;
    const pool = new EdgePool({ now: () => currentTime, staleThresholdMs: 2 * 60 * 60 * 1000 });
    pool.observe('198.51.100.99'); // observed at 10_000_000

    // Advance 3 hours (> 2h stale)
    currentTime += 3 * 60 * 60 * 1000;

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
      now: () => currentTime
    });

    const resolveDnsMock = vi.fn().mockResolvedValue(['192.0.2.1', '192.0.2.2']);
    const createAgentMock = vi.fn();

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      now: () => currentTime,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    // Stale IP cannot be used; no candidates remain -> throws original TransportError
    await expect(fallbackSession.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    expect(createAgentMock).not.toHaveBeenCalled();
  });

  it('Criterion 6: Recent successful edge ranks ahead of a recently failing edge during fallback', async () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });

    // Edge A: failing
    pool.observe('198.51.100.1');
    currentTime = 2_000;
    pool.recordFailure('198.51.100.1');

    // Edge B: successful
    pool.observe('198.51.100.2');
    currentTime = 3_000;
    pool.recordSuccess('198.51.100.2');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ETIMEDOUT')),
      now: () => currentTime
    });

    const attemptedOrder: string[] = [];
    const createAgentMock = vi.fn().mockImplementation((ip: string) => {
      attemptedOrder.push(ip);
      return {
        close: vi.fn().mockResolvedValue(undefined),
        destroy: vi.fn().mockResolvedValue(undefined)
      } as unknown as Agent;
    });

    const fallbackSession = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: vi.fn().mockResolvedValue(new Response('{}', { status: 200 })),
      now: () => currentTime,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: createAgentMock
    });

    await fallbackSession.request('GET', '/rci/show/version');

    // Edge B (recent success) must be attempted before Edge A (recent failure)
    expect(attemptedOrder[0]).toBe('198.51.100.2');
  });

  it('Criterion 7: Application/auth failures do not trigger pool fallback', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    // 1. AuthError on inner
    const authFetchMock = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    const innerAuth = new RemoteSession({ ...baseOpts, fetch: authFetchMock });
    const resolveDnsMock = vi.fn();
    const createAgentMock = vi.fn().mockImplementation(() => createMockAgent());

    const sessionAuth = new FallbackRemoteSession(innerAuth, pool, {
      ...baseOpts,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    await expect(sessionAuth.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(AuthError);
    expect(resolveDnsMock).not.toHaveBeenCalled();
    expect(createAgentMock).not.toHaveBeenCalled();

    // 2. RemoteCapabilityError on inner (e.g. 403 on startup-config)
    const capFetchMock = vi.fn().mockResolvedValue(new Response('', { status: 403 }));
    const innerCap = new RemoteSession({ ...baseOpts, fetch: capFetchMock });
    const sessionCap = new FallbackRemoteSession(innerCap, pool, {
      ...baseOpts,
      resolveDns: resolveDnsMock,
      createAgent: createAgentMock
    });

    await expect(sessionCap.request('GET', '/ci/startup-config.txt')).rejects.toBeInstanceOf(RemoteCapabilityError);
    expect(resolveDnsMock).not.toHaveBeenCalled();

    // 3. AuthError during fallback candidate request -> immediately rethrown, does not try next candidate
    pool.observe('198.51.100.2');
    const innerTransport = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    const fallbackAuthFetch = vi.fn().mockResolvedValue(new Response('', { status: 401 }));
    const sessionCandidateAuth = new FallbackRemoteSession(innerTransport, pool, {
      ...baseOpts,
      fetch: fallbackAuthFetch,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: createAgentMock
    });

    await expect(sessionCandidateAuth.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(AuthError);
    // Only 1 candidate attempted; deterministic error stops further fallback attempts
    expect(createAgentMock).toHaveBeenCalledTimes(1);
  });

  it('Criterion 8: Eligible transport failures can trigger fallback', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');
    pool.observe('198.51.100.2');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('Connection reset by peer'))
    });

    // Candidate 1 fails with transport error; candidate 2 succeeds
    let candidateCount = 0;
    const fallbackFetch = vi.fn().mockImplementation(() => {
      candidateCount++;
      if (candidateCount === 1) {
        return Promise.reject(new Error('ETIMEDOUT'));
      }
      return Promise.resolve(new Response('{"ok":true}', { status: 200 }));
    });

    const mockAgent = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fallbackFetch,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: vi.fn().mockReturnValue(mockAgent)
    });

    const response = await session.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);
    // Candidate 1 recorded failure, candidate 2 recorded success
    expect(pool.getEntry('198.51.100.1')?.lastFailure).toBeDefined();
    expect(pool.getEntry('198.51.100.2')?.lastSuccess).toBeDefined();
  });

  it('Criterion 9: Destination IP changes while URL hostname, SNI, and cert validation remain correct', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    let requestedUrl = '';
    const fallbackFetch = vi.fn().mockImplementation((url: string | URL) => {
      requestedUrl = url.toString();
      return Promise.resolve(new Response('{}', { status: 200 }));
    });

    const mockAgent = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;
    const createAgentMock = vi.fn().mockReturnValue(mockAgent);

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fallbackFetch,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: createAgentMock
    });

    await session.request('GET', '/rci/show/version');

    // The URL must keep the original logical hostname, preserving SNI and Host header
    expect(requestedUrl).toContain('https://router.keendns.example/rci/show/version');
    expect(requestedUrl).not.toContain('198.51.100.1');
    // The agent receives the target IP for destination routing
    expect(createAgentMock).toHaveBeenCalledWith('198.51.100.1');
  });

  it('Criterion 10: Newly observed DNS edge is learned dynamically', async () => {
    const pool = new EdgePool();
    expect(pool.size()).toBe(0);

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    // DNS returns 2 newly observed IPs
    const resolveDnsMock = vi.fn().mockResolvedValue(['192.0.2.10', '192.0.2.20']);

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      resolveDns: resolveDnsMock
    });

    await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);

    // Both IPs returned by DNS are now in the pool
    expect(pool.size()).toBe(2);
    expect(pool.getEntry('192.0.2.10')).toBeDefined();
    expect(pool.getEntry('192.0.2.20')).toBeDefined();
  });

  it('Criterion 11: No static list of IPs is required', () => {
    // EdgePool starts with 0 entries; no hardcoded IPs
    const pool = new EdgePool();
    expect(pool.size()).toBe(0);
    expect(pool.candidates()).toEqual([]);

    pool.observe('10.20.30.40');
    expect(pool.candidates()).toEqual(['10.20.30.40']);
  });

  it('Criterion 12: Failure for one profile does not globally poison an otherwise healthy edge', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    // Profile 1 fails on candidate 198.51.100.1
    const inner1 = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    });
    const fallbackFetch1 = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const mockAgent1 = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;

    const session1 = new FallbackRemoteSession(inner1, pool, {
      ...baseOpts,
      fetch: fallbackFetch1,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: vi.fn().mockReturnValue(mockAgent1)
    });

    await expect(session1.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    expect(pool.getEntry('198.51.100.1')?.lastFailure).toBeDefined();

    // Profile 2 tries the same edge and succeeds
    const inner2 = new RemoteSession({
      ...baseOpts,
      routerId: 'router-2',
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    });
    const fallbackFetch2 = vi.fn().mockResolvedValue(new Response('{"profile2":true}', { status: 200 }));
    const mockAgent2 = {
      close: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined)
    } as unknown as Agent;

    const session2 = new FallbackRemoteSession(inner2, pool, {
      ...baseOpts,
      routerId: 'router-2',
      fetch: fallbackFetch2,
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1', '192.0.2.2']),
      createAgent: vi.fn().mockReturnValue(mockAgent2)
    });

    const response = await session2.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);
    expect(pool.getEntry('198.51.100.1')?.lastSuccess).toBeDefined();
  });

  it('Criterion 13: Fallback remains inside existing logical request/deadline budget', async () => {
    let currentTime = 1_000;
    const pool = new EdgePool({ now: () => currentTime });
    pool.observe('198.51.100.1');

    // Initial timeout 10_000ms -> deadline = 11_000.
    // Inner session takes 10_001ms and fails -> remainingMs <= 0.
    const inner = {
      effectiveTimeoutMs: (req: number) => Math.min(10_000, req),
      request: vi.fn().mockImplementation(() => {
        currentTime += 10_001;
        throw new TransportError('request deadline exceeded');
      })
    } as unknown as RemoteSession;

    const createAgentMock = vi.fn();
    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      timeoutMs: 10_000,
      now: () => currentTime,
      createAgent: createAgentMock
    });

    await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    // Since deadline expired during inner request, fallback made no candidate attempts
    expect(createAgentMock).not.toHaveBeenCalled();
  });

  it('Criterion 13: Fallback respects caller AbortSignal and aborts cleanly', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    const controller = new AbortController();

    const inner = {
      effectiveTimeoutMs: (req: number) => Math.min(10_000, req),
      request: vi.fn().mockImplementation(() => {
        controller.abort();
        throw new TransportError('request cancelled before it started');
      })
    } as unknown as RemoteSession;

    const createAgentMock = vi.fn();
    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      createAgent: createAgentMock
    });

    await expect(
      session.request('GET', '/rci/show/version', undefined, { signal: controller.signal })
    ).rejects.toBeInstanceOf(TransportError);

    // Aborted signal prevents fallback attempts
    expect(createAgentMock).not.toHaveBeenCalled();
  });

  it('Criterion 14: Missing/empty/corrupt optional cached state cannot break normal DNS path', async () => {
    const pool = new EdgePool(); // empty pool
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"healthy":true}', { status: 200 }));
    const inner = new RemoteSession({ ...baseOpts, fetch: fetchMock });

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: fetchMock,
      resolveDns: vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    });
    const response = await session.request('GET', '/rci/show/version');
    expect(response.status).toBe(200);

    // Also: when inner fails and pool is empty and DNS resolution fails -> throws cleanly
    const failingInner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    });
    const sessionEmpty = new FallbackRemoteSession(failingInner, pool, {
      ...baseOpts,
      resolveDns: vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    });

    await expect(sessionEmpty.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
  });
});

describe('Undici Agent lifecycle and Destination IP override', () => {
  it('Agent lifecycle disposal on candidate success', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    const closeMock = vi.fn().mockResolvedValue(undefined);
    const destroyMock = vi.fn().mockResolvedValue(undefined);
    const mockAgent = { close: closeMock, destroy: destroyMock } as unknown as Agent;

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: vi.fn().mockResolvedValue(new Response('{}', { status: 200 })),
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: vi.fn().mockReturnValue(mockAgent)
    });

    expect(session.activeAgentCount).toBe(0);
    await session.request('GET', '/rci/show/version');

    // On success: close() called, destroy() not called, activeAgentCount back to 0
    expect(closeMock).toHaveBeenCalled();
    expect(destroyMock).not.toHaveBeenCalled();
    expect(session.activeAgentCount).toBe(0);
  });

  it('Agent lifecycle disposal on candidate failure', async () => {
    const pool = new EdgePool();
    pool.observe('198.51.100.1');

    const inner = new RemoteSession({
      ...baseOpts,
      attempts: 1,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET'))
    });

    const closeMock = vi.fn().mockResolvedValue(undefined);
    const destroyMock = vi.fn().mockResolvedValue(undefined);
    const mockAgent = { close: closeMock, destroy: destroyMock } as unknown as Agent;

    const session = new FallbackRemoteSession(inner, pool, {
      ...baseOpts,
      fetch: vi.fn().mockRejectedValue(new Error('ECONNRESET')),
      resolveDns: vi.fn().mockResolvedValue(['192.0.2.1']),
      createAgent: vi.fn().mockReturnValue(mockAgent)
    });

    expect(session.activeAgentCount).toBe(0);
    await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);

    // On failure: destroy() called, activeAgentCount back to 0
    expect(destroyMock).toHaveBeenCalled();
    expect(session.activeAgentCount).toBe(0);
  });

  it('FallbackRemoteSession.close() closes all active agents', async () => {
    const pool = new EdgePool();
    const inner = new RemoteSession(baseOpts);
    const session = new FallbackRemoteSession(inner, pool, baseOpts);

    const closeMock = vi.fn().mockResolvedValue(undefined);
    const mockAgent = { close: closeMock, destroy: vi.fn() } as unknown as Agent;
    (session as unknown as { activeAgents: Set<Agent> }).activeAgents.add(mockAgent);

    expect(session.activeAgentCount).toBe(1);
    await session.close();
    expect(closeMock).toHaveBeenCalled();
    expect(session.activeAgentCount).toBe(0);
  });

  it('defaultCreateAgent custom lookup overrides destination IP while preserving SNI and verified TLS', async () => {
    // Generate self-signed test certificate with SubjectAltName = router.keendns.example
    const tmpDir = mkdtempSync(join(tmpdir(), 'tls-test-'));
    const keyFile = join(tmpDir, 'key.pem');
    const certFile = join(tmpDir, 'cert.pem');

    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes -keyout "${keyFile}" -out "${certFile}" ` +
      `-subj "/CN=router.keendns.example" -addext "subjectAltName=DNS:router.keendns.example" -days 1`,
      { stdio: 'ignore' }
    );

    const key = readFileSync(keyFile, 'utf8');
    const cert = readFileSync(certFile, 'utf8');
    rmSync(tmpDir, { recursive: true, force: true });

    let serverSni: string | false | null = null;
    let serverHost: string | undefined = undefined;

    const server: HttpsServer = createHttpsServer({ key, cert }, (req, res) => {
      serverHost = req.headers.host;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ verified: true }));
    });

    server.on('secureConnection', tlsSocket => {
      serverSni = tlsSocket.servername;
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve());
      server.on('error', reject);
    });

    const port = (server.address() as { port: number }).port;

    // Create undici Agent using defaultCreateAgent pointing to 127.0.0.1 with CA trusted
    const agent = defaultCreateAgent('127.0.0.1', { ca: cert });

    try {
      // Connect to logical hostname `router.keendns.example`
      const res = await fetch(`https://router.keendns.example:${port}/rci/show/version`, {
        dispatcher: agent as unknown as NonNullable<RequestInit['dispatcher']>
      });
      const data = (await res.json()) as { verified: boolean };

      expect(data.verified).toBe(true);
      // Socket connected to 127.0.0.1, but SNI and Host header match logical hostname
      expect(serverSni).toBe('router.keendns.example');
      expect(serverHost).toBe(`router.keendns.example:${port}`);
    } finally {
      await agent.close();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it('defaultCreateAgent enforces rejectUnauthorized: true on hostname mismatch', async () => {
    // Certificate is for `wrong.keendns.example`
    const tmpDir = mkdtempSync(join(tmpdir(), 'tls-mismatch-test-'));
    const keyFile = join(tmpDir, 'key.pem');
    const certFile = join(tmpDir, 'cert.pem');

    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes -keyout "${keyFile}" -out "${certFile}" ` +
      `-subj "/CN=wrong.keendns.example" -addext "subjectAltName=DNS:wrong.keendns.example" -days 1`,
      { stdio: 'ignore' }
    );

    const key = readFileSync(keyFile, 'utf8');
    const cert = readFileSync(certFile, 'utf8');
    rmSync(tmpDir, { recursive: true, force: true });

    const server: HttpsServer = createHttpsServer({ key, cert }, (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve());
      server.on('error', reject);
    });

    const port = (server.address() as { port: number }).port;
    const agent = defaultCreateAgent('127.0.0.1', { ca: cert });

    try {
      // URL is for `router.keendns.example`, cert is for `wrong.keendns.example`
      // rejectUnauthorized: true must cause TLS handshake to reject
      await expect(
        fetch(`https://router.keendns.example:${port}/rci/show/version`, {
          dispatcher: agent as unknown as NonNullable<RequestInit['dispatcher']>
        })
      ).rejects.toThrow();
    } finally {
      await agent.close();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it('createRemoteClient wires FallbackRemoteSession and defaultEdgePool', () => {
    const client = createRemoteClient(baseOpts);
    expect(client).toBeDefined();
    expect(client.rci).toBeDefined();
    expect(defaultEdgePool).toBeInstanceOf(EdgePool);
  });

  it('createClient (LAN) does not wrap in FallbackRemoteSession', () => {
    const client = createClient({
      host: '192.168.1.1',
      login: 'admin',
      password: 'password'
    });
    expect(client).toBeDefined();
    expect(client.rci).toBeDefined();
  });
});
