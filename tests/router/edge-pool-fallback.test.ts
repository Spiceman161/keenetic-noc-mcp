import { execFileSync } from 'node:child_process';
import { channel } from 'node:diagnostics_channel';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { Agent, buildConnector, fetch as undiciFetch } from 'undici';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { EdgePool } from '../../src/router/edge-pool.js';
import { RemoteSession } from '../../src/router/remote-session.js';
import { TransportError } from '../../src/router/errors.js';
import {
  RciTransportCollector,
  runWithRciTransportCollector
} from '../../src/telemetry/rci-transport.js';

type TestAddress = { address: string; family: number };
type TestLookup = (
  hostname: string,
  options: { all?: boolean | undefined },
  callback: (error: NodeJS.ErrnoException | null, address: string | TestAddress[], family?: number) => void
) => void;

const logicalHostname = 'router.synthetic.test';
const baseOptions = {
  endpoint: `https://${logicalHostname}/rci/`,
  login: 'agent',
  password: 'synthetic-password',
  routerId: 'synthetic-router',
  attempts: 1,
  timeoutMs: 1_000,
  sleep: async () => undefined,
  random: () => 0
};

interface TestCertificate {
  key: string;
  cert: string;
}

function certificateFor(hostname: string): TestCertificate {
  const directory = mkdtempSync(join(tmpdir(), 'keenetic-fallback-tls-'));
  const keyPath = join(directory, 'key.pem');
  const certPath = join(directory, 'cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath,
      '-subj', `/CN=${hostname}`,
      '-addext', `subjectAltName=DNS:${hostname}`,
      '-days', '1'
    ], { stdio: 'ignore' });
    return {
      key: readFileSync(keyPath, 'utf8'),
      cert: readFileSync(certPath, 'utf8')
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

interface TestTlsServer {
  server: HttpsServer;
  port: number;
  hosts: string[];
  serverNames: Array<string | false | null>;
  closeConnections(): void;
  close(): Promise<void>;
}

async function startTlsServer(
  certificate: TestCertificate,
  address = '127.0.0.1',
  handler?: Parameters<typeof createHttpsServer>[1]
): Promise<TestTlsServer> {
  const hosts: string[] = [];
  const serverNames: Array<string | false | null> = [];
  const server = createHttpsServer(certificate, handler ?? ((request, response) => {
    hosts.push(request.headers.host ?? '');
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  }));
  if (handler) server.on('request', request => hosts.push(request.headers.host ?? ''));
  server.on('secureConnection', socket => serverNames.push(socket.servername));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, address, () => resolve());
  });
  const result = server.address();
  if (result === null || typeof result === 'string') throw new Error('Missing test server address.');
  return {
    server,
    port: result.port,
    hosts,
    serverNames,
    closeConnections: () => server.closeAllConnections(),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  };
}

function lookupFrom(getAddresses: () => TestAddress[] | Error, count?: { value: number }): TestLookup {
  return (_hostname, options, callback) => {
    if (count) count.value += 1;
    const result = getAddresses();
    if (result instanceof Error) {
      callback(result as NodeJS.ErrnoException, '', 0);
      return;
    }
    if (options.all) callback(null, result);
    else callback(null, result[0]!.address, result[0]!.family);
  };
}

let validCertificate: TestCertificate;
let wrongCertificate: TestCertificate;

beforeAll(() => {
  validCertificate = certificateFor(logicalHostname);
  wrongCertificate = certificateFor('wrong.synthetic.test');
});

describe('EdgePool', () => {
  it('validates and canonicalizes literals while deduplicating observations', () => {
    let now = 10;
    const pool = new EdgePool({ now: () => now });
    pool.observe('not-an-address');
    pool.observe('0:0:0:0:0:0:0:1');
    now = 20;
    pool.observe('::1');
    pool.observe('192.0.2.1');
    expect(pool.size()).toBe(2);
    expect(pool.getEntry('::1')).toMatchObject({
      ip: '::1', firstObservedAt: 10, lastObservedAt: 20
    });
  });

  it('keeps observation freshness independent from health', () => {
    let now = 100;
    const pool = new EdgePool({ now: () => now });
    pool.observe('192.0.2.1');
    now = 200;
    pool.recordFailure('192.0.2.1');
    pool.recordFailure('192.0.2.2');
    now = 300;
    pool.recordSuccess('192.0.2.1');
    pool.recordSuccess('192.0.2.3');
    expect(pool.getEntry('192.0.2.1')).toEqual({
      ip: '192.0.2.1', firstObservedAt: 100, lastObservedAt: 100,
      lastFailureAt: 200, lastSuccessAt: 300
    });
    expect(pool.size()).toBe(1);
  });

  it('does not revive stale entries through success or failure', () => {
    let now = 0;
    const pool = new EdgePool({ now: () => now, staleThresholdMs: 100 });
    pool.observe('192.0.2.1');
    now = 101;
    pool.recordSuccess('192.0.2.1');
    pool.recordFailure('192.0.2.1');
    expect(pool.candidates()).toEqual([]);
    expect(pool.getEntry('192.0.2.1')?.lastObservedAt).toBe(0);
  });

  it('uses the exact three-tier ordering and lexical ties', () => {
    let now = 1;
    const pool = new EdgePool({ now: () => now });
    for (const ip of ['192.0.2.6', '192.0.2.5', '192.0.2.4', '192.0.2.3', '192.0.2.2', '192.0.2.1']) {
      pool.observe(ip);
    }
    now = 10;
    pool.recordSuccess('192.0.2.2');
    pool.recordSuccess('192.0.2.1');
    now = 20;
    pool.recordFailure('192.0.2.3');
    pool.recordFailure('192.0.2.4');
    now = 30;
    pool.recordFailure('192.0.2.2');
    expect(pool.candidates()).toEqual(['192.0.2.1', '192.0.2.5']);
    expect(pool.candidates(['192.0.2.1', '192.0.2.5'])).toEqual([
      '192.0.2.6', '192.0.2.3'
    ]);
    expect(pool.candidates(['192.0.2.1', '192.0.2.5', '192.0.2.6', '192.0.2.3']))
      .toEqual(['192.0.2.4', '192.0.2.2']);
  });

  it('excludes canonical attempted addresses and caps results at two', () => {
    const pool = new EdgePool();
    pool.observe('::1');
    pool.observe('192.0.2.1');
    pool.observe('192.0.2.2');
    expect(pool.candidates(new Set(['0:0:0:0:0:0:0:1']), 50)).toEqual([
      '192.0.2.1', '192.0.2.2'
    ]);
  });

  it('evicts the oldest observation with a lexical tie-break at the cap', () => {
    let now = 1;
    const pool = new EdgePool({ now: () => now, maxEntries: 2 });
    pool.observe('192.0.2.2');
    pool.observe('192.0.2.1');
    now = 2;
    pool.observe('192.0.2.3');
    expect(pool.getEntry('192.0.2.1')).toBeUndefined();
    expect(pool.candidates([], 2)).toEqual(['192.0.2.3', '192.0.2.2']);
  });

  it('keeps health rankings isolated between sessions', () => {
    let now = 1;
    const first = new EdgePool({ now: () => now });
    const second = new EdgePool({ now: () => now });
    for (const pool of [first, second]) {
      pool.observe('192.0.2.1');
      pool.observe('192.0.2.2');
    }
    now = 2;
    first.recordFailure('192.0.2.1');
    second.recordSuccess('192.0.2.1');
    expect(first.candidates()).toEqual(['192.0.2.2', '192.0.2.1']);
    expect(second.candidates()).toEqual(['192.0.2.1', '192.0.2.2']);
  });
});

describe('documented Undici 6.28.1 diagnostics contract', () => {
  it('pins the exact installed runtime version', () => {
    const metadata = JSON.parse(readFileSync('node_modules/undici/package.json', 'utf8')) as {
      version: string;
    };
    const manifest = JSON.parse(readFileSync('package.json', 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const lock = JSON.parse(readFileSync('package-lock.json', 'utf8')) as {
      packages: Record<string, { dependencies?: Record<string, string>; version?: string }>;
    };
    expect(metadata.version).toBe('6.28.1');
    expect(manifest.dependencies['undici']).toBe('6.28.1');
    expect(lock.packages['']?.dependencies?.['undici']).toBe('6.28.1');
    expect(lock.packages['node_modules/undici']?.version).toBe('6.28.1');
  });

  it('ships the exact consumer dependency in the packed artifact without network access', () => {
    const directory = mkdtempSync(join(tmpdir(), 'keenetic-packed-artifact-'));
    try {
      const packed = JSON.parse(execFileSync('npm', [
        'pack', '--json', '--ignore-scripts', '--pack-destination', directory
      ], { encoding: 'utf8' })) as Array<{ filename: string }>;
      const tarball = join(directory, packed[0]!.filename);
      const manifest = JSON.parse(execFileSync('tar', [
        '-xOf', tarball, 'package/package.json'
      ], { encoding: 'utf8' })) as {
        dependencies: Record<string, string>;
      };
      expect(manifest.dependencies['undici']).toBe('6.28.1');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('correlates distinct reused requests to the same public socket peer with one lookup', async () => {
    const server: HttpServer = createHttpServer((_request, response) => response.end('{}'));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Missing HTTP server address.');
    let lookups = 0;
    const agent = new Agent({ connect: buildConnector({ lookup: (_hostname, options, callback) => {
      lookups += 1;
      if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
      else callback(null, '127.0.0.1', 4);
    } }) });
    const origin = `http://diagnostics.synthetic.test:${address.port}`;
    const created: object[] = [];
    const sent: Array<{ request: object; remoteAddress: string | undefined }> = [];
    const createChannel = channel('undici:request:create');
    const sendChannel = channel('undici:client:sendHeaders');
    const onCreate = (message: unknown): void => {
      const request = (message as { request: { origin?: string } }).request;
      if (String(request.origin) === origin) created.push(request);
    };
    const onSend = (message: unknown): void => {
      const value = message as { request: { origin?: string }; socket: { remoteAddress?: string } };
      if (String(value.request.origin) === origin) {
        sent.push({ request: value.request, remoteAddress: value.socket.remoteAddress });
      }
    };
    createChannel.subscribe(onCreate);
    sendChannel.subscribe(onSend);
    try {
      await (await undiciFetch(`${origin}/one`, { dispatcher: agent })).text();
      await new Promise(resolve => setImmediate(resolve));
      await (await undiciFetch(`${origin}/two`, { dispatcher: agent })).text();
      expect(lookups).toBe(1);
      expect(created).toHaveLength(2);
      expect(created[0]).not.toBe(created[1]);
      expect(sent.map(value => value.request)).toEqual(created);
      expect(sent.map(value => value.remoteAddress)).toEqual(['127.0.0.1', '127.0.0.1']);
    } finally {
      createChannel.unsubscribe(onCreate);
      sendChannel.unsubscribe(onSend);
      await agent.close();
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it('preserves request and connector-error object identity at request:error', async () => {
    const connectorError = Object.assign(new Error('synthetic lookup failure'), { code: 'ENOTFOUND' });
    const connector = buildConnector({ lookup: (_hostname, _options, callback) => {
      callback(connectorError, '', 0);
    } });
    let callbackError: Error | null = null;
    const agent = new Agent({ connect: (options, callback) => connector(options, (error, socket) => {
      callbackError = error;
      if (error !== null) callback(error, null);
      else callback(null, socket);
    }) });
    let createdRequest: object | undefined;
    let erroredRequest: object | undefined;
    let diagnosticError: unknown;
    const createChannel = channel('undici:request:create');
    const errorChannel = channel('undici:request:error');
    const onCreate = (message: unknown): void => {
      const request = (message as { request: { origin?: string } }).request;
      if (String(request.origin).startsWith('http://error.synthetic.test')) createdRequest = request;
    };
    const onError = (message: unknown): void => {
      const value = message as { request: { origin?: string }; error: unknown };
      if (String(value.request.origin).startsWith('http://error.synthetic.test')) {
        erroredRequest = value.request;
        diagnosticError = value.error;
      }
    };
    createChannel.subscribe(onCreate);
    errorChannel.subscribe(onError);
    try {
      await expect(undiciFetch('http://error.synthetic.test/', { dispatcher: agent })).rejects.toThrow();
      expect(erroredRequest).toBe(createdRequest);
      expect(callbackError).toBe(connectorError);
      expect(diagnosticError).toBe(connectorError);
    } finally {
      createChannel.unsubscribe(onCreate);
      errorChannel.unsubscribe(onError);
      await agent.destroy();
    }
  });

  it('publishes one connector error for multiple distinct queued request objects', async () => {
    const connectorError = new Error('shared connector failure');
    let connectorCalls = 0;
    const agent = new Agent({
      connections: 1,
      connect: (_options, callback) => {
        connectorCalls += 1;
        setImmediate(() => callback(connectorError, null));
      }
    });
    const requests: object[] = [];
    const errors: unknown[] = [];
    const errorChannel = channel('undici:request:error');
    const onError = (message: unknown): void => {
      const value = message as { request: { origin?: string }; error: unknown };
      if (String(value.request.origin) === 'http://queued.synthetic.test') {
        requests.push(value.request);
        errors.push(value.error);
      }
    };
    errorChannel.subscribe(onError);
    try {
      const results = await Promise.allSettled([
        undiciFetch('http://queued.synthetic.test/one', { dispatcher: agent }),
        undiciFetch('http://queued.synthetic.test/two', { dispatcher: agent })
      ]);
      expect(results.every(result => result.status === 'rejected')).toBe(true);
      expect(connectorCalls).toBe(1);
      expect(requests).toHaveLength(2);
      expect(requests[0]).not.toBe(requests[1]);
      expect(errors).toEqual([connectorError, connectorError]);
    } finally {
      errorChannel.unsubscribe(onError);
      await agent.destroy();
    }
  });

  it('subscribes once per module rather than once per session', () => {
    const script = `
      import diagnostics from 'node:diagnostics_channel';
      const prototype = Object.getPrototypeOf(diagnostics.channel('synthetic:probe'));
      const original = prototype.subscribe;
      const names = [];
      prototype.subscribe = function (listener) { names.push(this.name); return original.call(this, listener); };
      const { RemoteSession } = await import('./dist/router/remote-session.js');
      for (let index = 0; index < 5; index += 1) {
        new RemoteSession({ endpoint: 'https://router.synthetic.test/rci/', login: 'x', password: 'y', routerId: String(index) });
      }
      process.stdout.write(JSON.stringify(names));
    `;
    const names = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8'
    })) as string[];
    expect(names).toEqual([
      'undici:request:create', 'undici:client:sendHeaders', 'undici:request:error'
    ]);
  });
});

describe('RemoteSession pool fallback integration', () => {
  it('uses normal dual-address failover without a pool attempt', async () => {
    const server = await startTlsServer(validCertificate);
    const pinned: string[] = [];
    const lookupCount = { value: 0 };
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      lookup: lookupFrom(() => [
        { address: '127.0.0.2', family: 4 },
        { address: '127.0.0.1', family: 4 }
      ], lookupCount),
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      expect(lookupCount.value).toBe(1);
      expect(pinned).toEqual([]);
    } finally {
      await server.close();
    }
  });

  it('learns duplicate A/AAAA answers once with no post-request lookup', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    const lookupCount = { value: 0 };
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [
        { address: '127.0.0.1', family: 4 },
        { address: '127.0.0.1', family: 4 },
        { address: '0:0:0:0:0:0:0:1', family: 6 },
        { address: '::1', family: 6 }
      ], lookupCount)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      await new Promise(resolve => setImmediate(resolve));
      await (await session.request('GET', '/rci/show/system')).text();
      expect(lookupCount.value).toBe(1);
      expect(pool.size()).toBe(2);
      expect(pool.getEntry('127.0.0.1')?.lastSuccessAt).toBeDefined();
      expect(pool.getEntry('::1')).toBeDefined();
    } finally {
      await server.close();
    }
  });

  it('excludes the exact rotated normal set and recovers through a previously observed edge', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    const pinned: string[] = [];
    const lookupCount = { value: 0 };
    let phase: 'seed' | 'rotated' = 'seed';
    const session = new RemoteSession({
      ...baseOptions,
      attempts: 2,
      timeoutMs: 5_000,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => phase === 'seed'
        ? [{ address: '127.0.0.1', family: 4 }]
        : [{ address: '127.0.0.2', family: 4 }, { address: '127.0.0.3', family: 4 }], lookupCount),
      onPinnedAgent: (agent, ip) => {
        pinned.push(ip);
        vi.spyOn(agent, 'close');
      }
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      phase = 'rotated';
      const collector = new RciTransportCollector({
        connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
      });
      const response = await runWithRciTransportCollector(collector,
        () => session.request('GET', '/rci/show/system'));
      await response.text();
      expect(pinned).toEqual(['127.0.0.1']);
      expect(lookupCount.value).toBe(3);
      expect(pool.getEntry('127.0.0.2')?.lastFailureAt).toBeDefined();
      expect(pool.getEntry('127.0.0.3')?.lastFailureAt).toBeDefined();
      expect(pool.getEntry('127.0.0.1')?.lastSuccessAt).toBeDefined();
      expect(server.hosts.at(-1)).toBe(`${logicalHostname}:${server.port}`);
      expect(server.serverNames.at(-1)).toBe(logicalHostname);
      expect(collector.seal()).toMatchObject({
        normal_attempts: 2,
        fallback_considered: 1,
        fallback_activations: 1,
        fallback_attempts: 1,
        fallback_recoveries: 1,
        terminal_reasons: { fallback_recovered: 1 },
        fallback_events: [{ outcome: 'recovered', candidates: [{ attempted: true, outcome: 'recovered' }] }]
      });
    } finally {
      await server.close();
    }
  });

  it('uses a prior edge after a correlated DNS failure with an empty attempted set', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const pinned: string[] = [];
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      expect(pinned).toEqual(['127.0.0.1']);
    } finally {
      await server.close();
    }
  });

  it('fails closed when a custom fetch rejection has no documented correlation', async () => {
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const pinned = vi.fn();
    const fetch = vi.fn().mockRejectedValue(new Error('synthetic transport failure'));
    const session = new RemoteSession({ ...baseOptions, fetch }, {
      edgePool: pool,
      onPinnedAgent: pinned
    });
    await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    expect(fetch).toHaveBeenCalledOnce();
    expect(pinned).not.toHaveBeenCalled();
  });

  it('reports no-candidate and multi-candidate exhaustion evidence through RemoteSession', async () => {
    const failingLookup = lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), {
      code: 'ENOTFOUND'
    }));
    const noCandidates = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const emptySession = new RemoteSession(baseOptions, { lookup: failingLookup });
    await expect(runWithRciTransportCollector(noCandidates,
      () => emptySession.request('GET', '/rci/show/version'))).rejects.toBeInstanceOf(TransportError);
    expect(noCandidates.seal()).toMatchObject({
      fallback_considered: 1, fallback_activations: 0, fallback_attempts: 0,
      terminal_reasons: { fallback_no_candidates: 1 }
    });

    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    pool.observe('127.0.0.2');
    const exhausted = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const session = new RemoteSession({ ...baseOptions, timeoutMs: 500 }, {
      edgePool: pool, lookup: failingLookup
    });
    await expect(runWithRciTransportCollector(exhausted,
      () => session.request('GET', '/rci/show/version'))).rejects.toBeInstanceOf(TransportError);
    expect(exhausted.seal()).toMatchObject({
      fallback_considered: 1, fallback_activations: 1, fallback_attempts: 2,
      fallback_exhaustions: 1, terminal_reasons: { fallback_exhausted: 1 },
      fallback_events: [{ outcome: 'exhausted', candidates: [
        { attempted: true, outcome: 'failed' }, { attempted: true, outcome: 'failed' }
      ] }]
    });
  });

  it('keeps a barrier-controlled concurrent normal/fallback pair causally separate', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const sharedError = Object.assign(new Error('shared synthetic DNS failure'), { code: 'ENOTFOUND' });
    const callbacks: Array<Parameters<TestLookup>[2]> = [];
    let failLookups = false;
    const lookup: TestLookup = (_hostname, _options, callback) => {
      if (!failLookups) {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
        return;
      }
      callbacks.push(callback);
      if (callbacks.length === 2) {
        callbacks[0]!(sharedError, '', 0);
        callbacks[1]!(null, [{ address: '127.0.0.1', family: 4 }]);
      }
    };
    const pinned: string[] = [];
    const session = new RemoteSession({
      ...baseOptions,
      timeoutMs: 5_000,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup,
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      failLookups = true;
      const fallbackCollector = new RciTransportCollector({
        connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
      });
      const normalCollector = new RciTransportCollector({
        connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
      });
      const first = runWithRciTransportCollector(fallbackCollector,
        () => session.request('GET', '/rci/show/version'));
      const second = runWithRciTransportCollector(normalCollector,
        () => session.request('GET', '/rci/show/system'));
      const responses = await Promise.all([first, second]);
      await Promise.all(responses.map(response => response.text()));
      expect(pinned).toEqual(['127.0.0.1']);
      expect(fallbackCollector.seal()).toMatchObject({
        normal_attempts: 1,
        fallback_activations: 1,
        fallback_attempts: 1,
        terminal_reasons: { fallback_recovered: 1 }
      });
      expect(normalCollector.seal()).toMatchObject({
        normal_attempts: 1,
        fallback_activations: 0,
        fallback_attempts: 0,
        terminal_reasons: { normal_response: 1 }
      });
    } finally {
      await server.close();
    }
  });

  it('ignores unrelated and malformed diagnostic traffic', async () => {
    const pool = new EdgePool();
    const session = new RemoteSession({ ...baseOptions, fetch: vi.fn().mockResolvedValue(new Response('{}')) }, {
      edgePool: pool
    });
    expect(() => {
      channel('undici:request:create').publish(null);
      channel('undici:client:sendHeaders').publish({ request: {}, socket: {} });
      channel('undici:request:error').publish({ request: {}, error: {} });
    }).not.toThrow();
    const server: HttpServer = createHttpServer((_request, response) => response.end('{}'));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Missing HTTP server address.');
    try {
      await (await undiciFetch(`http://127.0.0.1:${address.port}/`)).text();
      await session.request('GET', '/rci/show/version');
      expect(pool.size()).toBe(0);
    } finally {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it('ignores valid sendHeaders diagnostics replayed after a settled success', async () => {
    let now = 10;
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool({ now: () => now });
    const endpoint = `https://${logicalHostname}:${server.port}/rci/`;
    const origin = new URL(endpoint).origin;
    let sent: { request: object; socket: object } | undefined;
    const sendChannel = channel('undici:client:sendHeaders');
    const onSend = (message: unknown): void => {
      const value = message as { request?: { origin?: unknown }; socket?: object };
      if (value.request !== undefined && value.socket !== undefined &&
          String(value.request.origin) === origin) {
        sent = { request: value.request, socket: value.socket };
      }
    };
    sendChannel.subscribe(onSend);
    const session = new RemoteSession({ ...baseOptions, endpoint }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{ address: '127.0.0.1', family: 4 }])
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      sendChannel.unsubscribe(onSend);
      if (sent === undefined) throw new Error('Missing captured sendHeaders diagnostics.');
      const before = { ...pool.getEntry('127.0.0.1')! };
      now = 20;

      sendChannel.publish(sent);

      expect(pool.getEntry('127.0.0.1')).toEqual(before);
    } finally {
      sendChannel.unsubscribe(onSend);
      await server.close();
    }
  });

  it('ignores valid request:error diagnostics replayed after a settled failure', async () => {
    let now = 10;
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool({ now: () => now });
    const endpoint = `https://${logicalHostname}:${server.port}/rci/`;
    const origin = new URL(endpoint).origin;
    let failed: { request: object; error: object } | undefined;
    const errorChannel = channel('undici:request:error');
    const onError = (message: unknown): void => {
      const value = message as { request?: { origin?: unknown }; error?: object };
      if (value.request !== undefined && value.error !== undefined &&
          String(value.request.origin) === origin) {
        failed = { request: value.request, error: value.error };
      }
    };
    errorChannel.subscribe(onError);
    const session = new RemoteSession({ ...baseOptions, endpoint }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{ address: '127.0.0.2', family: 4 }])
    });
    try {
      await expect(session.request('GET', '/rci/show/version'))
        .rejects.toBeInstanceOf(TransportError);
      errorChannel.unsubscribe(onError);
      if (failed === undefined) throw new Error('Missing captured request:error diagnostics.');
      const before = { ...pool.getEntry('127.0.0.2')! };
      now = 20;

      errorChannel.publish(failed);

      expect(pool.getEntry('127.0.0.2')).toEqual(before);
    } finally {
      errorChannel.unsubscribe(onError);
      await server.close();
    }
  });

  it('bounds a never-settling lookup and ignores its late callback', async () => {
    const pool = new EdgePool();
    let lateCallback: Parameters<TestLookup>[2] | undefined;
    const pinned = vi.fn();
    const session = new RemoteSession({ ...baseOptions, timeoutMs: 30 }, {
      edgePool: pool,
      lookup: (_hostname, _options, callback) => { lateCallback = callback; },
      onPinnedAgent: pinned
    });
    await expect(session.request('GET', '/rci/show/version')).rejects.toThrow(/deadline/i);
    lateCallback?.(null, '127.0.0.1', 4);
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(pool.size()).toBe(0);
    expect(pinned).not.toHaveBeenCalled();
  });

  it('shares the replay gate between ordinary retry and pool fallback', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    const pinned: string[] = [];
    let rotated = false;
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{ address: rotated ? '127.0.0.2' : '127.0.0.1', family: 4 }]),
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      rotated = true;
      await expect(session.request('POST', '/rci/', {
        system: { configuration: { save: {} } }
      })).rejects.toBeInstanceOf(TransportError);
      expect(pinned).toEqual([]);
      const response = await session.request('POST', '/rci/', { show: { version: {} } });
      await response.text();
      expect(pinned).toEqual(['127.0.0.1']);
    } finally {
      await server.close();
    }
  });

  it('sends the immutable show snapshot through pinned fallback after caller mutation', async () => {
    const receivedBodies: string[] = [];
    const server = await startTlsServer(validCertificate, '127.0.0.1', (request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', chunk => chunks.push(Buffer.from(chunk)));
      request.on('end', () => {
        if (request.method === 'POST') receivedBodies.push(Buffer.concat(chunks).toString('utf8'));
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('{}');
      });
    });
    const pool = new EdgePool();
    const pinned: string[] = [];
    const body: Record<string, unknown> = { show: { version: {} } };
    let failLookup = false;
    const lookup: TestLookup = (_hostname, options, callback) => {
      if (!failLookup) {
        if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
        else callback(null, '127.0.0.1', 4);
        return;
      }
      delete body['show'];
      body['system'] = { configuration: { save: {} } };
      callback(Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' }), '', 0);
    };
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup,
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      failLookup = true;

      await (await session.request('POST', '/rci/', body)).text();

      expect(pinned).toEqual(['127.0.0.1']);
      expect(receivedBodies).toEqual(['{"show":{"version":{}}}']);
      expect(receivedBodies[0]).not.toContain('configuration');
    } finally {
      await server.close();
    }
  });

  it('keeps overlapping sessions and their health evidence isolated', async () => {
    const server = await startTlsServer(validCertificate, '127.0.0.1', async (_request, response) => {
      await new Promise(resolve => setTimeout(resolve, 20));
      response.end('{}');
    });
    const firstPool = new EdgePool();
    const secondPool = new EdgePool();
    secondPool.observe('127.0.0.1');
    const first = new RemoteSession({
      ...baseOptions,
      routerId: 'first',
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: firstPool,
      lookup: lookupFrom(() => [{ address: '127.0.0.1', family: 4 }])
    });
    const second = new RemoteSession({
      ...baseOptions,
      routerId: 'second',
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: secondPool,
      lookup: lookupFrom(() => Object.assign(new Error('second DNS failure'), { code: 'ENOTFOUND' }))
    });
    try {
      const responses = await Promise.all([
        first.request('GET', '/rci/show/version'),
        second.request('GET', '/rci/show/version')
      ]);
      await Promise.all(responses.map(response => response.text()));
      expect(firstPool.size()).toBe(1);
      expect(firstPool.getEntry('127.0.0.1')?.lastSuccessAt).toBeDefined();
      expect(secondPool.size()).toBe(1);
      expect(secondPool.getEntry('127.0.0.1')?.lastSuccessAt).toBeDefined();
    } finally {
      await server.close();
    }
  });
});

describe('RemoteSession fallback TLS, families, deadlines and cleanup', () => {
  it('uses the production fixed lookup for IPv6 while preserving Host, SNI and verified TLS', async () => {
    const server = await startTlsServer(validCertificate, '::1');
    const pool = new EdgePool();
    pool.observe('0:0:0:0:0:0:0:1');
    const pinned: string[] = [];
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: (_agent, ip) => pinned.push(ip)
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      expect(pinned).toEqual(['::1']);
      expect(server.hosts).toEqual([`${logicalHostname}:${server.port}`]);
      expect(server.serverNames).toEqual([logicalHostname]);
    } finally {
      await server.close();
    }
  });

  it('fails closed for hostname mismatch even with hostile runtime input', async () => {
    const server = await startTlsServer(wrongCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const options = {
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`,
      rejectUnauthorized: false
    };
    const session = new RemoteSession(options, {
      ca: wrongCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' }))
    });
    try {
      await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    } finally {
      await server.close();
    }
  });

  it('fails closed for an untrusted certificate', async () => {
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' }))
    });
    try {
      await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
    } finally {
      await server.close();
    }
  });

  it('flushes post-connect cancellation evidence without mutating pool health', async () => {
    let requestStarted!: () => void;
    const started = new Promise<void>(resolve => { requestStarted = resolve; });
    const server = await startTlsServer(validCertificate, '127.0.0.1', () => requestStarted());
    const pool = new EdgePool();
    const controller = new AbortController();
    const collector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const session = new RemoteSession({
      ...baseOptions,
      timeoutMs: 5_000,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{ address: '127.0.0.1', family: 4 }])
    });
    try {
      const pending = runWithRciTransportCollector(collector, () => session.request(
        'GET', '/rci/show/version', undefined, { signal: controller.signal }
      ));
      await started;
      controller.abort();
      await expect(pending).rejects.toBeInstanceOf(TransportError);
      expect(pool.size()).toBe(0);
      await expect(Promise.resolve(collector.seal())).resolves.toMatchObject({
        normal_attempts: 1,
        observed_edge_ips: ['127.0.0.1'],
        selected_normal_edge_ips: ['127.0.0.1'],
        correlation_complete: true,
        terminal_reasons: { cancelled: 1 }
      });
    } finally {
      await server.close();
    }
  });

  it('records an honest incomplete pre-correlation deadline without mutating pool health', async () => {
    const pool = new EdgePool();
    const collector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const fetch = vi.fn((_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('synthetic abort')), {
          once: true
        });
      }));
    const session = new RemoteSession({ ...baseOptions, fetch, timeoutMs: 20 }, { edgePool: pool });

    await expect(runWithRciTransportCollector(collector,
      () => session.request('GET', '/rci/show/version'))).rejects.toThrow(/deadline/i);
    expect(pool.size()).toBe(0);
    await expect(Promise.resolve(collector.seal())).resolves.toMatchObject({
      normal_attempts: 1,
      observed_edge_ips: [],
      selected_normal_edge_ips: [],
      correlation_complete: false,
      terminal_reasons: { deadline_exceeded: 1 }
    });
  });

  it('destroys an in-flight pinned Agent on cancellation and starts no later candidate', async () => {
    let requestStarted!: () => void;
    const started = new Promise<void>(resolve => { requestStarted = resolve; });
    const server = await startTlsServer(validCertificate, '127.0.0.1', () => requestStarted());
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    pool.observe('127.0.0.2');
    const controller = new AbortController();
    const agents: Agent[] = [];
    const session = new RemoteSession({
      ...baseOptions,
      timeoutMs: 5_000,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: agent => {
        agents.push(agent);
        vi.spyOn(agent, 'destroy');
      }
    });
    const collector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    try {
      const pending = runWithRciTransportCollector(collector, () => session.request(
        'GET', '/rci/show/version', undefined, { signal: controller.signal }
      ));
      await started;
      controller.abort();
      await expect(pending).rejects.toBeInstanceOf(TransportError);
      expect(agents).toHaveLength(1);
      expect(agents[0]!.destroy).toHaveBeenCalled();
      expect(collector.seal()).toMatchObject({
        fallback_attempts: 1, terminal_reasons: { cancelled: 1 },
        fallback_events: [{ outcome: 'cancelled', candidates: [{ attempted: true }, { attempted: false }] }]
      });
    } finally {
      await server.close();
    }
  });

  it('treats a pinned timeout as terminal with a stable clock and creates no later Agent', async () => {
    const server = await startTlsServer(validCertificate, '127.0.0.1', () => undefined);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    pool.observe('127.0.0.2');
    const agents: Agent[] = [];
    const collector = new RciTransportCollector({
      connection: { mode: 'remote', endpoint: 'https://edge.keenetic.pro/rci/' }
    });
    const session = new RemoteSession({
      ...baseOptions,
      timeoutMs: 50,
      now: () => 0,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: agent => {
        agents.push(agent);
        vi.spyOn(agent, 'destroy');
      }
    });
    try {
      let failure: unknown;
      try {
        await runWithRciTransportCollector(collector,
          () => session.request('GET', '/rci/show/version'));
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(TransportError);
      expect((failure as Error).message).toMatch(/deadline/i);
      expect(agents).toHaveLength(1);
      expect(agents[0]!.destroy).toHaveBeenCalled();
      expect(pool.getEntry('127.0.0.1')?.lastFailureAt).toBeUndefined();
      await expect(Promise.resolve(collector.seal())).resolves.toMatchObject({
        fallback_attempts: 1, terminal_reasons: { deadline_exceeded: 1 },
        fallback_events: [{ outcome: 'deadline_exceeded', candidates: [{ attempted: true }, { attempted: false }] }]
      });
    } finally {
      await server.close();
    }
  });

  it('checks cancellation before constructing a fallback Agent', async () => {
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    const controller = new AbortController();
    const pinned = vi.fn();
    const lookup: TestLookup = (_hostname, _options, callback) => {
      controller.abort();
      callback(Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' }), '', 0);
    };
    const session = new RemoteSession(baseOptions, {
      edgePool: pool,
      lookup,
      onPinnedAgent: pinned
    });
    await expect(session.request('GET', '/rci/show/version', undefined, {
      signal: controller.signal
    })).rejects.toBeInstanceOf(TransportError);
    expect(pinned).not.toHaveBeenCalled();
  });

  it('discards correlated supplied-IP updates when cancellation wins fallback admission', async () => {
    const server = await startTlsServer(validCertificate);
    let poolNow = 10;
    const pool = new EdgePool({ now: () => poolNow });
    pool.observe('127.0.0.2');
    const controller = new AbortController();
    const pinned = vi.fn();
    let race = false;
    let useFailingAddress = false;
    let clockReads = 0;
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`,
      now: () => {
        if (!race) return 0;
        clockReads += 1;
        if (clockReads === 5) controller.abort();
        return 0;
      }
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{
        address: useFailingAddress ? '127.0.0.2' : '127.0.0.1', family: 4
      }]),
      onPinnedAgent: pinned
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      const beforeWorking = { ...pool.getEntry('127.0.0.1')! };
      const beforeSupplied = { ...pool.getEntry('127.0.0.2')! };
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      useFailingAddress = true;
      poolNow = 20;
      race = true;

      let failure: unknown;
      try {
        await session.request('GET', '/rci/show/system', undefined, {
          signal: controller.signal
        });
      } catch (error) {
        failure = error;
      }

      expect(clockReads).toBe(5);
      expect(failure).toBeInstanceOf(TransportError);
      expect((failure as Error).message).toMatch(/request cancelled/i);
      expect((failure as Error).message).not.toMatch(/failed after/i);
      expect(pinned).not.toHaveBeenCalled();
      expect(pool.getEntry('127.0.0.1')).toEqual(beforeWorking);
      expect(pool.getEntry('127.0.0.2')).toEqual(beforeSupplied);
    } finally {
      await server.close();
    }
  });

  it('discards correlated selected-IP updates when deadline wins fallback admission', async () => {
    let failNormalRequest = false;
    const server = await startTlsServer(validCertificate, '127.0.0.1', (_request, response) => {
      if (failNormalRequest) {
        response.destroy();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
    let poolNow = 10;
    const pool = new EdgePool({ now: () => poolNow });
    pool.observe('127.0.0.2');
    const pinned = vi.fn();
    let race = false;
    let clockReads = 0;
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`,
      now: () => {
        if (!race) return 0;
        clockReads += 1;
        return clockReads >= 5 ? baseOptions.timeoutMs : 0;
      }
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => [{ address: '127.0.0.1', family: 4 }]),
      onPinnedAgent: pinned
    });
    try {
      await (await session.request('GET', '/rci/show/version')).text();
      const beforeSelected = { ...pool.getEntry('127.0.0.1')! };
      const beforeCandidate = { ...pool.getEntry('127.0.0.2')! };
      server.closeConnections();
      await new Promise(resolve => setTimeout(resolve, 20));
      failNormalRequest = true;
      poolNow = 20;
      race = true;

      let failure: unknown;
      try {
        await session.request('GET', '/rci/show/system');
      } catch (error) {
        failure = error;
      }

      expect(clockReads).toBe(5);
      expect(failure).toBeInstanceOf(TransportError);
      expect((failure as Error).message).toMatch(/request deadline exceeded/i);
      expect((failure as Error).message).not.toMatch(/failed after/i);
      expect(pinned).not.toHaveBeenCalled();
      expect(pool.getEntry('127.0.0.1')).toEqual(beforeSelected);
      expect(pool.getEntry('127.0.0.2')).toEqual(beforeCandidate);
    } finally {
      await server.close();
    }
  });

  it('starts graceful close on success and cleanup rejection cannot replace the response', async () => {
    vi.restoreAllMocks();
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.1');
    let closeSpy: ReturnType<typeof vi.spyOn> | undefined;
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: agent => {
        closeSpy = vi.spyOn(agent, 'close').mockRejectedValue(new Error('synthetic close rejection'));
      }
    });
    try {
      const response = await session.request('GET', '/rci/show/version');
      expect(response.status).toBe(200);
      expect(closeSpy).toHaveBeenCalledOnce();
      await response.text();
    } finally {
      await server.close();
    }
  });

  it('destroys a failed candidate and cleanup rejection cannot replace the typed error', async () => {
    vi.restoreAllMocks();
    const server = await startTlsServer(validCertificate);
    const pool = new EdgePool();
    pool.observe('127.0.0.2');
    let destroySpy: ReturnType<typeof vi.spyOn> | undefined;
    const session = new RemoteSession({
      ...baseOptions,
      endpoint: `https://${logicalHostname}:${server.port}/rci/`
    }, {
      ca: validCertificate.cert,
      edgePool: pool,
      lookup: lookupFrom(() => Object.assign(new Error('synthetic DNS failure'), { code: 'ENOTFOUND' })),
      onPinnedAgent: agent => {
        destroySpy = vi.spyOn(agent, 'destroy')
          .mockRejectedValue(new Error('synthetic destroy rejection'));
      }
    });
    try {
      await expect(session.request('GET', '/rci/show/version')).rejects.toBeInstanceOf(TransportError);
      expect(destroySpy).toHaveBeenCalledOnce();
    } finally {
      await server.close();
    }
  });
});

afterAll(() => {
  vi.restoreAllMocks();
});
