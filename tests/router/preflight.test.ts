import { describe, expect, it, vi } from 'vitest';
import type { KeeneticClient } from '../../src/router/client.js';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import { runRouterPreflight } from '../../src/router/preflight.js';
import type { RciProbeMetadata } from '../../src/router/rci.js';

const metadata = (available = true): RciProbeMetadata => ({
  httpStatus: available ? 200 : 404,
  contentTypeClass: 'json',
  shape: available ? 'object' : 'unknown',
  items: available ? 1 : null,
  bytes: 999,
  payloadShape: available ? 'object' : 'unknown',
  payloadItems: available ? 1 : null,
  payloadItemShape: available ? 'object' : 'unknown',
  wrapperDepth: 1
});

function client(options: {
  capabilitiesError?: Error;
  startupAvailable?: boolean;
  diagnosticFailure?: string;
  model?: string;
  firmware?: string;
  operationalError?: Error;
} = {}): KeeneticClient {
  return {
    capabilities: vi.fn(async () => {
      if (options.capabilitiesError) throw options.capabilitiesError;
      return {
        model: options.model ?? 'Keenetic Test raw-secret',
        hwId: 'KN-0000',
        firmware: options.firmware ?? '5.1.3',
        components: new Set<string>(),
        features: new Set<string>()
      };
    }),
    probedCapabilities: vi.fn(async () => {
      if (options.operationalError) throw options.operationalError;
      return ({
      config: {
        runningCli: { state: 'available', method: 'rci-show', reason: null },
        runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
        startup: options.startupAvailable === false
          ? { state: 'unavailable', method: null, reason: 'not-found' }
          : { state: 'available', method: 'rci-more', reason: null },
        backup: options.startupAvailable === false
          ? { state: 'unavailable', method: null, reason: 'not-found' }
          : { state: 'available', method: 'ci-file', reason: null }
      }
      });
    }),
    rci: {
      get: vi.fn(async (path: string) => {
        if (path === options.diagnosticFailure) throw new Error('raw diagnostic body raw-secret');
        return { privateConfiguration: 'raw-secret' };
      }),
      getText: vi.fn(async () => '! sanitized config'),
      probeGet: vi.fn(async (path: string) => {
        if (path === 'more?filename=startup-config') return metadata(options.startupAvailable !== false);
        return metadata();
      })
    }
  } as unknown as KeeneticClient;
}

const remote = { mode: 'remote' as const, endpoint: 'https://router.example.test/rci/' };
const lan = { mode: 'lan' as const, endpoint: '192.0.2.1' };
const remoteDeps = {
  resolveDns: vi.fn(async () => ['192.0.2.10', '2001:db8::10']),
  verifyTls: vi.fn(async () => undefined)
};

describe('router onboarding preflight', () => {
  it('verifies remote DNS and TLS without reporting addresses or certificate data', async () => {
    const result = await runRouterPreflight(remote, client(), remoteDeps);

    expect(result.ready).toBe(true);
    expect(result.checks['DNS resolution']).toEqual({ status: 'pass', detail: '2 addresses' });
    expect(result.checks['TLS']?.status).toBe('pass');
    expect(remoteDeps.resolveDns).toHaveBeenCalledWith('router.example.test');
    expect(remoteDeps.verifyTls).toHaveBeenCalledWith('router.example.test', '192.0.2.10', 443, 10_000);
    expect(remoteDeps.verifyTls).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(result)).not.toContain('192.0.2.10');
    expect(JSON.stringify(result)).not.toContain('2001:db8::10');
  });

  it('blocks on DNS failure and does not attempt TLS or RCI', async () => {
    const instance = client();
    const verifyTls = vi.fn(async () => undefined);
    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => { throw new Error('192.0.2.55 raw-secret'); },
      verifyTls
    });

    expect(result.ready).toBe(false);
    expect(result.checks['DNS resolution']?.status).toBe('fail');
    expect(verifyTls).not.toHaveBeenCalled();
    expect(instance.capabilities).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('192.0.2.55');
    expect(JSON.stringify(result.checks)).not.toContain('raw-secret');
  });

  it('freshly resolves DNS for every remote preflight invocation', async () => {
    const resolveDns = vi.fn()
      .mockResolvedValueOnce(['192.0.2.10'])
      .mockResolvedValueOnce(['2001:db8::10']);
    const verifyTls = vi.fn(async () => undefined);

    await runRouterPreflight(remote, client(), { resolveDns, verifyTls });
    await runRouterPreflight(remote, client(), { resolveDns, verifyTls });

    expect(resolveDns).toHaveBeenCalledTimes(2);
    expect(resolveDns).toHaveBeenNthCalledWith(1, 'router.example.test');
    expect(resolveDns).toHaveBeenNthCalledWith(2, 'router.example.test');
    expect(verifyTls).toHaveBeenNthCalledWith(1, 'router.example.test', '192.0.2.10', 443, 10_000);
    expect(verifyTls).toHaveBeenNthCalledWith(2, 'router.example.test', '2001:db8::10', 443, 10_000);
  });

  it('rejects a non-HTTPS endpoint before network access', async () => {
    const instance = client();
    const resolveDns = vi.fn(async () => ['192.0.2.10']);
    const result = await runRouterPreflight(
      { mode: 'remote', endpoint: 'http://router.example.test/rci/' },
      instance,
      { resolveDns }
    );

    expect(result).toEqual({
      ready: false,
      checks: { Endpoint: { status: 'fail', detail: 'invalid HTTPS endpoint' } }
    });
    expect(resolveDns).not.toHaveBeenCalled();
    expect(instance.capabilities).not.toHaveBeenCalled();
  });

  it('stops immediately on a certificate or hostname failure without exposing error data', async () => {
    const instance = client();
    let now = 0;
    const sleep = vi.fn(async (ms: number) => { now += ms; });
    const verifyTls = vi.fn(async (_hostname: string, _address: string) => {
      throw Object.assign(new Error('certificate SAN router.example.test 192.0.2.55 raw-secret'), {
        code: 'ERR_TLS_CERT_ALTNAME_INVALID'
      });
    });
    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => now
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({ status: 'fail', detail: 'certificate or hostname verification failed' });
    expect(verifyTls).toHaveBeenCalledTimes(1);
    expect(verifyTls).toHaveBeenCalledWith('router.example.test', '192.0.2.10', 443, 10_000);
    expect(sleep).not.toHaveBeenCalled();
    expect(instance.capabilities).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('raw-secret');
    expect(JSON.stringify(result)).not.toContain('router.example.test');
    expect(JSON.stringify(result)).not.toContain('192.0.2.55');
  });

  it('fails over from a timed-out address to the next verified TLS candidate', async () => {
    const instance = client();
    let now = 0;
    const sleep = vi.fn(async (ms: number) => { now += ms; });
    const verifyTls = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('timeout raw-secret'), { code: 'ETIMEDOUT' }))
      .mockResolvedValueOnce(undefined);

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => now
    });

    expect(result.ready).toBe(true);
    expect(result.checks['TLS']).toEqual({ status: 'pass', detail: 'certificate and hostname verified after retry' });
    expect(verifyTls).toHaveBeenNthCalledWith(1, 'router.example.test', '192.0.2.10', 443, 10_000);
    expect(verifyTls).toHaveBeenNthCalledWith(2, 'router.example.test', '2001:db8::10', 443, 10_000);
    expect(sleep).not.toHaveBeenCalled();
    expect(instance.capabilities).toHaveBeenCalledOnce();
  });

  it('keeps one-address retry behavior on the original hostname identity', async () => {
    const instance = client();
    let now = 0;
    const sleep = vi.fn(async (ms: number) => { now += ms; });
    const verifyTls = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('reset raw-secret'), { code: 'ECONNRESET' }))
      .mockResolvedValueOnce(undefined);

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10'],
      verifyTls,
      sleep,
      now: () => now
    });

    expect(result.ready).toBe(true);
    expect(verifyTls).toHaveBeenNthCalledWith(1, 'router.example.test', '192.0.2.10', 443, 10_000);
    expect(verifyTls).toHaveBeenNthCalledWith(2, 'router.example.test', '192.0.2.10', 443, 10_000);
    expect(sleep).toHaveBeenCalledWith(1_000);
  });

  it.each([
    'CERT_REVOKED',
    'CERT_UNTRUSTED',
    'CERT_REJECTED',
    'INVALID_CA',
    'INVALID_PURPOSE',
    'CERT_CHAIN_TOO_LONG',
    'UNABLE_TO_GET_ISSUER_CERT',
    'ERR_TLS_CERT_ALTNAME_INVALID',
    'HOSTNAME_MISMATCH'
  ])('treats %s as a terminal certificate failure without exposing error data', async code => {
    const instance = client();
    const sleep = vi.fn(async () => undefined);
    const verifyTls = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('router.example.test 192.0.2.55 raw-secret'), { code }))
      .mockResolvedValueOnce(undefined);

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => 0
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({ status: 'fail', detail: 'certificate or hostname verification failed' });
    expect(verifyTls).toHaveBeenCalledTimes(1);
    expect(verifyTls).toHaveBeenCalledWith('router.example.test', '192.0.2.10', 443, 10_000);
    expect(sleep).not.toHaveBeenCalled();
    expect(instance.capabilities).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('raw-secret');
    expect(JSON.stringify(result)).not.toContain('router.example.test');
    expect(JSON.stringify(result)).not.toContain('192.0.2.55');
  });

  it('fails an unknown TLS or protocol error immediately without exposing error data', async () => {
    const instance = client();
    const sleep = vi.fn(async () => undefined);
    const verifyTls = vi.fn()
      .mockRejectedValueOnce(Object.assign(
        new Error('wrong version router.example.test 192.0.2.55 raw-secret'),
        { code: 'ERR_SSL_WRONG_VERSION_NUMBER' }
      ))
      .mockResolvedValueOnce(undefined);

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => 0
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({ status: 'fail', detail: 'TLS connection failed' });
    expect(verifyTls).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(instance.capabilities).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('raw-secret');
    expect(JSON.stringify(result)).not.toContain('router.example.test');
    expect(JSON.stringify(result)).not.toContain('192.0.2.55');
  });

  it('enforces an absolute attempt deadline for a verifier that never settles', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(0);
      const instance = client();
      const verifyTls = vi.fn(() => new Promise<void>(() => undefined));
      const resultPromise = runRouterPreflight(remote, instance, {
        resolveDns: async () => ['192.0.2.10'],
        verifyTls,
        sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
        now: () => Date.now()
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(verifyTls).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(verifyTls).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(verifyTls).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(10_000);
      await vi.advanceTimersByTimeAsync(2_000);
      expect(verifyTls).toHaveBeenCalledTimes(3);
      await vi.advanceTimersByTimeAsync(7_000);
      const result = await resultPromise;

      expect(result.ready).toBe(false);
      expect(result.checks['TLS']).toEqual({
        status: 'fail', detail: 'TLS connection timeout or retry budget exhausted'
      });
      expect(instance.capabilities).not.toHaveBeenCalled();
      expect(verifyTls).toHaveBeenCalledTimes(3);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a verifier success observed after the total TLS deadline', async () => {
    const instance = client();
    let now = 0;
    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10'],
      verifyTls: async () => { now = 30_000; },
      sleep: async () => undefined,
      now: () => now
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({
      status: 'fail', detail: 'TLS connection timeout or retry budget exhausted'
    });
    expect(instance.capabilities).not.toHaveBeenCalled();
  });

  it('bounds safely transient failures across all resolved candidates and never calls RCI', async () => {
    const instance = client();
    const sleep = vi.fn(async () => undefined);
    const verifyTls = vi.fn(async (_hostname: string, _address: string) => {
      throw Object.assign(new Error('reset raw-secret'), { code: 'ECONNRESET' });
    });

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => 0
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({
      status: 'fail', detail: 'transient TCP/TLS connection failed after bounded retries'
    });
    expect(verifyTls).toHaveBeenCalledTimes(5);
    expect(verifyTls.mock.calls.map(call => call[1])).toEqual([
      '192.0.2.10', '2001:db8::10', '192.0.2.10', '2001:db8::10', '192.0.2.10'
    ]);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(instance.capabilities).not.toHaveBeenCalled();
  });

  it('uses one TLS budget and does not start a backoff that crosses its deadline', async () => {
    const instance = client();
    let now = 0;
    const timeouts: number[] = [];
    const sleep = vi.fn(async (ms: number) => { now += ms; });
    const verifyTls = vi.fn(async (_hostname: string, _address: string, _port: number, timeoutMs: number) => {
      timeouts.push(timeoutMs);
      now += timeoutMs;
      throw Object.assign(new Error('reset raw-secret'), { code: 'ECONNRESET' });
    });

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10', '2001:db8::10'],
      verifyTls,
      sleep,
      now: () => now
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({
      status: 'fail', detail: 'TLS connection timeout or retry budget exhausted'
    });
    expect(timeouts).toEqual([10_000, 10_000, 8_000]);
    expect(verifyTls.mock.calls.map(call => call[1])).toEqual([
      '192.0.2.10', '2001:db8::10', '192.0.2.10'
    ]);
    expect(sleep).toHaveBeenCalledWith(2_000);
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(instance.capabilities).not.toHaveBeenCalled();
  });

  it('keeps timeout failures distinct from transient TCP/TLS failures', async () => {
    const instance = client();
    const sleep = vi.fn(async () => undefined);
    const verifyTls = vi.fn(async () => {
      throw Object.assign(new Error('timeout raw-secret'), { code: 'ETIMEDOUT' });
    });

    const result = await runRouterPreflight(remote, instance, {
      resolveDns: async () => ['192.0.2.10'],
      verifyTls,
      sleep,
      now: () => 0
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']).toEqual({
      status: 'fail', detail: 'TLS connection timeout or retry budget exhausted'
    });
    expect(verifyTls).toHaveBeenCalledTimes(5);
    expect(sleep).toHaveBeenCalledTimes(4);
    expect(instance.capabilities).not.toHaveBeenCalled();
  });

  it.each([
    [new TransportError('host 192.0.2.66 raw-secret'), 'Reachability'],
    [new AuthError('password raw-secret rejected'), 'Authentication'],
    [new RciError('raw-secret response', { path: 'show/version', code: '500', ident: 'test' }), 'RCI']
  ] as const)('classifies a core failure without exposing its message', async (error, check) => {
    const result = await runRouterPreflight(lan, client({ capabilitiesError: error }));

    expect(result.ready).toBe(false);
    expect(result.checks[check]?.status).toBe('fail');
    expect(JSON.stringify(result)).not.toContain('raw-secret');
    expect(JSON.stringify(result)).not.toContain('192.0.2.66');
  });

  it('projects model and firmware and keeps optional failures as warnings', async () => {
    const instance = client({ startupAvailable: false, diagnosticFailure: 'show/internet/status' });
    const result = await runRouterPreflight(lan, instance);

    expect(result).toMatchObject({ ready: true, model: 'Keenetic Test raw-secret', firmware: '5.1.3' });
    expect(result.checks['Running config']).toEqual({ status: 'pass', detail: 'available through rci-show' });
    expect(result.checks['Startup config']?.status).toBe('warning');
    expect(result.checks['System diagnostic']?.status).toBe('pass');
    expect(result.checks['Internet diagnostic']?.status).toBe('warning');
    expect(result.checks['DNS diagnostic']?.status).toBe('pass');
    expect(result.checks['Backup']?.detail).toContain('/ci/startup-config.txt');
    expect(instance.rci.get).toHaveBeenCalledWith('show/system', 256_000);
    expect(instance.rci.get).toHaveBeenCalledWith('show/internet/status', 256_000);
    expect(instance.rci.get).toHaveBeenCalledWith('show/dns-proxy', 256_000);
    expect(JSON.stringify(result.checks)).not.toContain('privateConfiguration');
    expect(instance.rci.getText).not.toHaveBeenCalled();
  });

  it('keeps remote backup readiness separate from RCI startup reads', async () => {
    const result = await runRouterPreflight(remote, client(), remoteDeps);

    expect(result.checks['Startup config']?.status).toBe('pass');
    expect(result.checks['Backup']).toEqual({
      status: 'skipped',
      detail: 'write backup requires a LAN profile for /ci/startup-config.txt; read-only use is ready'
    });
  });

  it('reports an operational authentication failure without exposing its message', async () => {
    const result = await runRouterPreflight(lan, client({
      operationalError: new AuthError('password raw-secret rejected')
    }));
    expect(result.ready).toBe(true);
    expect(result.checks['Running config']?.detail).toBe('capability probe authentication failed');
    expect(JSON.stringify(result.checks)).not.toContain('raw-secret');
  });

  it('sanitizes and bounds router-controlled terminal fields', async () => {
    const model = `Keenetic\n\u001b[31mFAKE\u001b[0m\u001b]2;title\u0007\u202e ${'x'.repeat(200)}`;
    const result = await runRouterPreflight(lan, client({ model, firmware: '5.1.3\rspoof' }));
    expect(result.model).not.toMatch(/[\r\n\u001b\u0007\u202e]/);
    expect(Array.from(result.model ?? '')).toHaveLength(120);
    expect(result.firmware).toBe('5.1.3 spoof');
  });

  it('leaves LAN preflight independent of DNS, TLS, clock, and sleep hooks', async () => {
    const resolveDns = vi.fn(async () => ['192.0.2.10']);
    const verifyTls = vi.fn(async () => undefined);
    const sleep = vi.fn(async () => undefined);
    const now = vi.fn(() => 0);

    const result = await runRouterPreflight(lan, client(), { resolveDns, verifyTls, sleep, now });

    expect(result.ready).toBe(true);
    expect(resolveDns).not.toHaveBeenCalled();
    expect(verifyTls).not.toHaveBeenCalled();
    expect(sleep).not.toHaveBeenCalled();
    expect(now).not.toHaveBeenCalled();
    expect(result.checks['TLS']).toEqual({ status: 'skipped', detail: 'not required for LAN' });
  });
});
