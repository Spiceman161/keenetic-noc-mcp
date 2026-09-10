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
  resolveDns: vi.fn(async () => 2),
  verifyTls: vi.fn(async () => undefined)
};

describe('router onboarding preflight', () => {
  it('verifies remote DNS and TLS without reporting addresses or certificate data', async () => {
    const result = await runRouterPreflight(remote, client(), remoteDeps);

    expect(result.ready).toBe(true);
    expect(result.checks['DNS resolution']).toEqual({ status: 'pass', detail: '2 addresses' });
    expect(result.checks['TLS']?.status).toBe('pass');
    expect(remoteDeps.resolveDns).toHaveBeenCalledWith('router.example.test');
    expect(remoteDeps.verifyTls).toHaveBeenCalledWith('router.example.test', 443);
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

  it('rejects a non-HTTPS endpoint before network access', async () => {
    const instance = client();
    const resolveDns = vi.fn(async () => 1);
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

  it('blocks on TLS or certificate failure', async () => {
    const result = await runRouterPreflight(remote, client(), {
      resolveDns: async () => 1,
      verifyTls: async () => { throw new Error('certificate SAN contains raw-secret'); }
    });

    expect(result.ready).toBe(false);
    expect(result.checks['TLS']?.status).toBe('fail');
    expect(JSON.stringify(result)).not.toContain('raw-secret');
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
});
