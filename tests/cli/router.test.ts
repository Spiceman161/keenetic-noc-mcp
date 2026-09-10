import { describe, expect, it, vi } from 'vitest';
import { isWizardAction, runConnectionChecks } from '../../src/cli/router.js';
import { AuthError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import type { RouterProfile } from '../../src/profiles/registry.js';

const profile = (mode: 'lan' | 'remote'): RouterProfile => ({
  id: 'test', name: 'Test', mode,
  endpoint: mode === 'remote' ? 'https://rci.example.test/rci/' : '192.0.2.1',
  login: 'agent', secretRef: 'file:test', readOnly: true
});

function client(options: { baseError?: Error; diagnosticError?: string; startupAvailable?: boolean; backupError?: Error } = {}): KeeneticClient {
  return {
    capabilities: vi.fn(async () => {
      if (options.baseError) throw options.baseError;
      return { model: 'Keenetic Test', hwId: 'KN-0000', firmware: '5.1.3', components: new Set(), features: new Set() };
    }),
    probedCapabilities: vi.fn(async () => ({
      config: {
        runningCli: { state: 'available', method: 'rci-show', reason: null },
        runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
        startup: options.startupAvailable === false
          ? { state: 'unavailable', method: null, reason: 'not-found' }
          : { state: 'available', method: 'rci-more', reason: null },
        backup: options.backupError
          ? { state: 'unavailable', method: null, reason: 'denied' }
          : { state: 'available', method: 'ci-file', reason: null }
      }
    })),
    rci: {
      get: vi.fn(async (path: string) => {
        if (path === options.diagnosticError) throw new Error('unavailable');
        return {};
      }),
      getText: vi.fn(async () => {
        if (options.backupError) throw options.backupError;
        return '! sanitized config';
      }),
      probeGet: vi.fn(async (path: string) => ({
        httpStatus: path === 'more?filename=startup-config' && options.startupAvailable === false ? 404 : 200,
        contentTypeClass: 'json', shape: 'object', items: 1, bytes: 10,
        payloadShape: 'object', payloadItems: 1, payloadItemShape: 'object', wrapperDepth: 1
      }))
    }
  } as unknown as KeeneticClient;
}

const remoteDeps = { resolveDns: async () => 1, verifyTls: async () => undefined };

describe('router test checks', () => {
  it('keeps both add spellings routed to the wizard', () => {
    expect(isWizardAction('add')).toBe(true);
    expect(isWizardAction('init')).toBe(true);
    expect(isWizardAction('test')).toBe(false);
  });
  it('reuses preflight config and diagnostic reads', async () => {
    const instance = client();
    const result = await runConnectionChecks(profile('lan'), instance);
    expect(result.overall).toBe('healthy');
    expect(instance.rci.get).toHaveBeenCalledWith('show/system', 256_000);
    expect(instance.rci.get).toHaveBeenCalledWith('show/internet/status', 256_000);
    expect(instance.rci.get).toHaveBeenCalledWith('show/dns-proxy', 256_000);
    expect(instance.probedCapabilities).toHaveBeenCalledTimes(1);
  });

  it('keeps remote backup capability separate and healthy', async () => {
    const result = await runConnectionChecks(profile('remote'), client(), remoteDeps);
    expect(result.overall).toBe('healthy');
    expect(result.checks['Startup config']).toContain('available through rci-more');
    expect(result.checks['Backup']).toContain('write backup requires a LAN profile');
    expect(result.checks['Backup']).toContain('read-only use is ready');
  });

  it('preserves a degraded exit result when LAN backup is unavailable', async () => {
    const result = await runConnectionChecks(profile('lan'), client({ backupError: new Error('denied') }));
    expect(result.overall).toBe('degraded');
    expect(result.checks['Backup']).toContain('/ci/startup-config.txt unavailable: denied');
  });

  it('continues after an optional diagnostic fails and reports degraded', async () => {
    const instance = client({ diagnosticError: 'show/dns-proxy' });
    const result = await runConnectionChecks(profile('lan'), instance);
    expect(result.overall).toBe('degraded');
    expect(result.checks['Running config']).toContain('available');
    expect(result.checks['DNS diagnostic']).toContain('unavailable');
    expect(instance.probedCapabilities).toHaveBeenCalled();
  });

  it('marks dependent checks skipped after authentication fails', async () => {
    const result = await runConnectionChecks(profile('lan'), client({ baseError: new AuthError('bad credentials') }));
    expect(result.overall).toBe('unhealthy');
    expect(result.checks['Authentication']).toContain('credentials rejected');
    expect(result.checks['RCI']).toContain('authentication failed');
  });
});
