import { describe, expect, it, vi } from 'vitest';
import { runConnectionChecks } from '../../src/cli/router.js';
import { AuthError, RemoteCapabilityError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import type { RouterProfile } from '../../src/profiles/registry.js';

const profile = (mode: 'lan' | 'remote'): RouterProfile => ({
  id: 'test', name: 'Test', mode,
  endpoint: mode === 'remote' ? 'https://rci.example.test/rci/' : '192.0.2.1',
  login: 'agent', secretRef: 'file:test', readOnly: true
});

function client(options: { baseError?: Error; configError?: Error; dnsError?: Error; startupError?: Error } = {}): KeeneticClient {
  return {
    capabilities: vi.fn(async () => {
      if (options.baseError) throw options.baseError;
      return { model: 'Keenetic Test', hwId: 'KN-0000', firmware: '5.1.3', components: new Set(), features: new Set() };
    }),
    rci: {
      get: vi.fn(async (path: string) => {
        if (path === 'show/last-change' && options.configError) throw options.configError;
        if (path === 'show/dns-proxy' && options.dnsError) throw options.dnsError;
        return {};
      }),
      getText: vi.fn(async () => {
        if (options.startupError) throw options.startupError;
        return '! sanitized config';
      })
    }
  } as unknown as KeeneticClient;
}

describe('router test checks', () => {
  it('runs independent config, DNS and startup-config reads', async () => {
    const instance = client();
    const result = await runConnectionChecks(profile('lan'), instance);
    expect(result.overall).toBe('healthy');
    expect(instance.rci.get).toHaveBeenCalledWith('show/last-change');
    expect(instance.rci.get).toHaveBeenCalledWith('show/dns-proxy');
    expect(instance.rci.getText).toHaveBeenCalledWith('/ci/startup-config.txt');
  });

  it('treats the known remote /ci denial as a healthy capability limitation', async () => {
    const result = await runConnectionChecks(profile('remote'), client({
      startupError: new RemoteCapabilityError('remote denied /ci/')
    }));
    expect(result.overall).toBe('healthy');
    expect(result.checks['Startup config']).toContain('unsupported remotely');
    expect(result.checks['Backup']).toContain('LAN profile');
  });

  it('continues after an individual read fails and reports degraded', async () => {
    const instance = client({ dnsError: new Error('DNS unavailable') });
    const result = await runConnectionChecks(profile('lan'), instance);
    expect(result.overall).toBe('degraded');
    expect(result.checks['Config read']).toBe('✓');
    expect(result.checks['DNS']).toContain('failed');
    expect(instance.rci.getText).toHaveBeenCalled();
  });

  it('marks dependent checks skipped after authentication fails', async () => {
    const result = await runConnectionChecks(profile('remote'), client({ baseError: new AuthError('bad credentials') }));
    expect(result.overall).toBe('unhealthy');
    expect(result.checks['Authentication']).toContain('failed');
    expect(result.checks['DNS']).toContain('skipped');
  });
});
