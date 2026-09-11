import { describe, expect, it, vi } from 'vitest';
import { isWizardAction, runConnectionChecks, runRouterRegistration, runRouterRemoval, runRouterSnapshot, type RouterRegistrationDependencies, type Terminal } from '../../src/cli/router.js';
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

function registrationHarness(answer = 'y', options: {
  runCode?: number;
  runError?: Error;
  saveError?: Error;
  launchError?: Error;
} = {}) {
  const outputs: string[] = [];
  const ui: Terminal = {
    ask: vi.fn(async () => answer),
    close: vi.fn(),
    out: line => { outputs.push(line); }
  };
  const deps: Partial<RouterRegistrationDependencies> = {
    getProfile: vi.fn(async () => profile('remote')),
    serverLaunch: vi.fn(() => {
      if (options.launchError) throw options.launchError;
      return { command: '/usr/bin/node', args: ['/opt/keenetic noc/dist/index.js'] };
    }),
    runRegistration: vi.fn(async () => {
      if (options.runError) throw options.runError;
      return options.runCode ?? 0;
    }),
    saveRegistration: vi.fn(async () => {
      if (options.saveError) throw options.saveError;
    })
  };
  return { ui, deps, outputs };
}

describe('standalone router registration', () => {
  it('passes an absolute launch argv with spaces as one argument and saves metadata', async () => {
    const { ui, deps, outputs } = registrationHarness();
    await expect(runRouterRegistration('/profiles', 'test', 'codex', ui, deps)).resolves.toBe(0);
    expect(deps.runRegistration).toHaveBeenCalledWith({
      command: 'codex',
      args: ['mcp', 'add', 'keenetic_test', '--', '/usr/bin/node',
        '/opt/keenetic noc/dist/index.js', '--router', 'test', '--read-only']
    });
    expect(deps.saveRegistration).toHaveBeenCalledWith('/profiles', 'test', 'codex',
      'keenetic_test');
    expect(outputs.join('\n')).not.toContain('keenetic-noc-mcp --router');
  });

  it('cancels without invoking the client or changing metadata', async () => {
    const { ui, deps } = registrationHarness('n');
    await expect(runRouterRegistration('/profiles', 'test', 'codex', ui, deps)).resolves.toBe(1);
    expect(deps.runRegistration).not.toHaveBeenCalled();
    expect(deps.saveRegistration).not.toHaveBeenCalled();
  });

  it.each([
    ['launch resolution', { launchError: new Error('missing') }],
    ['spawn error', { runError: new Error('missing client') }],
    ['client exit', { runCode: 1 }]
  ] as const)('keeps the profile metadata unchanged after %s failure', async (_name, options) => {
    const { ui, deps } = registrationHarness('y', options);
    await expect(runRouterRegistration('/profiles', 'test', 'codex', ui, deps)).resolves.toBe(1);
    expect(deps.saveRegistration).not.toHaveBeenCalled();
  });

  it('reports metadata failure after the external registration succeeds', async () => {
    const { ui, deps, outputs } = registrationHarness('y',
      { saveError: new Error('registry unavailable') });
    await expect(runRouterRegistration('/profiles', 'test', 'claude', ui, deps)).resolves.toBe(1);
    expect(deps.runRegistration).toHaveBeenCalledOnce();
    expect(outputs.at(-1)).toContain('metadata could not be updated');
  });
});

describe('explicit router snapshot', () => {
  it('stores a partial snapshot and prints only aggregate metadata', async () => {
    const unavailable = { status: 'unavailable' as const, reason: 'not-supported' as const, data: null };
    const snapshot = { schemaVersion: 1 as const, at: '2026-09-11T10:00:00.000Z', complete: false,
      sources: { system: unavailable, configuration: unavailable, interfaces: unavailable,
        routes: unavailable, dns: unavailable, vpn: unavailable, wifi: unavailable, devices: unavailable } };
    const output: string[] = [];
    const deps = {
      getProfile: vi.fn(async () => profile('remote')),
      readPassword: vi.fn(async () => 'not-printed'),
      createClient: vi.fn(() => client()),
      collect: vi.fn(async () => snapshot),
      write: vi.fn(async () => ({ path: '/private/path.json', bytes: 900, pruned: 2 }))
    };
    await expect(runRouterSnapshot('/profiles', 'test', line => output.push(line), deps)).resolves.toBe(0);
    expect(deps.write).toHaveBeenCalledWith('/profiles', 'test', snapshot);
    expect(output.join('\n')).toContain('partial');
    expect(output.join('\n')).toContain('900 bytes');
    expect(output.join('\n')).not.toMatch(/not-printed|private\/path/);
  });

  it('does not collect when the profile secret is unavailable', async () => {
    const collect = vi.fn();
    await expect(runRouterSnapshot('/profiles', 'test', undefined, {
      getProfile: vi.fn(async () => profile('lan')),
      readPassword: vi.fn(async () => null),
      collect
    })).rejects.toThrow('Profile password is unavailable');
    expect(collect).not.toHaveBeenCalled();
  });
});

describe('router removal snapshot lifecycle', () => {
  it('removes snapshots after the confirmed profile removal', async () => {
    const calls: string[] = [];
    const ui: Terminal = { ask: vi.fn(async () => 'y'), close: vi.fn(), out: vi.fn() };
    await expect(runRouterRemoval('/profiles', 'test', ui, {
      getProfile: vi.fn(async () => profile('lan')),
      removeProfile: vi.fn(async () => { calls.push('profile'); return profile('lan'); }),
      removeSecret: vi.fn(async () => { calls.push('secret'); }),
      removeState: vi.fn(async () => { calls.push('state'); }),
      removeSnapshots: vi.fn(async (_id, finalize) => { calls.push('snapshots'); await finalize(); })
    })).resolves.toBe(0);
    expect(calls).toEqual(['secret', 'state', 'snapshots', 'profile']);
    expect(ui.out).toHaveBeenCalledWith(expect.stringContaining('local snapshots'));
  });

  it('keeps the profile retryable when snapshot cleanup fails', async () => {
    const removeProfileCall = vi.fn();
    const ui: Terminal = { ask: vi.fn(async () => 'y'), close: vi.fn(), out: vi.fn() };
    await expect(runRouterRemoval('/profiles', 'test', ui, {
      getProfile: vi.fn(async () => profile('lan')),
      removeProfile: removeProfileCall,
      removeSecret: vi.fn(async () => undefined),
      removeState: vi.fn(async () => undefined),
      removeSnapshots: vi.fn(async () => { throw new Error('disk busy'); })
    })).rejects.toThrow('disk busy');
    expect(removeProfileCall).not.toHaveBeenCalled();
  });

  it('does not remove anything when confirmation is declined', async () => {
    const removeProfileCall = vi.fn();
    const ui: Terminal = { ask: vi.fn(async () => 'n'), close: vi.fn(), out: vi.fn() };
    await expect(runRouterRemoval('/profiles', 'test', ui, {
      getProfile: vi.fn(async () => profile('lan')),
      removeProfile: removeProfileCall
    })).resolves.toBe(1);
    expect(removeProfileCall).not.toHaveBeenCalled();
  });
});
