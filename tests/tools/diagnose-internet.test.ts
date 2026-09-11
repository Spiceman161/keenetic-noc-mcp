import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerInternetDiagnosticTool } from '../../src/tools/diagnose-internet.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

const HEALTHY: Record<string, unknown> = {
  'show/version': {
    model: 'Keenetic Test', hw_id: 'KN-0000', title: '5.1.3',
    ndw: { components: '', features: '' }
  },
  'show/system': {
    hostname: 'router', uptime: '1000', cpuload: 2, memtotal: 524_288,
    memfree: 300_000, conntotal: 32_768, connfree: 32_000
  },
  'show/internet/status': {
    checked: 'Fri Aug  7 03:54:06 2026', enabled: true, reliable: true,
    'gateway-accessible': true, 'dns-accessible': true,
    'captive-accessible': true, internet: true,
    gateway: { interface: 'GigabitEthernet1' }
  },
  'show/interface': {
    GigabitEthernet1: {
      type: 'GigabitEthernet', link: 'up', state: 'up', connected: 'yes', global: true
    }
  },
  'show/ip/route': [{
    destination: '0.0.0.0/0', gateway: '203.0.113.1', interface: 'GigabitEthernet1',
    metric: 1000, rejecting: false, floating: false, static: false, proto: 'boot'
  }],
  'show/dns-proxy': {
    'proxy-status': { enabled: true, status: 'up', server: [{ protocol: 'DoT', status: 'up' }] }
  },
  'show/last-change': {
    date: 'Thu,  6 Aug 2026 10:46:01 GMT', user: 'admin', agent: 'http/rci',
    checksum: 'aa4bc868709b49cb803db0fd3cc43f6f',
    'fail-safe': { unsaved: false, rollback: false, 'time-left': 0 }
  }
};

function setup(options: {
  values?: Record<string, unknown>;
  failures?: Record<string, Error>;
  capabilityError?: Error;
  logs?: unknown;
  maxResponseBytes?: number;
  startup?: string;
  startupError?: Error;
  connectionMode?: 'lan' | 'remote';
} = {}) {
  const values = { ...HEALTHY, ...options.values };
  const get = vi.fn(async (path: string, _maxBytes?: number) => {
    if (path === 'show/version' && options.capabilityError) throw options.capabilityError;
    const failure = options.failures?.[path];
    if (failure) throw failure;
    return values[path];
  });
  const post = vi.fn(async (_body: unknown, _maxBytes?: number) => options.logs ?? ({
    show: { log: { log: {
      '1': { timestamp: '00:01', ident: 'Network', message: {
        level: 'info', label: 'GigabitEthernet1', message: 'link is up'
      } }
    } } }
  }));
  const getText = vi.fn(async (_path: string, _maxBytes?: number) => {
    if (options.startupError) throw options.startupError;
    return options.startup ?? '! $$$ Md5 checksum: aa4bc868709b49cb803db0fd3cc43f6f\n';
  });
  const client = {
    rci: {
      get,
      post,
      getText
    },
    // Deliberately remains successful when the fresh show/version request
    // fails: production caches this method, so it cannot be the sentinel.
    capabilities: vi.fn(async () => ({
      model: 'Cached Keenetic', hwId: 'KN-0000', firmware: 'old',
      components: new Set<string>(), features: new Set<string>()
    }))
  } as unknown as KeeneticClient;
  const ctx: ToolContext = {
    client,
    maxResponseBytes: options.maxResponseBytes ?? 25_000,
    readOnly: true,
    backup: stubBackup(),
    connection: {
      mode: options.connectionMode ?? 'lan',
      endpoint: options.connectionMode === 'remote'
        ? 'https://rci.example.test/rci/'
        : 'http://192.0.2.1/rci/'
    }
  };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, { annotations?: { readOnlyHint?: boolean }; inputSchema?: unknown }> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, config: never, handler: Handler) => {
    handlers[name] = handler;
    configs[name] = config;
    return {} as never;
  }) as never);
  registerInternetDiagnosticTool(server, ctx);
  return {
    handler: handlers['diagnose_internet']!,
    config: configs['diagnose_internet']!,
    get,
    getText,
    post
  };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

describe('diagnose_internet', () => {
  it('returns a stable healthy evidence report and uses only bounded reads', async () => {
    const { handler, config, get, getText, post } = setup();
    const out = payload(await handler({}));

    expect(out).toMatchObject({
      schemaVersion: 1,
      status: 'healthy',
      complete: true,
      untrustedRouterData: true,
      truncated: false
    });
    expect(out.checks.map((check: any) => check.id)).toEqual([
      'system', 'internet', 'wan-link', 'default-route', 'dns',
      'vpn-default-route', 'recent-logs', 'configuration-state'
    ]);
    expect(out.evidence.internet.data.checkedAt).toBe('Fri Aug 7 03:54:06 2026');
    expect(out.evidence.routes.data.items[0]).not.toHaveProperty('gateway');
    expect(out.findings).toEqual([]);
    expect(config.annotations?.readOnlyHint).toBe(true);
    for (const call of get.mock.calls) expect(call[1]).toEqual(expect.any(Number));
    expect(getText).toHaveBeenCalledWith('/ci/startup-config.txt', 256_000);
    expect(post).toHaveBeenCalledWith({ show: { log: {} } }, 256_000);
  });

  it('reads core evidence sequentially and leaves logs until last', async () => {
    const setupResult = setup({ connectionMode: 'remote' });
    const order: string[] = [];
    let active = 0;
    let maxActive = 0;
    const record = async <T>(name: string, value: T): Promise<T> => {
      order.push(name);
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise(resolve => setTimeout(resolve, 1));
      active -= 1;
      return value;
    };
    setupResult.get.mockImplementation(async (path: string) =>
      record(path, HEALTHY[path]));
    setupResult.post.mockImplementation(async () =>
      record('show/log', { show: { log: { log: {} } } }));

    await setupResult.handler({});

    expect(maxActive).toBe(1);
    expect(order).toEqual([
      'show/version',
      'show/system',
      'show/internet/status',
      'show/interface',
      'show/ip/route',
      'show/dns-proxy',
      'show/last-change',
      'show/log'
    ]);
  });

  it('stops polling after a session transport failure', async () => {
    const setupResult = setup({
      connectionMode: 'remote',
      failures: { 'show/system': new TransportError('session unavailable') }
    });

    const out = payload(await setupResult.handler({}));

    expect(setupResult.get.mock.calls.map(call => call[0])).toEqual([
      'show/version', 'show/system'
    ]);
    expect(setupResult.post).not.toHaveBeenCalled();
    expect(out.evidence.system).toMatchObject({ status: 'unavailable', reason: 'transport-error' });
    expect(out.evidence.internet).toMatchObject({ status: 'unavailable', reason: 'transport-error' });
    expect(out.evidence.logs).toMatchObject({ status: 'unavailable', reason: 'transport-error' });
  });

  it('treats authentication loss after the sentinel as a fatal MCP error', async () => {
    const setupResult = setup({
      failures: { 'show/system': new AuthError('credentials rejected') }
    });

    const result = await setupResult.handler({});

    expect(result.isError).toBe(true);
    expect(setupResult.get.mock.calls.map(call => call[0])).toEqual([
      'show/version', 'show/system'
    ]);
    expect(setupResult.post).not.toHaveBeenCalled();
  });

  it('latches a LAN startup-config transport failure before reading logs', async () => {
    const setupResult = setup({
      startupError: new TransportError('startup transport unavailable')
    });

    const out = payload(await setupResult.handler({}));

    expect(setupResult.post).not.toHaveBeenCalled();
    expect(out.evidence.internet.status).toBe('available');
    expect(out.evidence.configuration).toMatchObject({
      status: 'unavailable', reason: 'transport-error'
    });
    expect(out.evidence.logs).toMatchObject({
      status: 'unavailable', reason: 'transport-error'
    });
  });

  it('treats LAN startup-config authentication loss as fatal before logs', async () => {
    const setupResult = setup({
      startupError: new AuthError('startup credentials rejected')
    });

    const result = await setupResult.handler({});

    expect(result.isError).toBe(true);
    expect(setupResult.post).not.toHaveBeenCalled();
  });

  it('reports a physical active uplink down but ignores a down backup uplink', async () => {
    const interfaces = {
      GigabitEthernet1: { type: 'GigabitEthernet', link: 'down', state: 'up', global: true },
      GigabitEthernet2: { type: 'GigabitEthernet', link: 'down', state: 'up', global: true }
    };
    const route = [{ destination: '0.0.0.0/0', interface: 'GigabitEthernet1', rejecting: false }];
    const out = payload(await setup({ values: {
      'show/interface': interfaces,
      'show/ip/route': route,
      'show/internet/status': { internet: false, 'gateway-accessible': false, 'dns-accessible': false }
    } }).handler({}));
    expect(out.status).toBe('unhealthy');
    expect(out.findings.map((finding: any) => finding.id)).toContain('physical-uplink-down');

    const backupOnly = payload(await setup({ values: {
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'up', state: 'up', global: true },
        GigabitEthernet2: { type: 'GigabitEthernet', link: 'down', state: 'up', global: true }
      }
    } }).handler({}));
    expect(backupOnly.findings.map((finding: any) => finding.id)).not.toContain('physical-uplink-down');
  });

  it('recognizes the older role=inet WAN shape', async () => {
    const out = payload(await setup({ values: { 'show/interface': {
      GigabitEthernet1: {
        type: 'GigabitEthernet', role: 'inet', link: 'up', state: 'up', connected: 'yes'
      }
    } } }).handler({}));
    expect(out.checks.find((check: any) => check.id === 'wan-link').status).toBe('pass');
    expect(out.evidence.interfaces.data.items[0].internetRole).toBe(true);
  });

  it('diagnoses missing route and a DNS reachability failure', async () => {
    const missing = payload(await setup({ values: {
      'show/ip/route': [],
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: false,
        'gateway-accessible': false, 'dns-accessible': false
      }
    } }).handler({}));
    expect(missing.findings.map((finding: any) => finding.id)).toContain('missing-default-route');

    const dns = payload(await setup({ values: { 'show/internet/status': {
      checked: true, enabled: true, reliable: true, internet: false,
      'gateway-accessible': true, 'dns-accessible': false
    } } }).handler({}));
    expect(dns.findings.map((finding: any) => finding.id)).toContain('dns-unreachable');
  });

  it('does not diagnose a down higher-metric backup route as the active outage', async () => {
    const routes = [
      { destination: '0.0.0.0/0', interface: 'GigabitEthernet1', metric: 10, rejecting: false },
      { destination: '0.0.0.0/0', interface: 'Wireguard3', metric: 100, rejecting: false }
    ];
    const out = payload(await setup({ values: {
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'up', state: 'up', global: true },
        Wireguard3: { type: 'Wireguard', link: 'down', state: 'down', global: true }
      },
      'show/ip/route': routes
    } }).handler({}));
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('vpn-default-route-down');
    expect(out.status).toBe('healthy');
  });

  it('ignores a stale gateway pointer to a down backup VPN', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: false, enabled: false, reliable: true, internet: false,
        'gateway-accessible': false, 'dns-accessible': false,
        gateway: { interface: 'Wireguard3' }
      },
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'up', state: 'up', global: true },
        Wireguard3: { type: 'Wireguard', link: 'down', state: 'down', global: true }
      },
      'show/ip/route': [
        { destination: '0.0.0.0/0', interface: 'GigabitEthernet1', metric: 10, rejecting: false },
        { destination: '0.0.0.0/0', interface: 'Wireguard3', metric: 100, rejecting: false }
      ]
    } }).handler({}));
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('vpn-default-route-down');
    expect(out.status).toBe('degraded');
  });

  it('marks an ambiguous ECMP or failover route set without blaming a backup', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: true,
        'gateway-accessible': true, 'dns-accessible': true
      },
      'show/ip/route': [
        { destination: '0.0.0.0/0', interface: 'GigabitEthernet1', metric: 10, rejecting: false },
        { destination: '0.0.0.0/0', interface: 'GigabitEthernet2', metric: 10, rejecting: false }
      ],
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'up', state: 'up', global: true },
        GigabitEthernet2: { type: 'GigabitEthernet', link: 'down', state: 'down', global: true }
      }
    } }).handler({}));
    expect(out.status).toBe('degraded');
    expect(out.findings.map((finding: any) => finding.id)).toContain('ambiguous-default-route');
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('physical-uplink-down');
  });

  it('does not substitute another route when gateway.interface has no match', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: true,
        'gateway-accessible': true, 'dns-accessible': true,
        gateway: { interface: 'MissingInterface' }
      },
      'show/ip/route': [
        { destination: '0.0.0.0/0', interface: 'GigabitEthernet1', metric: 10, rejecting: false },
        { destination: '0.0.0.0/0', interface: 'GigabitEthernet2', metric: 20, rejecting: false }
      ]
    } }).handler({}));
    expect(out.status).toBe('degraded');
    expect(out.findings.map((finding: any) => finding.id)).toContain('ambiguous-default-route');
    expect(out.findings.find((finding: any) => finding.id === 'ambiguous-default-route').summary)
      .toMatch(/conflicting or ambiguous/i);
  });

  it('treats a single route that contradicts gateway.interface as ambiguous', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: true,
        'gateway-accessible': true, 'dns-accessible': true,
        gateway: { interface: 'MissingInterface' }
      }
    } }).handler({}));
    expect(out.status).toBe('degraded');
    expect(out.findings.map((finding: any) => finding.id)).toContain('ambiguous-default-route');
    expect(out.findings.find((finding: any) => finding.id === 'ambiguous-default-route').summary)
      .toMatch(/conflicting or ambiguous/i);
  });

  it('does not turn stale or contradictory internet flags into critical findings', async () => {
    const stale = payload(await setup({ values: {
      'show/internet/status': {
        checked: false, enabled: false, reliable: true, internet: false,
        'gateway-accessible': false, 'dns-accessible': false
      },
      'show/ip/route': [],
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'down', state: 'down', global: true }
      }
    } }).handler({}));
    expect(stale.status).toBe('degraded');
    expect(stale.findings.some((finding: any) => finding.severity === 'critical')).toBe(false);
    expect(stale.checks.find((check: any) => check.id === 'dns').status).not.toBe('fail');

    const conflict = payload(await setup({ values: { 'show/internet/status': {
      checked: true, enabled: true, reliable: true, internet: true,
      'gateway-accessible': false, 'dns-accessible': true
    } } }).handler({}));
    expect(conflict.status).toBe('degraded');
    expect(conflict.findings.map((finding: any) => finding.id)).toContain('conflicting-internet-evidence');
    expect(conflict.findings.some((finding: any) => finding.severity === 'critical')).toBe(false);

    const ipv6Possible = payload(await setup({ values: { 'show/ip/route': [] } }).handler({}));
    expect(ipv6Possible.status).toBe('degraded');
    expect(ipv6Possible.findings.find((finding: any) => finding.id === 'missing-default-route').severity)
      .toBe('warning');
  });

  it('describes an up VPN with explicitly offline peers accurately', async () => {
    const out = payload(await setup({ values: {
      'show/interface': {
        GigabitEthernet1: { type: 'GigabitEthernet', link: 'up', state: 'up', global: true },
        Wireguard3: {
          type: 'Wireguard', link: 'up', state: 'up', global: true, defaultgw: true,
          wireguard: { peer: [{ online: false, via: 'GigabitEthernet1' }] }
        }
      },
      'show/ip/route': [
        { destination: '0.0.0.0/0', interface: 'Wireguard3', metric: 10, rejecting: false }
      ],
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: false,
        'gateway-accessible': true, 'dns-accessible': true,
        gateway: { interface: 'Wireguard3' }
      }
    } }).handler({}));
    const finding = out.findings.find((item: any) => item.id === 'vpn-default-route-down');
    expect(finding.summary).toMatch(/peers are offline/i);
    expect(finding.summary).not.toMatch(/interface is explicitly down/i);
  });

  it('recognizes a healthy or failed VPN default route without exposing peer material', async () => {
    const base = {
      type: 'Wireguard', link: 'up', state: 'up', global: true, defaultgw: true,
      wireguard: { 'private-key': 'never-show-this', peer: [{ online: true, via: 'GigabitEthernet1' }] }
    };
    const route = [{ destination: '0.0.0.0/0', interface: 'Wireguard3', rejecting: false }];
    const healthy = payload(await setup({ values: {
      'show/interface': { GigabitEthernet1: HEALTHY['show/interface'] as object, Wireguard3: base },
      'show/ip/route': route,
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: true,
        'gateway-accessible': true, 'dns-accessible': true,
        gateway: { interface: 'Wireguard3' }
      }
    } }).handler({}));
    expect(healthy.findings.map((finding: any) => finding.id)).toContain('vpn-default-route-active');
    expect(JSON.stringify(healthy)).not.toContain('never-show-this');

    const failed = payload(await setup({ values: {
      'show/interface': { Wireguard3: { ...base, link: 'down', state: 'down' } },
      'show/ip/route': route,
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: false,
        'gateway-accessible': false, 'dns-accessible': false,
        gateway: { interface: 'Wireguard3' }
      }
    } }).handler({}));
    expect(failed.findings.map((finding: any) => finding.id)).toContain('vpn-default-route-down');
  });

  it('preserves partial evidence and treats absent booleans as unknown', async () => {
    const result = await setup({
      values: { 'show/internet/status': { checked: 'unknown-shape' } },
      failures: { 'show/dns-proxy': new RciError('raw password=bad', {
        path: 'show/dns-proxy', code: '500', ident: 'http'
      }) }
    }).handler({});
    expect(result.isError).not.toBe(true);
    const out = payload(result);
    expect(out.complete).toBe(false);
    expect(out.evidence.dns).toMatchObject({ status: 'unavailable', reason: 'rci-error', data: null });
    expect(out.evidence.internet.data.internet).toBeNull();
    expect(JSON.stringify(out)).not.toContain('password=bad');
  });

  it('does not turn unknown DNS or VPN fields into healthy evidence', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': { internet: true, 'gateway-accessible': true },
      'show/dns-proxy': {},
      'show/interface': {
        Wireguard3: { type: 'Wireguard', global: true, defaultgw: true }
      },
      'show/ip/route': [{ destination: '0.0.0.0/0', interface: 'Wireguard3', rejecting: false }]
    } }).handler({}));
    expect(out.checks.find((check: any) => check.id === 'dns').status).toBe('unknown');
    expect(out.checks.find((check: any) => check.id === 'vpn-default-route').status).toBe('unknown');
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('vpn-default-route-active');
  });

  it('does not treat an enabled-only DNS proxy as healthy', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: true, enabled: true, reliable: true, internet: true,
        'gateway-accessible': true
      },
      'show/dns-proxy': { 'proxy-status': { enabled: true } }
    } }).handler({}));
    expect(out.checks.find((check: any) => check.id === 'dns').status).toBe('unknown');
  });

  it('does not trust a positive DNS flag from a disabled internet monitor', async () => {
    const out = payload(await setup({ values: {
      'show/internet/status': {
        checked: false, enabled: false, reliable: true, internet: false,
        'gateway-accessible': false, 'dns-accessible': true
      },
      'show/dns-proxy': { 'proxy-status': { enabled: true } }
    } }).handler({}));
    expect(out.checks.find((check: any) => check.id === 'dns').status).toBe('unknown');
  });

  it('classifies malformed route rows as unavailable rather than a missing route', async () => {
    const out = payload(await setup({ values: {
      'show/ip/route': ['not-a-route']
    } }).handler({}));
    expect(out.evidence.routes).toMatchObject({
      status: 'unavailable', reason: 'unexpected-response', data: null
    });
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('missing-default-route');
  });

  it.each([
    [{}],
    [{ destination: 42 }],
    [{ destination: '0.0.0.0/0', interface: '' }]
  ])('rejects a semantically malformed route array', async routes => {
    const out = payload(await setup({ values: { 'show/ip/route': routes } }).handler({}));
    expect(out.evidence.routes.reason).toBe('unexpected-response');
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('missing-default-route');
  });

  it.each([
    new AuthError('password=bad'),
    new TransportError('router unreachable')
  ])('returns an MCP error when the baseline router check fails', async error => {
    const result = await setup({ capabilityError: error }).handler({});
    expect(result.isError).toBe(true);
  });

  it('keeps a baseline RCI failure partial and does not expose its body', async () => {
    const result = await setup({ capabilityError: new RciError('private response raw-private-data', {
      path: 'show/version', code: '500', ident: 'http'
    }) }).handler({});
    expect(result.isError).not.toBe(true);
    const out = payload(result);
    expect(out.status).toBe('degraded');
    expect(out.complete).toBe(false);
    expect(out.evidence.system.data.versionAvailable).toBe(false);
    expect(result.content.map(part => part.text).join('')).not.toContain('raw-private-data');
  });

  it('uses embedded interface ids and excludes unrelated LAN logs', async () => {
    const logs = { show: { log: { log: {
      '1': { timestamp: '00:01', ident: 'Hotspot', message: {
        label: 'Bridge0', message: 'client joined'
      } },
      '2': { timestamp: '00:02', ident: 'dns-proxy', message: { message: 'upstream ready' } }
    } } } };
    const out = payload(await setup({ values: { 'show/interface': {
      '0': { id: 'GigabitEthernet1', type: 'GigabitEthernet', link: 'up', global: true },
      '1': { id: 'Bridge0', type: 'Bridge', link: 'up' }
    } }, logs }).handler({}));
    expect(out.evidence.interfaces.data.items.map((item: any) => item.id))
      .toEqual(['Bridge0', 'GigabitEthernet1']);
    expect(out.evidence.logs.data.items).toHaveLength(1);
    expect(out.evidence.logs.data.items[0].ident).toBe('dns-proxy');
  });

  it('reports unsaved configuration only as informational context', async () => {
    const out = payload(await setup({ startup:
      '! $$$ Md5 checksum: 0f9e8d7c6b5a49382716f5e4d3c2b1a0\n'
    }).handler({}));
    expect(out.findings).toContainEqual(expect.objectContaining({
      id: 'unsaved-configuration', severity: 'info'
    }));
    expect(out.findings.find((finding: any) => finding.id === 'unsaved-configuration').summary)
      .toMatch(/context/i);
  });

  it('keeps an unavailable saved checksum unknown and the report incomplete', async () => {
    const out = payload(await setup({ startupError: new RciError('HTTP 403', {
      path: '/ci/startup-config.txt', code: '403', ident: 'http'
    }) }).handler({}));
    expect(out.status).toBe('healthy');
    expect(out.complete).toBe(false);
    expect(out.evidence.configuration.data.unsavedChanges).toBeNull();
    expect(out.checks.find((check: any) => check.id === 'configuration-state').status).toBe('unknown');
  });

  it('does not request the LAN-only startup file for a remote diagnosis', async () => {
    const setupResult = setup({ connectionMode: 'remote' });
    const out = payload(await setupResult.handler({}));
    expect(setupResult.getText).not.toHaveBeenCalled();
    expect(out.evidence.configuration.data.unsavedChanges).toBeNull();
    expect(out.complete).toBe(false);
  });

  it('redacts a complete naked key before truncating an untrusted log line', async () => {
    const key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst';
    const logs = { show: { log: { log: {
      '1': { ident: 'dns-proxy', message: { message: `${'.'.repeat(476)}${key}` } }
    } } } };
    const out = payload(await setup({ logs }).handler({}));
    const text = JSON.stringify(out.evidence.logs.data.items);
    expect(text).toContain('[REDACTED_KEY]');
    expect(text).not.toContain(key.slice(0, 12));
  });

  it('projects malformed fail-safe time without losing checks and findings', async () => {
    const out = payload(await setup({ values: {
      'show/last-change': {
        checksum: 'aa4bc868709b49cb803db0fd3cc43f6f',
        'fail-safe': { 'time-left': 'x'.repeat(60_000) }
      }
    } }).handler({}));
    expect(out.schemaVersion).toBe(1);
    expect(out.checks).toHaveLength(8);
    expect(out.evidence.configuration.data.failSafe.secondsLeft).toBeNull();
  });

  it('bounds untrusted logs and keeps the final output under the configured ceiling', async () => {
    const rows: Record<string, unknown> = {};
    for (let i = 0; i < 80; i += 1) {
      rows[String(i)] = {
        timestamp: `00:${String(i % 60).padStart(2, '0')}`,
        ident: 'dns-proxy',
        message: { message: `token=secret-${i} ${'x'.repeat(800)}` }
      };
    }
    const logs = { show: { log: { log: rows } } };
    const result = await setup({ logs, maxResponseBytes: 8_000 }).handler({});
    const text = result.content.map(part => part.text).join('');
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(8_000);
    const out = JSON.parse(text);
    expect(out.truncated).toBe(true);
    expect(out.evidence.logs.data.untrusted).toBe(true);
    expect(out.evidence.logs.data.shown).toBeLessThanOrEqual(20);
    expect(text).not.toContain('secret-');
  });
});
