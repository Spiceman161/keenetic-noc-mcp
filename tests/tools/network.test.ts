import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { registerNetworkTools } from '../../src/tools/network.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

const DATA: Record<string, unknown> = {
  'show/internet/status': {
    checked: true,
    enabled: true,
    reliable: true,
    'gateway-accessible': true,
    'dns-accessible': true,
    internet: true
  },
  'show/ip/route': [
    {
      destination: '0.0.0.0/0',
      gateway: '203.0.113.1',
      interface: 'GigabitEthernet1',
      metric: 0,
      flags: 'UG'
    },
    { destination: '192.0.2.0/24', gateway: '0.0.0.0', interface: 'Bridge0', metric: 0, flags: 'U' }
  ],
  'ip/policy': {
    Policy0: { description: 'desc-1', permit: [{ enabled: true, interface: 'Wireguard3' }] }
  },
  'show/interface': {
    WifiMaster0: { type: 'WifiMaster', description: '2.4 GHz', band: '2.4', link: 'up' },
    'WifiMaster0/AccessPoint0': { type: 'AccessPoint', ssid: 'ssid-1', link: 'up', state: 'up' },
    WifiMaster1: { type: 'WifiMaster', description: '5 GHz', band: '5', link: 'up' },
    'WifiMaster1/AccessPoint0': { type: 'AccessPoint', ssid: 'ssid-2', link: 'up', state: 'up' }
  },
  'show/associations': {
    station: [{ mac: '02:00:00:00:00:01', ap: 'WifiMaster0/AccessPoint0', rssi: -36, txrate: 65 }]
  }
};

function harness(options: { internetStatus?: unknown; maxResponseBytes?: number } = {}) {
  const get = vi.fn(async (path: string) => {
    if (!(path in DATA)) throw new Error(`this path does not exist on this firmware: ${path}`);
    return path === 'show/internet/status' && options.internetStatus !== undefined
      ? options.internetStatus
      : DATA[path];
  });
  const client = {
    rci: { get, post: vi.fn(), getText: vi.fn() },
    capabilities: vi.fn()
  } as unknown as KeeneticClient;

  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, { annotations?: { readOnlyHint?: boolean } }> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((
    name: string,
    config: { annotations?: { readOnlyHint?: boolean } },
    handler: Handler
  ) => {
    handlers[name] = handler;
    configs[name] = config;
    return {} as never;
  }) as never);

  registerNetworkTools(server, {
    client, maxResponseBytes: options.maxResponseBytes ?? 25_000, readOnly: false, backup: stubBackup()
  });
  return { handlers, configs, get };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(p => p.text).join(''));
}

describe('get_internet_status', () => {
  it('reports reachability flags', async () => {
    const { handlers } = harness();
    const out = payload(await handlers['get_internet_status']!({}));
    expect(out.internet).toBe(true);
    expect(out.gatewayAccessible).toBe(true);
    expect(out.dnsAccessible).toBe(true);
  });

  it('projects healthy current Ping Check evidence without changing legacy scalars', async () => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: true,
      'gateway-accessible': true, 'dns-accessible': true,
      gateway: { excluded: false, failures: 2 }
    } });
    const out = payload(await handlers['get_internet_status']!({}));

    expect(out.pingCheck).toEqual({
      configured: true, verdict: 'pass', verdictReason: 'check-passed',
      gatewayExcluded: false, gatewayFailures: 2, transitionReason: 'unknown'
    });
    expect(out).toMatchObject({ internet: true, checked: true, enabled: true, reliable: true });
  });

  it('distinguishes an explicit disabled check from stale negative fields', async () => {
    const { handlers } = harness({ internetStatus: {
      checked: false, enabled: false, reliable: true, internet: false,
      'gateway-accessible': false, 'dns-accessible': false,
      gateway: { excluded: true, failures: 3 }
    } });
    const out = payload(await handlers['get_internet_status']!({}));
    expect(out.pingCheck).toMatchObject({
      configured: false, verdict: 'no-active-check', verdictReason: 'no-active-check',
      transitionReason: 'not-applicable'
    });
  });

  it.each([
    [{ 'gateway-accessible': false }, 'gateway-unreachable'],
    [{ 'gateway-accessible': true, 'dns-accessible': false }, 'dns-unreachable'],
    [{ 'gateway-accessible': true, 'dns-accessible': true, 'captive-accessible': false }, 'captive-unreachable'],
    [{ 'gateway-accessible': true, 'dns-accessible': true, 'captive-accessible': true }, 'internet-check-failed']
  ])('uses only the fixed failure reason priority for %o', async (subchecks, verdictReason) => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: false, ...subchecks
    } });
    const out = payload(await handlers['get_internet_status']!({}));
    expect(out.pingCheck).toMatchObject({ verdict: 'fail', verdictReason, transitionReason: 'unknown' });
  });

  it('keeps malformed, incomplete, and contradictory source fields unknown and private', async () => {
    const secret = 'private-key-sentinel';
    const cases: unknown[] = [
      [],
      'unexpected-status-shape',
      { checked: false, enabled: true, reliable: true, internet: false },
      { checked: true, enabled: true, reliable: false, internet: true },
      { checked: true, enabled: true, reliable: true, internet: true, 'gateway-accessible': false },
      {
        checked: true, enabled: [], reliable: {}, internet: 'yes',
        gateway: { excluded: 'no', failures: -1, secret, interface: secret }
      },
      {
        checked: true, enabled: true, reliable: true, internet: 'yes',
        gateway: { excluded: [], failures: Number.MAX_SAFE_INTEGER + 1 }
      }
    ];
    for (const internetStatus of cases) {
      const { handlers } = harness({ internetStatus });
      const out = payload(await handlers['get_internet_status']!({}));
      expect(out.pingCheck).toMatchObject({ verdict: 'unknown' });
      expect(JSON.stringify(out.pingCheck)).not.toContain(secret);
    }
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: true,
      gateway: { excluded: 'no', failures: Number.MAX_SAFE_INTEGER + 1 }
    } });
    const out = payload(await handlers['get_internet_status']!({}));
    expect(out.pingCheck).toEqual({
      configured: true, verdict: 'pass', verdictReason: 'check-passed',
      gatewayExcluded: null, gatewayFailures: null, transitionReason: 'unknown'
    });
  });

  it('uses one existing read, retains read-only annotation, and honors the response bound', async () => {
    const { handlers, configs, get } = harness({ maxResponseBytes: 500 });
    const result = await handlers['get_internet_status']!({});
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('show/internet/status');
    expect(configs['get_internet_status']?.annotations?.readOnlyHint).toBe(true);
    expect(Buffer.byteLength(result.content.map(part => part.text).join(''))).toBeLessThanOrEqual(500);
  });
});

describe('list_routes', () => {
  it('returns every route with totals', async () => {
    const out = payload(await harness().handlers['list_routes']!({}));
    expect(out.routes).toHaveLength(2);
    expect(out.total).toBe(2);
  });

  it('filters to the default route when kind is default', async () => {
    const out = payload(await harness().handlers['list_routes']!({ kind: 'default' }));
    expect(out.routes.map((r: any) => r.destination)).toEqual(['0.0.0.0/0']);
  });
});

describe('list_policies', () => {
  it('returns each policy with its name and description', async () => {
    const out = payload(await harness().handlers['list_policies']!({}));
    expect(out.policies).toEqual([
      { name: 'Policy0', description: 'desc-1', interfaces: ['Wireguard3'] }
    ]);
  });
});

describe('get_wifi_status', () => {
  it('groups access points by band and counts clients', async () => {
    const out = payload(await harness().handlers['get_wifi_status']!({}));
    const twoFour = out.bands.find((b: any) => b.band === '2.4');
    expect(twoFour.accessPoints[0].ssid).toBe('ssid-1');
    expect(twoFour.accessPoints[0].clients).toBe(1);
    const five = out.bands.find((b: any) => b.band === '5');
    expect(five.accessPoints[0].clients).toBe(0);
  });
});
