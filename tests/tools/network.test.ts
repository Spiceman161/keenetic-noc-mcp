import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { registerNetworkTools } from '../../src/tools/network.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
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

function harness(options: {
  internetStatus?: unknown;
  internetError?: Error;
  maxResponseBytes?: number;
} = {}) {
  const get = vi.fn(async (path: string) => {
    if (!(path in DATA)) throw new Error(`this path does not exist on this firmware: ${path}`);
    if (path === 'show/internet/status' && options.internetError) throw options.internetError;
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

const PING_CHECK_KEYS = [
  'configured', 'verdict', 'verdictReason', 'gatewayExcluded', 'gatewayFailures', 'transitionReason'
];

function pingCheck(output: any): any {
  expect(Object.keys(output.pingCheck)).toEqual(PING_CHECK_KEYS);
  return output.pingCheck;
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

    expect(pingCheck(out)).toEqual({
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
    expect(pingCheck(out)).toMatchObject({
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
    expect(pingCheck(out)).toMatchObject({ verdict: 'fail', verdictReason, transitionReason: 'unknown' });
  });

  it.each([
    { 'gateway-accessible': false },
    { 'dns-accessible': false },
    { 'captive-accessible': false },
    { 'gateway-accessible': false, 'dns-accessible': false },
    { 'gateway-accessible': false, 'captive-accessible': false },
    { 'dns-accessible': false, 'captive-accessible': false },
    { 'gateway-accessible': false, 'dns-accessible': false, 'captive-accessible': false }
  ])('classifies every positive-aggregate subcheck contradiction as unknown: %o', async subchecks => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: true, ...subchecks
    } });
    expect(pingCheck(payload(await handlers['get_internet_status']!({})))).toMatchObject({
      verdict: 'unknown', verdictReason: 'conflicting-status', transitionReason: 'unknown'
    });
  });

  it('gives explicit disabled state precedence over every stale negative contradiction', async () => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: false, reliable: true, internet: true,
      'gateway-accessible': false, 'dns-accessible': false, 'captive-accessible': false
    } });
    expect(pingCheck(payload(await handlers['get_internet_status']!({})))).toMatchObject({
      configured: false,
      verdict: 'no-active-check',
      verdictReason: 'no-active-check',
      transitionReason: 'not-applicable'
    });
  });

  it.each([
    ['checked false', { checked: false, enabled: true, reliable: true, internet: true }, true],
    ['checked empty', { checked: '', enabled: true, reliable: true, internet: true }, true],
    ['checked malformed', { checked: [], enabled: true, reliable: true, internet: true }, true],
    ['reliable false', { checked: true, enabled: true, reliable: false, internet: true }, true],
    ['reliable missing', { checked: true, enabled: true, internet: true }, true],
    ['reliable malformed', { checked: true, enabled: true, reliable: {}, internet: true }, true],
    ['enabled missing', { checked: true, reliable: true, internet: true }, null],
    ['enabled malformed', { checked: true, enabled: [], reliable: true, internet: true }, null]
  ])('fails closed for non-current or malformed gate evidence: %s', async (_label, internetStatus, configured) => {
    const { handlers } = harness({ internetStatus });
    expect(pingCheck(payload(await handlers['get_internet_status']!({})))).toMatchObject({
      configured, verdict: 'unknown', verdictReason: 'unknown', transitionReason: 'unknown'
    });
  });

  it.each([null, 'true', [], {}, 1])('does not turn malformed enabled=%o into pass or fail', async enabled => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled, reliable: true, internet: true
    } });
    expect(pingCheck(payload(await handlers['get_internet_status']!({})))).toMatchObject({
      configured: null, verdict: 'unknown', verdictReason: 'unknown', transitionReason: 'unknown'
    });
  });

  it.each([null, 'true', [], {}, 1])('does not turn malformed reliable=%o into pass or fail', async reliable => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable, internet: true
    } });
    expect(pingCheck(payload(await handlers['get_internet_status']!({})))).toMatchObject({
      configured: true, verdict: 'unknown', verdictReason: 'unknown', transitionReason: 'unknown'
    });
  });

  it('keeps malformed source fields unknown and private', async () => {
    const secret = 'private-key-sentinel';
    const cases: unknown[] = [
      [],
      'unexpected-status-shape',
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
      expect(pingCheck(out)).toMatchObject({ verdict: 'unknown' });
      expect(JSON.stringify(out)).not.toContain(secret);
    }
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: true,
      gateway: { excluded: 'no', failures: Number.MAX_SAFE_INTEGER + 1 }
    } });
    const out = payload(await handlers['get_internet_status']!({}));
    expect(pingCheck(out)).toEqual({
      configured: true, verdict: 'pass', verdictReason: 'check-passed',
      gatewayExcluded: null, gatewayFailures: null, transitionReason: 'unknown'
    });
  });

  it.each([
    ['string', '2'],
    ['negative', -1],
    ['fractional', 1.5],
    ['unsafe', Number.MAX_SAFE_INTEGER + 1]
  ])('rejects %s gateway failure counts', async (_label, failures) => {
    const { handlers } = harness({ internetStatus: {
      checked: true, enabled: true, reliable: true, internet: true, gateway: { failures }
    } });
    expect(pingCheck(payload(await handlers['get_internet_status']!({}))).gatewayFailures).toBeNull();
  });

  it('retains all seven legacy false-coercing scalars for malformed input', async () => {
    const { handlers } = harness({ internetStatus: {
      internet: 'yes', checked: [], enabled: {}, reliable: 1,
      'gateway-accessible': null, 'dns-accessible': 'up', 'captive-accessible': []
    } });
    const out = payload(await handlers['get_internet_status']!({}));
    expect(out).toMatchObject({
      internet: false,
      checked: false,
      enabled: false,
      reliable: false,
      gatewayAccessible: false,
      dnsAccessible: false,
      captiveAccessible: false
    });
    expect(pingCheck(out)).toMatchObject({ configured: null, verdict: 'unknown' });
  });

  it.each([
    ['authentication', 'auth-error-sentinel', new AuthError('auth-error-sentinel')],
    ['transport', 'transport-error-sentinel', new TransportError('transport-error-sentinel')],
    ['ordinary RCI', 'rci-error-sentinel', new RciError('rci-error-sentinel', {
      path: 'show/internet/status', code: '500', ident: 'http'
    })],
    ['response-too-large RCI', 'response-limit-sentinel', new RciError('response-limit-sentinel', {
      path: 'show/internet/status', code: 'response-too-large', ident: 'rci'
    })]
  ])('preserves %s source failures as MCP errors', async (_label, marker, internetError) => {
    const { handlers } = harness({ internetError });
    const result = await handlers['get_internet_status']!({});
    expect(result.isError).toBe(true);
    const text = result.content.map(part => part.text).join('');
    expect(text).toContain(marker);
    expect(text).not.toContain('pingCheck');
  });

  it('uses one existing read, retains read-only annotation, and honors the response bound', async () => {
    const { handlers, configs, get } = harness({ maxResponseBytes: 500 });
    const result = await handlers['get_internet_status']!({});
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('show/internet/status');
    expect(configs['get_internet_status']?.annotations?.readOnlyHint).toBe(true);
    expect(Buffer.byteLength(result.content.map(part => part.text).join(''))).toBeLessThanOrEqual(500);
  });

  it('uses the existing bounded result envelope instead of leaking over-limit source fields', async () => {
    const secret = 'over-limit-secret-sentinel';
    const { handlers } = harness({
      maxResponseBytes: 180,
      internetStatus: {
        checked: true, enabled: true, reliable: true, internet: true,
        gateway: { secret }
      }
    });
    const result = await handlers['get_internet_status']!({});
    const text = result.content.map(part => part.text).join('');
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(180);
    expect(JSON.parse(text)).toMatchObject({ truncated: true });
    expect(text).not.toContain(secret);
    expect(text).not.toContain('pingCheck');
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
