import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { readFile } from 'node:fs/promises';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { isDhcpBindingsShape, registerDeviceDiagnosticTool } from '../../src/tools/diagnose-device.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

const HOST = {
  mac: '02:00:00:00:00:01', ip: '192.0.2.5', ip6: ['2001:db8::5'], name: 'device-1',
  hostname: 'host-1', registered: true, active: true, access: 'permit', policy: 'Policy0',
  interface: { id: 'Bridge0', name: 'Home' }, link: 'up', ssid: 'ssid-1',
  ap: 'WifiMaster0/AccessPoint0', authenticated: true, rssi: -55, txrate: 144,
  mode: '11ax', ht: 80, dhcp: { expires: 1200 }
};

const VALUES: Record<string, unknown> = {
  'show/version': { model: 'Keenetic Test', title: '5.1.4' },
  'show/ip/hotspot': { host: [HOST] },
  'show/ip/dhcp/bindings': { lease: [{ mac: HOST.mac, ip: HOST.ip, expires: '1190', via: 'Bridge0' }] },
  'show/associations': { station: [{ mac: HOST.mac, ap: HOST.ap, authenticated: true,
    rssi: -54, txrate: 144, rxrate: 173, mode: '11ax', ht: 80 }] },
  'show/interface': {
    WifiMaster0: { type: 'WifiMaster', band: '5' },
    'WifiMaster0/AccessPoint0': { type: 'AccessPoint', link: 'up', state: 'up' },
    Wireguard3: { type: 'Wireguard', link: 'up', state: 'up' }
  },
  'ip/policy': { Policy0: { description: 'tunnel', permit: [{ interface: 'Wireguard3' }] } },
  'show/internet/status': { checked: true, 'dns-accessible': true, internet: true }
};

function setup(options: { values?: Record<string, unknown>; failures?: Record<string, Error> } = {}) {
  const values = { ...VALUES, ...options.values };
  const order: string[] = [];
  const get = vi.fn(async (path: string, _maxBytes?: number) => {
    order.push(path);
    const failure = options.failures?.[path];
    if (failure) throw failure;
    return values[path];
  });
  const post = vi.fn(async (body: unknown, _maxBytes?: number) => {
    order.push('show/log');
    expect(body).toEqual({ show: { log: {} } });
    const failure = options.failures?.['show/log'];
    if (failure) throw failure;
    return { show: { log: { log: {
      '1': { timestamp: '00:01', ident: 'Hotspot', message: { message: `${HOST.ip} joined password=private` } },
      '2': { timestamp: '00:02', ident: 'System', message: { message: 'unrelated' } }
    } } } };
  });
  const client = { rci: { get, post } } as unknown as KeeneticClient;
  const ctx: ToolContext = { client, maxResponseBytes: 25_000, readOnly: true, backup: stubBackup() };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  let handler: Handler | undefined;
  let config: { annotations?: Record<string, boolean> } | undefined;
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, value: never, callback: Handler) => {
    if (name === 'diagnose_device') { handler = callback; config = value; }
    return {} as never;
  }) as never);
  registerDeviceDiagnosticTool(server, ctx);
  return { handler: handler!, config: config!, get, post, order };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

describe('diagnose_device', () => {
  it('accepts the synthetic form measured on KeeneticOS 5.1.3', async () => {
    const fixture = JSON.parse(await readFile(new URL('../fixtures/show_ip_dhcp_bindings.json', import.meta.url), 'utf8'));
    expect(isDhcpBindingsShape(fixture)).toBe(true);
    expect(isDhcpBindingsShape({ lease: [{ mac: [], expires: {} }] })).toBe(false);
  });

  it('collects bounded sources sequentially, with the read-only log dispatcher last', async () => {
    const fixture = setup();
    const out = payload(await fixture.handler({ name: 'DEVICE-1' }));
    expect(out).toMatchObject({ schemaVersion: 1, status: 'healthy', complete: true,
      untrustedRouterData: true, truncated: false });
    expect(out.evidence.identity.data.mac).toBe(HOST.mac);
    expect(out.evidence.dhcpBinding.data).toMatchObject({ matched: true, expiresSeconds: 1190 });
    expect(out.evidence.wifi.data).toMatchObject({ applicable: true, associated: true,
      band: '5', rxRateMbps: 173 });
    expect(out.evidence.logs.data.items[0].line).not.toContain('private');
    expect(fixture.order).toEqual(['show/version', 'show/ip/hotspot', 'show/ip/dhcp/bindings',
      'show/associations', 'show/interface', 'ip/policy', 'show/internet/status', 'show/log']);
    for (const call of fixture.get.mock.calls) expect(call[1]).toEqual(expect.any(Number));
    expect(fixture.post).toHaveBeenCalledWith({ show: { log: {} } }, 2_000_000);
    expect(fixture.config.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });

  it('marks Wi-Fi not applicable for a wired device without inventing telemetry', async () => {
    const wired = { ...HOST, ssid: undefined, ap: undefined, rssi: undefined, interface: { id: 'Bridge0' }, policy: '' };
    const fixture = setup({ values: {
      'show/ip/hotspot': { host: [wired] },
      'show/ip/dhcp/bindings': { lease: [] },
      'show/associations': { station: [] },
      'ip/policy': {}
    } });
    const out = payload(await fixture.handler({ mac: HOST.mac.toUpperCase() }));
    expect(out.evidence.connection.data.kind).toBe('wired');
    expect(out.evidence.wifi.data).toMatchObject({ applicable: false, rssiDbm: null });
    expect(out.checks.find((check: any) => check.id === 'wifi').status).toBe('not-applicable');
  });

  it('reports explicit access denial and Wi-Fi authentication failure without log inference', async () => {
    const blocked = { ...HOST, access: 'deny', authenticated: false };
    const fixture = setup({ values: {
      'show/ip/hotspot': { host: [blocked] },
      'show/associations': { station: [{ mac: HOST.mac, ap: HOST.ap, authenticated: false }] }
    } });
    const out = payload(await fixture.handler({ ip: HOST.ip }));
    expect(out.status).toBe('unhealthy');
    expect(out.findings.map((finding: any) => finding.id)).toEqual(expect.arrayContaining([
      'device-access-blocked', 'wifi-not-authenticated'
    ]));
  });

  it('uses unknown for absent addresses and missing telemetry', async () => {
    const offline = { mac: HOST.mac, name: HOST.name, registered: true, active: false, access: 'permit' };
    const fixture = setup({ values: {
      'show/ip/hotspot': { host: [offline] }, 'show/ip/dhcp/bindings': { lease: [] },
      'show/associations': { station: [] }, 'show/interface': {}, 'ip/policy': {}
    } });
    const out = payload(await fixture.handler({ name: HOST.name }));
    expect(out.status).toBe('degraded');
    expect(out.checks.find((check: any) => check.id === 'address').status).toBe('unknown');
    expect(out.findings.map((finding: any) => finding.id)).toContain('device-inactive');
  });

  it('preserves core evidence when a secondary RCI path or shape is unavailable', async () => {
    const fixture = setup({
      values: { 'show/associations': { unexpected: true } },
      failures: { 'show/ip/dhcp/bindings': new RciError('missing', {
        path: 'show/ip/dhcp/bindings', code: '404', ident: 'http'
      }) }
    });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(out.evidence.identity.status).toBe('available');
    expect(out.evidence.dhcpBinding.reason).toBe('rci-error');
    expect(out.evidence.wifi.data).toMatchObject({ associationStateAvailable: false, associated: null });
    expect(out.complete).toBe(false);
  });

  it('retains an explicit Wi-Fi authentication failure when interface detail is unavailable', async () => {
    const fixture = setup({
      values: { 'show/associations': { station: [{ mac: HOST.mac, ap: HOST.ap, authenticated: false }] } },
      failures: { 'show/interface': new RciError('missing', {
        path: 'show/interface', code: '404', ident: 'http'
      }) }
    });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(out.evidence.wifi.data.authenticated).toBe(false);
    expect(out.findings.map((finding: any) => finding.id)).toContain('wifi-not-authenticated');
    expect(out.complete).toBe(false);
  });

  it('retains hotspot authentication evidence when association detail is unavailable', async () => {
    const fixture = setup({
      values: { 'show/ip/hotspot': { host: [{ ...HOST, authenticated: false }] } },
      failures: { 'show/associations': new RciError('missing', {
        path: 'show/associations', code: '404', ident: 'http'
      }) }
    });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(out.evidence.wifi.data).toMatchObject({ authenticated: false, associated: null,
      associationStateAvailable: false });
    expect(out.findings.map((finding: any) => finding.id)).toContain('wifi-not-authenticated');
    expect(out.findings.map((finding: any) => finding.id)).not.toContain('wifi-association-missing');
    expect(out.complete).toBe(false);
  });

  it('keeps Wi-Fi not applicable for wired devices when associations are unavailable', async () => {
    const wired = { ...HOST, ssid: undefined, ap: undefined, policy: '' };
    const fixture = setup({
      values: { 'show/ip/hotspot': { host: [wired] }, 'ip/policy': {} },
      failures: { 'show/associations': new RciError('missing', {
        path: 'show/associations', code: '404', ident: 'http'
      }) }
    });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(out.checks.find((check: any) => check.id === 'wifi').status).toBe('not-applicable');
  });

  it('retains a missing assigned policy when interface state is unavailable', async () => {
    const fixture = setup({
      values: { 'ip/policy': {} },
      failures: { 'show/interface': new RciError('missing', {
        path: 'show/interface', code: '404', ident: 'http'
      }) }
    });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(out.evidence.routingPolicy.data).toMatchObject({ assigned: 'Policy0', present: false });
    expect(out.findings.map((finding: any) => finding.id)).toContain('routing-policy-missing');
  });

  it('latches the first transport failure and skips later router requests', async () => {
    const fixture = setup({ failures: { 'show/associations': new TransportError('offline') } });
    const out = payload(await fixture.handler({ mac: HOST.mac }));
    expect(fixture.order).toEqual(['show/version', 'show/ip/hotspot', 'show/ip/dhcp/bindings', 'show/associations']);
    expect(out.evidence.wifi.data).toMatchObject({ associationStateAvailable: false, associated: null });
    expect(out.evidence.logs.reason).toBe('transport-error');
  });

  it('treats authentication loss as fatal and redacts its message', async () => {
    const fixture = setup({ failures: { 'ip/policy': new AuthError('password=private') } });
    const result = await fixture.handler({ mac: HOST.mac });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).not.toContain('private');
    expect(fixture.order).not.toContain('show/internet/status');
  });

  it('rejects ambiguous and unmatched selectors without enumerating devices', async () => {
    const hosts = { host: [
      { mac: '02:00:00:00:00:11', name: 'Kitchen Phone' },
      { mac: '02:00:00:00:00:12', name: 'kitchenphone' }
    ] };
    const ambiguous = await setup({ values: { 'show/ip/hotspot': hosts } }).handler({ name: 'Kitchen Phone' });
    expect(ambiguous.isError).toBe(true);
    expect(ambiguous.content[0]?.text).not.toContain('02:00:00:00:00:11');
    const missing = await setup().handler({ name: 'not-present' });
    expect(missing.isError).toBe(true);
    expect(missing.content[0]?.text).not.toContain(HOST.name);
    expect(missing.content[0]?.text).not.toContain(HOST.mac);
  });

  it('requires exactly one selector', async () => {
    const empty = setup();
    expect((await empty.handler({})).isError).toBe(true);
    expect(empty.get).not.toHaveBeenCalled();
    const multiple = setup();
    expect((await multiple.handler({ mac: HOST.mac, ip: HOST.ip })).isError).toBe(true);
    expect(multiple.get).not.toHaveBeenCalled();
    const oversized = setup();
    expect((await oversized.handler({ name: 'x'.repeat(257) })).isError).toBe(true);
    expect(oversized.get).not.toHaveBeenCalled();
  });
});
