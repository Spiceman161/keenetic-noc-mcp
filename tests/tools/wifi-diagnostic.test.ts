import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerWifiDiagnosticTools } from '../../src/tools/wifi-diagnostic.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

const host = { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'Kitchen Phone',
  hostname: 'phone', active: true, ap: 'WifiMaster0/AccessPoint0', ssid: 'safe-ssid' };
const values: Record<string, unknown> = {
  'show/version': { title: '5.1.3' },
  'show/ip/hotspot': { host: [host] },
  'show/associations': { station: [{ mac: host.mac, ap: host.ap, authenticated: true,
    rssi: -55, txrate: 100, ht: 80 }] },
  'show/interface': {
    WifiMaster0: { id: 'WifiMaster0', type: 'WifiMaster', state: 'up', bandwidth: 80 },
    'WifiMaster0/AccessPoint0': { id: 'WifiMaster0/AccessPoint0', type: 'AccessPoint', state: 'up' }
  }
};

function setup(options: { values?: Record<string, unknown>; failures?: Record<string, Error>; maxBytes?: number } = {}) {
  const responses = { ...values, ...options.values };
  const order: string[] = [];
  const get = vi.fn(async (path: string, maxBytes?: number) => {
    order.push(path);
    expect(maxBytes).toBe(path === 'show/version' ? 64_000 : 256_000);
    const failure = options.failures?.[path];
    if (failure) throw failure;
    return responses[path];
  });
  const client = { rci: { get } } as unknown as KeeneticClient;
  const ctx: ToolContext = { client, maxResponseBytes: options.maxBytes ?? 25_000,
    readOnly: true, backup: stubBackup() };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, { annotations?: Record<string, boolean> }> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, config: never, handler: Handler) => {
    handlers[name] = handler;
    configs[name] = config;
    return {} as never;
  }) as never);
  registerWifiDiagnosticTools(server, ctx);
  return { handlers, configs, get, order };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

describe('diagnose_wifi', () => {
  it('collects fresh bounded sources sequentially and returns only aggregate client data', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['diagnose_wifi']!({}));
    expect(fixture.order).toEqual(['show/version', 'show/interface', 'show/associations']);
    expect(out).toMatchObject({ schemaVersion: 1, status: 'healthy', complete: true,
      evidence: { topology: { data: { totals: { radios: 1, accessPoints: 1, clients: 1 } } } } });
    expect(JSON.stringify(out)).not.toContain(host.mac);
    expect(JSON.stringify(out)).not.toContain(host.ssid);
    expect(fixture.configs['diagnose_wifi']?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });

  it('latches the first transport failure as unavailable evidence', async () => {
    const fixture = setup({ failures: { 'show/interface': new TransportError('offline') } });
    const out = payload(await fixture.handlers['diagnose_wifi']!({}));
    expect(fixture.order).toEqual(['show/version', 'show/interface']);
    expect(out.status).toBe('unknown');
    expect(out.complete).toBe(false);
    expect(out.evidence.topology.data.sourceAvailability).toMatchObject({ interfaces: 'unavailable', associations: 'unavailable' });
  });

  it('continues after nonfatal RCI and malformed source failures', async () => {
    const unavailable = setup({ failures: { 'show/interface': new RciError('missing', {
      path: 'show/interface', code: '404', ident: 'http'
    }) } });
    expect(payload(await unavailable.handlers['diagnose_wifi']!({})).evidence.topology.data
      .sourceAvailability.interfaces).toBe('unavailable');
    expect(unavailable.order).toEqual(['show/version', 'show/interface', 'show/associations']);
    const malformed = setup({ values: { 'show/associations': { wrong: [] } } });
    expect(payload(await malformed.handlers['diagnose_wifi']!({})).complete).toBe(false);
    const malformedInterfaces = setup({ values: { 'show/interface': { error: 'wrong' } } });
    const malformedOut = payload(await malformedInterfaces.handlers['diagnose_wifi']!({}));
    expect(malformedOut.complete).toBe(false);
    expect(malformedOut.evidence.topology.data.sourceAvailability.interfaces).toBe('unavailable');
  });

  it('preserves the aggregate report envelope under response trimming', async () => {
    const out = payload(await setup({ maxBytes: 2_000 }).handlers['diagnose_wifi']!({}));
    expect(out).toMatchObject({ schemaVersion: 1, truncated: true,
      evidence: { topology: { data: { totals: { radios: 1, accessPoints: 1, clients: 1 } } } } });
    expect(out.checks).toEqual(expect.any(Array));
    expect(out.findings).toEqual(expect.any(Array));
  });

  it('preserves an unhealthy aggregate envelope under response trimming', async () => {
    const fixture = setup({ maxBytes: 2_000, values: {
      'show/interface': {},
      'show/associations': { station: [{ mac: host.mac, ap: 'WifiMaster9/AccessPoint9',
        authenticated: false, rssi: -90 }] }
    } });
    const result = await fixture.handlers['diagnose_wifi']!({});
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(2_000);
    expect(out).toMatchObject({ schemaVersion: 1, status: 'unhealthy',
      evidence: { topology: { data: { totals: { clients: 1 } } } } });
    expect(out.findings).toHaveLength(4);
    expect(out).not.toHaveProperty('originalBytes');
  });

  it('treats authentication failure as fatal and sanitized', async () => {
    const fixture = setup({ failures: { 'show/version': new AuthError('password=private') } });
    const result = await fixture.handlers['diagnose_wifi']!({});
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).not.toContain('private');
    expect(fixture.order).toEqual(['show/version']);
  });
});

describe('get_wifi_client_health', () => {
  it('resolves hotspot first and returns only the selected client evidence', async () => {
    const sibling = { mac: '02:00:00:00:00:02', name: 'private sibling', ap: host.ap, ssid: 'other-ssid' };
    const fixture = setup({ values: { 'show/ip/hotspot': { host: [host, sibling] },
      'show/associations': { station: [values['show/associations'] &&
        (values['show/associations'] as any).station[0], { mac: sibling.mac, ap: sibling.ap, rssi: -20 }] } } });
    const out = payload(await fixture.handlers['get_wifi_client_health']!({ name: 'ＫＩＴＣＨＥＮphone' }));
    expect(fixture.order).toEqual(['show/ip/hotspot', 'show/associations', 'show/interface']);
    expect(out.evidence.identity.data).toMatchObject({ mac: host.mac, name: host.name });
    expect(out.evidence.connection.data.ssid).toBe(host.ssid);
    expect(JSON.stringify(out)).not.toContain(sibling.mac);
    expect(JSON.stringify(out)).not.toContain(sibling.name);
    expect(fixture.configs['get_wifi_client_health']?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });

  it('returns not-applicable for a wired device', async () => {
    const wired = { mac: host.mac, ip: host.ip, name: host.name, active: true, interface: { id: 'Bridge0' } };
    const fixture = setup({ values: { 'show/ip/hotspot': { host: [wired] }, 'show/associations': { station: [] } } });
    expect(payload(await fixture.handlers['get_wifi_client_health']!({ mac: host.mac })).status).toBe('not-applicable');
  });

  it('rejects unsafe selector cases without listing known devices', async () => {
    const empty = setup();
    expect((await empty.handlers['get_wifi_client_health']!({})).isError).toBe(true);
    expect(empty.get).not.toHaveBeenCalled();
    const ambiguous = setup({ values: { 'show/ip/hotspot': { host: [host, { ...host,
      mac: '02:00:00:00:00:03', name: 'kitchenphone' }] } } });
    const result = await ambiguous.handlers['get_wifi_client_health']!({ name: host.name });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).not.toContain(host.mac);
    const missing = await setup().handlers['get_wifi_client_health']!({ name: 'missing' });
    expect(missing.content[0]?.text).not.toContain(host.name);
  });

  it('latches transport failures after identity and makes later evidence unavailable', async () => {
    const fixture = setup({ failures: { 'show/associations': new TransportError('offline') } });
    const out = payload(await fixture.handlers['get_wifi_client_health']!({ ip: host.ip }));
    expect(fixture.order).toEqual(['show/ip/hotspot', 'show/associations']);
    expect(out.evidence.association.reason).toBe('transport-error');
    expect(out.evidence.radio.reason).toBe('transport-error');
  });

  it('does not call a partial hotspot row wired when associations are unavailable', async () => {
    const partial = { mac: host.mac, ip: host.ip, active: true, interface: { id: 'Bridge0' } };
    const fixture = setup({ values: { 'show/ip/hotspot': { host: [partial] } },
      failures: { 'show/associations': new TransportError('offline') } });
    const out = payload(await fixture.handlers['get_wifi_client_health']!({ mac: host.mac }));
    expect(out.status).not.toBe('not-applicable');
    expect(out.complete).toBe(false);
    expect(out.evidence.connection.data.kind).toBe('unknown');
    expect(out.evidence.association.reason).toBe('transport-error');
  });

  it('treats response-too-large as bounded unavailable evidence', async () => {
    const fixture = setup({ failures: { 'show/associations': new RciError('large', {
      path: 'show/associations', code: 'response-too-large', ident: 'rci'
    }) } });
    const out = payload(await fixture.handlers['get_wifi_client_health']!({ mac: host.mac }));
    expect(out.evidence.association.reason).toBe('response-too-large');
  });

  it('preserves selected identity and the report envelope under response trimming', async () => {
    const out = payload(await setup({ maxBytes: 2_000 }).handlers['get_wifi_client_health']!({ mac: host.mac }));
    expect(out).toMatchObject({ schemaVersion: 1, truncated: true,
      evidence: { identity: { data: { mac: host.mac } } } });
    expect(out.checks).toEqual(expect.any(Array));
    expect(out.findings).toEqual(expect.any(Array));
  });

  it('preserves an unhealthy selected-client envelope under response trimming', async () => {
    const fixture = setup({ maxBytes: 2_000, values: {
      'show/associations': { station: [{ mac: host.mac, ap: 'WifiMaster9/AccessPoint9',
        authenticated: false, rssi: -90 }] }, 'show/interface': {}
    } });
    const result = await fixture.handlers['get_wifi_client_health']!({ mac: host.mac });
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(2_000);
    expect(out).toMatchObject({ schemaVersion: 1, status: 'unhealthy',
      evidence: { identity: { data: { mac: host.mac } } } });
    expect(out.findings.length).toBeGreaterThanOrEqual(3);
    expect(out).not.toHaveProperty('originalBytes');
  });
});
