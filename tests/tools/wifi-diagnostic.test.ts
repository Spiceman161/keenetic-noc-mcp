import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerWifiDiagnosticTools } from '../../src/tools/wifi-diagnostic.js';
import { getToolResultTelemetry, type ToolContext, type ToolResult } from '../../src/tools/registry.js';
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
    expect(maxBytes).toBe(path === 'show/version' ? 64_000
      : path === 'show/interface/Bridge0' ? 32_000 : 256_000);
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

describe('get_mesh_status', () => {
  const controllerMac = '02:00:00:00:00:01';
  const firstMac = '02:00:00:00:00:02';
  const secondMac = '02:00:00:00:00:03';
  const rows = [
    { mac: firstMac, mode: 'extender', hw_type: 'extender', model: 'KN-1234', fw: '5.1.3',
      rci: { errors: 0 }, backhaul: { bridge: `8000.${controllerMac}`, uplink: 'WifiMaster0/WifiStation0', authenticated: true },
      port: [{ link: false }], password: 'secret-one' },
    { mac: secondMac, mode: 'extender', hw_type: 'extender', model: 'KN-2345', fw: '5.1.4',
      rci: { errors: 0 }, backhaul: { bridge: `e000.${firstMac}`, uplink: 'GigabitEthernet0/Vlan1', authenticated: true },
      port: [{ link: true }], ssid: 'secret-ssid' },
    { mac: '02:00:00:00:00:04', model: 'KN-3456', license: 'secret-license' }
  ];

  it('observes exact empty object with only one GET', async () => {
    const fixture = setup({ values: { 'show/mws/member': {} } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'observed', configuredMembers: 0, members: [], controller: { status: 'unknown' }
    });
    expect(fixture.order).toEqual(['show/mws/member']);
    expect(fixture.configs['get_mesh_status']?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });

  it('projects current links, response-local parent, offline skeleton and conditional controller', async () => {
    const fixture = setup({ values: { 'show/mws/member': rows,
      'show/interface/Bridge0': { mac: controllerMac, password: 'secret-bridge' },
      'show/version': { model: 'KN-4567', release: '5.1.5', token: 'secret-version' } } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(fixture.order).toEqual(['show/mws/member', 'show/interface/Bridge0', 'show/version']);
    expect(result).toMatchObject({ status: 'observed', configuredMembers: 3, shown: 3,
      controller: { status: 'derived', ref: 'controller', model: 'KN-4567', firmware: '5.1.5' },
      members: [
        { ref: 'member-1', role: 'extender', firmware: '5.1.3', parentKind: 'controller', parentRef: 'controller', backhaul: 'observed', medium: 'wireless', authenticated: true },
        { ref: 'member-2', firmware: '5.1.4', parentKind: 'extender', parentRef: 'member-1', backhaul: 'observed', medium: 'wired' },
        { ref: 'member-3', model: 'KN-3456', firmware: null, parentKind: 'unknown', backhaul: 'not-observed', medium: 'unknown' }
      ] });
    expect(JSON.stringify(result)).not.toMatch(/02:00:00|secret-|WifiMaster|GigabitEthernet|Vlan1/);
  });

  it('suppresses stale polling backhaul, firmware and controller derivation', async () => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[0], rci: { errors: 1 } }] } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({ members: [{
      pollingError: true, firmware: null, parentKind: 'unknown', backhaul: 'unknown', medium: 'unknown'
    }], controller: { status: 'unknown' } });
    expect(fixture.order).toEqual(['show/mws/member']);
  });

  it.each([undefined, '1', -1, 0.5])('does not infer current topology from errors %s', async (errors) => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[0],
      ...(errors === undefined ? { rci: undefined } : { rci: { errors } }) }],
      'show/interface/Bridge0': { mac: controllerMac } } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(result).toMatchObject({ status: 'observed', configuredMembers: 1,
      controller: { status: 'unknown', firmware: null }, members: [{ model: 'KN-1234',
        pollingError: null, parentKind: 'unknown', parentRef: null, backhaul: 'unknown',
        medium: 'unknown', firmware: null }] });
    expect(fixture.order).toEqual(['show/mws/member']);
  });

  it.each([{}, { bridge: `8000.${controllerMac}` },
    { bridge: `8000.${controllerMac}`, uplink: 'other-uplink' }])(
    'does not expose firmware or parent on partial backhaul %#', async (backhaul) => {
      const fixture = setup({ values: { 'show/mws/member': [{ ...rows[0], backhaul }],
        'show/interface/Bridge0': { mac: controllerMac } } });
      const result = payload(await fixture.handlers['get_mesh_status']!({}));
      expect(result).toMatchObject({ status: 'observed', configuredMembers: 1,
        controller: { status: 'unknown' }, members: [{ model: 'KN-1234', firmware: null,
          backhaul: 'unknown', medium: 'unknown', parentKind: 'unknown', parentRef: null }] });
      expect(fixture.order).toEqual(['show/mws/member']);
    });

  it.each([{ source: [{}] }, { source: [{}, rows[2]] },
    { source: [rows[2], { mac: firstMac, backhaul: { uplink: 9 } }] }])(
    'rejects arrays containing identity-free or malformed member rows %#', async ({ source }) => {
      const fixture = setup({ values: { 'show/mws/member': source } });
      expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
        status: 'unavailable', reason: 'unexpected-response', configuredMembers: null,
        controller: { status: 'unknown' }
      });
      expect(fixture.order).toEqual(['show/mws/member']);
    });

  it.each([[], { error: 'nope' }, new Date(0), null, 42, [{ mac: 9 }]])('does not infer zero from uncertain shape', async (source) => {
    const fixture = setup({ values: { 'show/mws/member': source } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(result.status).not.toBe('observed');
    expect(result.configuredMembers).toBeNull();
    expect(fixture.order).toEqual(['show/mws/member']);
  });

  it('bounds rows and payload detail without losing member counts', async () => {
    const many = setup({ values: { 'show/mws/member': Array.from({ length: 33 }, () => rows[2]) } });
    expect(payload(await many.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'unavailable', reason: 'member-limit', configuredMembers: null, truncated: true
    });
    const small = setup({ values: { 'show/mws/member': rows.slice(1) }, maxBytes: 440 });
    const output = await small.handlers['get_mesh_status']!({});
    expect(Buffer.byteLength(output.content[0]!.text!, 'utf8')).toBeLessThanOrEqual(440);
    expect(payload(output)).toMatchObject({ status: 'observed', configuredMembers: 2, truncated: true });
  });

  it.each([
    ['show/interface/Bridge0', new AuthError('secret auth'), ['show/mws/member', 'show/interface/Bridge0']],
    ['show/interface/Bridge0', new TransportError('secret transport'), ['show/mws/member', 'show/interface/Bridge0']],
    ['show/version', new AuthError('secret auth'), ['show/mws/member', 'show/interface/Bridge0', 'show/version']],
    ['show/version', new TransportError('secret transport'), ['show/mws/member', 'show/interface/Bridge0', 'show/version']]
  ] as const)('keeps primary on optional %s failure', async (path, failure, order) => {
    const fixture = setup({ values: { 'show/mws/member': rows, 'show/interface/Bridge0': { mac: controllerMac } },
      failures: { [path]: failure } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(fixture.order).toEqual(order);
    expect(result).toMatchObject({ status: 'observed', configuredMembers: 3, shown: 3 });
    expect(result.sources[path === 'show/version' ? 'version' : 'bridge']).toBe(
      failure instanceof AuthError ? 'authentication-error' : 'transport-error'
    );
    expect(JSON.stringify(result)).not.toContain('secret');
  });

  it('does not derive controller on bridge mismatch or ambiguous extender identity', async () => {
    const fixture = setup({ values: { 'show/mws/member': [rows[0], rows[0], rows[1]],
      'show/interface/Bridge0': { mac: '02:00:00:00:00:ff' } } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(fixture.order).toEqual(['show/mws/member', 'show/interface/Bridge0']);
    expect(result).toMatchObject({ controller: { status: 'unknown' },
      members: [{ parentRef: null }, { parentRef: null }, { parentKind: 'extender', parentRef: null }] });
  });

  it('reports unsupported or missing primary source as unavailable with one GET', async () => {
    const fixture = setup({ failures: { 'show/mws/member': new RciError('private response', {
      path: 'show/mws/member', code: '404', ident: 'http'
    }) } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'unavailable', reason: 'rci-error', configuredMembers: null
    });
    expect(fixture.order).toEqual(['show/mws/member']);
  });

  it.each([
    'Authentication failed for login synthetic-user at 192.0.2.91 router synthetic-router-id',
    'Challenge failed at synthetic-router.example for synthetic-user router synthetic-router-id 192.0.2.91'
  ])('preserves fatal authentication without exposing identifying text', async (message) => {
    const fixture = setup({ failures: { 'show/mws/member': new AuthError(message) } });
    const result = await fixture.handlers['get_mesh_status']!({});
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('Mesh membership authentication failed.');
    expect(getToolResultTelemetry(result)?.errorCode).toBe('authentication');
    for (const identifier of ['synthetic-user', 'synthetic-router.example', 'synthetic-router-id', '192.0.2.91']) {
      expect(JSON.stringify({ result, telemetry: getToolResultTelemetry(result) })).not.toContain(identifier);
    }
    expect(fixture.order).toEqual(['show/mws/member']);
  });

  it('does not treat a capped primary read as zero members', async () => {
    const fixture = setup({ failures: { 'show/mws/member': new RciError('oversized', {
      path: 'show/mws/member', code: 'response-too-large', ident: 'rci'
    }) } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'unavailable', reason: 'response-too-large', configuredMembers: null
    });
    expect(fixture.order).toEqual(['show/mws/member']);
  });
});

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
