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
  const readMeshLog = vi.fn(async () => {
    order.push('POST /rci/show/mws/log');
    const failure = options.failures?.['POST /rci/show/mws/log'];
    if (failure) throw failure;
    return responses['POST /rci/show/mws/log'];
  });
  const client = { rci: { get, readMeshLog } } as unknown as KeeneticClient;
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
  return { handlers, configs, get, readMeshLog, order };
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
    expect(fixture.order).toEqual(['show/mws/member', 'show/interface/Bridge0', 'show/version', 'show/associations']);
    expect(result).toMatchObject({ status: 'observed', configuredMembers: 3, shown: 3,
      controller: { status: 'derived', ref: 'controller', model: 'KN-4567', firmware: '5.1.5' },
      members: [
        { ref: 'member-1', role: 'extender', firmware: '5.1.3', parentKind: 'controller', parentRef: 'controller', backhaul: 'observed', medium: 'wireless', authenticated: true },
        { ref: 'member-2', firmware: '5.1.4', parentKind: 'extender', parentRef: 'member-1', backhaul: 'observed', medium: 'wired' },
        { ref: 'member-3', model: 'KN-3456', firmware: null, parentKind: 'unknown', backhaul: 'not-observed', medium: 'unknown', pollingError: null }
      ] });
    expect(JSON.stringify(result)).not.toMatch(/02:00:00|secret-|WifiMaster|GigabitEthernet|Vlan1/);
  });

  it('projects bounded wireless and wired member details from the existing reads only', async () => {
    const fixture = setup({ values: { 'show/mws/member': [
      { ...rows[0], model: 'Buddy 5 (KN-3311)', hw_id: 'KN-3311', 'known-host': 'BuddyOffice',
        associations: 0, 'fw-release': '5.01.C.5.0-0', fw: '5.1.5',
        cid: 'cid-wifi-sentinel', license: 'license-wifi-sentinel', fqdn: 'wifi.example.invalid',
        ip: '192.0.2.21', unexpected: { opaque: 'opaque-wifi-sentinel' },
        backhaul: { ...rows[0]!.backhaul, rssi: -55, txrate: 100, ht: 80, mode: 'x',
          mcs: 4, txss: 2, uptime: 20, cost: 19, speed: '100', duplex: 'full', 'port-label': '0' } },
      { ...rows[1], model: 'Buddy 5 (KN-3311)', hw_id: 'KN-3311',
        'known-host': 'BuddyNikola', associations: 3, cid: 'cid-wired-sentinel',
        license: 'license-wired-sentinel', fqdn: 'wired.example.invalid', ip: '192.0.2.22',
        unexpected: { opaque: 'opaque-wired-sentinel' }, backhaul: { ...rows[1]!.backhaul,
          cost: 19, speed: '100', duplex: 'full', 'port-label': '0' } },
      { ...rows[2], model: 'Buddy 5 (KN-3311)', hw_id: 'KN-3311', 'known-host': 'BuddySpare',
        cid: 'cid-offline-sentinel', license: 'license-offline-sentinel',
        fqdn: 'offline.example.invalid', ip: '192.0.2.23',
        unexpected: { opaque: 'opaque-offline-sentinel' } }
    ], 'show/interface/Bridge0': { mac: controllerMac }, 'show/version': { model: 'KN-4567' } } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(fixture.order).toEqual(['show/mws/member', 'show/interface/Bridge0', 'show/version', 'show/associations']);
    expect(result.members).toMatchObject([
      { model: 'Buddy 5 (KN-3311)', hwId: 'KN-3311', displayName: 'BuddyOffice',
        associationCount: 0, firmware: '5.1.5', medium: 'wireless', backhaulDetails: null },
      { model: 'Buddy 5 (KN-3311)', hwId: 'KN-3311', displayName: 'BuddyNikola',
        associationCount: 3, medium: 'wired', backhaulDetails: { duplex: 'full' } },
      { model: 'Buddy 5 (KN-3311)', hwId: 'KN-3311', displayName: 'BuddySpare',
        associationCount: null, firmware: null, authenticated: null,
        medium: 'unknown', backhaulDetails: null, backhaul: 'not-observed' }
    ]);
    const output = JSON.stringify(result);
    for (const field of ['port-label', 'cost', 'speed', 'rssi', 'txrate', 'ht', 'mcs', 'txss', 'uptime',
      'cid', 'license', 'fqdn', 'ip', 'unexpected', 'ssid']) {
      expect(output).not.toContain(`"${field}":`);
    }
    for (const value of [firstMac, secondMac, '02:00:00:00:00:04', 'WifiMaster0/WifiStation0',
      'GigabitEthernet0/Vlan1', 'cid-wifi-sentinel', 'license-wifi-sentinel',
      'wifi.example.invalid', '192.0.2.21', 'opaque-wifi-sentinel', 'cid-wired-sentinel',
      'license-wired-sentinel', 'wired.example.invalid', '192.0.2.22', 'opaque-wired-sentinel',
      'cid-offline-sentinel', 'license-offline-sentinel', 'offline.example.invalid',
      '192.0.2.23', 'opaque-offline-sentinel', 'secret-one', 'secret-ssid', 'secret-license']) {
      expect(output).not.toContain(value);
    }
  });

  it('rejects an unseparated MAC as a display label without losing model or hardware ID', async () => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[0], model: 'Buddy 5 (KN-3311)',
      hw_id: 'KN-3311', 'known-host': '020000000001' }] } });
    const result = await fixture.handlers['get_mesh_status']!({});
    const output = result.content.map(part => part.text).join('');
    expect(JSON.parse(output).members[0]).toMatchObject({ model: 'Buddy 5 (KN-3311)',
      hwId: 'KN-3311', displayName: null });
    expect(output).not.toContain('020000000001');
  });

  it('retains typed association observations on stale members without stale link details', async () => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[1], associations: 7,
      'known-host': 'BuddyOffice', rci: { errors: 1 }, backhaul: { ...rows[1]!.backhaul, duplex: 'full' } }] } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(result.members[0]).toMatchObject({ pollingError: true, associationCount: 7,
      displayName: 'BuddyOffice', firmware: null, medium: 'unknown', authenticated: null,
      backhaulDetails: null, parentKind: 'unknown' });
    expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
  });

  it.each([null, -1, 0.1, 100_001, '0', Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER])(
    'ignores invalid association count %s without discarding the member', async associations => {
      const fixture = setup({ values: { 'show/mws/member': [{ ...rows[2], associations }] } });
      expect(payload(await fixture.handlers['get_mesh_status']!({})).members[0].associationCount).toBeNull();
    });

  it.each(['token=payload', 'password secret', 'a\u001b[31mB', 'https://test.invalid/x',
    'host.example', '192.0.2.1', '02:00:00:00:00:01', '02-00-00-00-00-01',
    'sk-1234567890abcdef', 'x'.repeat(30), 'x'.repeat(49),
    'tokenPayload', 'owner\u202eadmin', { name: 'BuddyOffice' }])(
    'rejects unsafe known-host %s without exposing extra fields', async name => {
      const fixture = setup({ values: { 'show/mws/member': [{ ...rows[2], 'known-host': name,
        hw_id: 'KN-1234-02:00:00:00:00:01', model: 'secret (KN-3311)', associations: {},
        backhaul: { duplex: { secret: 'secret-private' } }, cid: 'private-cid',
        license: 'private-license', fqdn: 'private.example', ip: '192.0.2.1' }] } });
      const output = payload(await fixture.handlers['get_mesh_status']!({}));
      expect(output.members[0]).toMatchObject({ hwId: null, model: null, displayName: null,
        associationCount: null, backhaulDetails: null });
      expect(JSON.stringify(output)).not.toMatch(/private-|192\.0\.2\.1|host\.example|02:00:00|tokenPayload/);
    });

  it('withholds malformed optional duplex while retaining a valid current wired member', async () => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[1],
      hw_id: 'KN-3311', 'known-host': ' BuddyOffice ', associations: 100_000,
      backhaul: { ...rows[1]!.backhaul, duplex: { secret: 'hidden' },
        speed: '100', 'port-label': 'private-port' } }] } });
    const result = payload(await fixture.handlers['get_mesh_status']!({}));
    expect(result.members[0]).toMatchObject({ medium: 'wired', backhaul: 'observed',
      displayName: 'BuddyOffice', hwId: 'KN-3311', associationCount: 100_000,
      backhaulDetails: { duplex: null } });
    expect(JSON.stringify(result)).not.toMatch(/private-port|hidden|"speed"/);
  });

  it('bounds the final serialized redacted member output under a tight cap', async () => {
    const fixture = setup({ values: { 'show/mws/member': Array.from({ length: 12 }, (_, index) => ({
      ...rows[2], 'known-host': `Buddy${index}LongDisplayLabel`, hw_id: 'KN-3311', associations: 0
    })) }, maxBytes: 440 });
    const result = await fixture.handlers['get_mesh_status']!({});
    const text = result.content.map(part => part.text).join('');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(440);
    expect(JSON.parse(text)).toMatchObject({ status: 'observed', configuredMembers: 12,
      shown: 0, truncated: true, members: [], reason: null });
  });

  it('suppresses stale polling backhaul, firmware and controller derivation', async () => {
    const fixture = setup({ values: { 'show/mws/member': [{ ...rows[0], rci: { errors: 1 } }] } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({ members: [{
      pollingError: true, firmware: null, parentKind: 'unknown', backhaul: 'unknown', medium: 'unknown'
    }], controller: { status: 'unknown' } });
    expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
  });

  it.each([
    { label: 'fw', row: { ...rows[2], fw: '5.1.5' }, pollingError: null },
    { label: 'fw-release', row: { ...rows[2], 'fw-release': '5.1.5' }, pollingError: null },
    { label: 'successful polling', row: { ...rows[2], rci: { errors: 0 } }, pollingError: false },
    { label: 'failed polling', row: { ...rows[2], rci: { errors: 1 } }, pollingError: true },
    { label: 'malformed polling errors', row: { ...rows[2], rci: { errors: '1' } }, pollingError: null },
    { label: 'incomplete polling', row: { ...rows[2], rci: {} }, pollingError: null }
  ])('keeps missing backhaul unknown with $label', async ({ row, pollingError }) => {
    const fixture = setup({ values: { 'show/mws/member': [row] } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'observed', configuredMembers: 1, members: [{ ref: 'member-1', model: 'KN-3456',
        firmware: null, parentKind: 'unknown', parentRef: null, backhaul: 'unknown',
        medium: 'unknown', pollingError }]
    });
    expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
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
    expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
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
      expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
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
    ['show/interface/Bridge0', new AuthError('secret auth'), ['show/mws/member', 'show/interface/Bridge0', 'show/associations']],
    ['show/interface/Bridge0', new TransportError('secret transport'), ['show/mws/member', 'show/interface/Bridge0', 'show/associations']],
    ['show/version', new AuthError('secret auth'), ['show/mws/member', 'show/interface/Bridge0', 'show/version', 'show/associations']],
    ['show/version', new TransportError('secret transport'), ['show/mws/member', 'show/interface/Bridge0', 'show/version', 'show/associations']]
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
    expect(fixture.order).toEqual(['show/mws/member', 'show/interface/Bridge0', 'show/associations']);
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

describe('bounded Mesh controller associations and native events', () => {
  const extender = '02:00:00:00:00:21';
  const controller = '02:00:00:00:00:22';
  const other = '02:00:00:00:00:23';
  const client = '02:00:00:00:00:31';
  const member = { mac: extender, mode: 'extender', hw_type: 'extender', 'known-host': 'MeshOffice' };
  const interfaces = { ap0: { mac: controller, type: 'AccessPoint', group: 'Bridge0', ssid: 'private-ssid' } };
  const event = { timestamp: 'Sep 26 01:13:51', mac: client, left: { ap: controller, band: 0 },
    ap: extender, band: 1, roam: 'ft', id: 'secret-event-id', segment: 'private-segment' };

  it('counts association rows, excluding known backhaul, and verifies empty station', async () => {
    const fixture = setup({ values: { 'show/mws/member': [member], 'show/associations': {
      station: [{ ap: 'WifiMaster0/AccessPoint0' }, { ap: 'WifiMaster0/AccessPoint0', mac: client },
        { ap: 'WifiMaster0/Backhaul0' }] } } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'observed', controller: { associationCount: 2 }, sources: { associations: null }
    });
    expect(fixture.order).toEqual(['show/mws/member', 'show/associations']);
    const zero = setup({ values: { 'show/mws/member': [member], 'show/associations': { station: [] } } });
    expect(payload(await zero.handlers['get_mesh_status']!({})).controller.associationCount).toBe(0);
  });

  it.each([
    [{ station: [{ ap: 'WifiMaster0/AccessPoint0' }, { ap: 'other' }] }, 'unexpected-response'],
    [{ station: [{ ap: 1 }] }, 'unexpected-response'],
    [{}, 'unexpected-response'],
    [[], 'unexpected-response']
  ])('preserves member evidence on invalid optional association %j', async (source, reason) => {
    const fixture = setup({ values: { 'show/mws/member': [member], 'show/associations': source } });
    expect(payload(await fixture.handlers['get_mesh_status']!({}))).toMatchObject({
      status: 'observed', configuredMembers: 1, members: [{ ref: 'member-1' }],
      controller: { associationCount: null }, sources: { associations: reason }
    });
  });

  it.each([new AuthError('private'), new TransportError('private'),
    new RciError('private', { path: 'show/associations', code: 'response-too-large', ident: 'rci' })])(
    'retains primary status on optional error %s', async error => {
      const fixture = setup({ values: { 'show/mws/member': [member] }, failures: { 'show/associations': error } });
      const report = payload(await fixture.handlers['get_mesh_status']!({}));
      expect(report).toMatchObject({ status: 'observed', members: [{ ref: 'member-1' }],
        controller: { associationCount: null } });
      expect(JSON.stringify(report)).not.toContain('private');
      expect(fixture.readMeshLog).not.toHaveBeenCalled();
    });

  it('projects independent transition endpoints and response-local client references', async () => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: {
      '10': { ...event, left: { ap: extender, band: 0 }, ap: controller, band: 1 },
      '2': event,
      '11': { ...event, mac: other, left: undefined, ap: extender, band: 7, roam: 'unknown' },
      '12': { ...event, mac: client, left: { ap: extender, band: 1 }, ap: extender, band: 0 },
      '13': { ...event, mac: other, ap: undefined, left: { ap: controller, band: 0 } }
    } }, 'show/mws/member': [member], 'show/interface': interfaces } });
    const result = payload(await fixture.handlers['get_mesh_events']!({}));
    expect(fixture.order).toEqual(['POST /rci/show/mws/log', 'show/mws/member', 'show/interface']);
    expect(fixture.configs['get_mesh_events']?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    expect(result).toMatchObject({ schemaVersion: 1, status: 'observed', shown: 5, truncated: false,
      sources: { log: null, members: null, interfaces: null }, events: [
        { type: 'transition', clientRef: 'client-1', fromNode: { kind: 'controller', ref: 'controller' },
          toNode: { kind: 'extender', ref: 'member-1', displayName: 'MeshOffice' },
          fromBandIndex: 0, toBandIndex: 1, roamMethod: 'ft', timestamp: 'Sep 26 01:13:51' },
        { type: 'transition', clientRef: 'client-1', fromNode: { kind: 'extender' }, toNode: { kind: 'controller' } },
        { type: 'association', clientRef: 'client-2', fromNode: null, toBandIndex: null, roamMethod: null },
        { type: 'transition', clientRef: 'client-1', fromNode: { ref: 'member-1' },
          toNode: { ref: 'member-1' } },
        { type: 'departure', clientRef: 'client-2', toNode: null, toBandIndex: null }
      ] });
    expect(JSON.stringify(result)).not.toMatch(/02:00:00|secret-|private-|WifiMaster|ssid|segment|"id":/);
  });

  it('keeps usable rows on malformed rows without falsely setting truncated', async () => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: {
      '0': { ...event, mac: 'invalid' }, '1': event,
      '2': { ...event, left: { ap: 'invalid', band: 0 } }
    } }, 'show/mws/member': [], 'show/interface': {} } });
    expect(payload(await fixture.handlers['get_mesh_events']!({}))).toMatchObject({
      status: 'observed', reason: 'unexpected-response', shown: 1, truncated: false,
      sources: { log: 'unexpected-response', members: 'unexpected-response', interfaces: 'unexpected-response' },
      events: [{ fromNode: { kind: 'unknown', ref: null, displayName: null },
        toNode: { kind: 'unknown', ref: null, displayName: null } }]
    });
  });

  it('rejects ambiguous, unmatched, and conflicting AP joins without losing events', async () => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: {
      '0': event, '1': { ...event, mac: other, ap: other }
    } }, 'show/mws/member': [member, { ...member, mac: extender.toUpperCase() }],
    'show/interface': { ...interfaces, duplicate: { ...interfaces.ap0 } } } });
    const report = payload(await fixture.handlers['get_mesh_events']!({}));
    expect(report).toMatchObject({ status: 'observed', shown: 2, truncated: false,
      events: [
        { fromNode: { kind: 'unknown', ref: null }, toNode: { kind: 'unknown', ref: null } },
        { toNode: { kind: 'unknown', ref: null } }
      ] });
    const conflict = setup({ values: { 'POST /rci/show/mws/log': { log: { '0': event } },
      'show/mws/member': [member], 'show/interface': { ap0: { ...interfaces.ap0, mac: extender } } } });
    expect(payload(await conflict.handlers['get_mesh_events']!({})).events[0].toNode)
      .toMatchObject({ kind: 'unknown', ref: null });
  });

  it.each(['show/mws/member', 'show/interface'])('fails soft on optional %s read', async path => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: { '0': event } },
      'show/mws/member': [member], 'show/interface': interfaces },
    failures: { [path]: new AuthError('secret-credential') } });
    const report = payload(await fixture.handlers['get_mesh_events']!({}));
    expect(report).toMatchObject({ status: 'observed', shown: 1, truncated: false,
      sources: { [path === 'show/mws/member' ? 'members' : 'interfaces']: 'authentication-error' } });
    expect(report.events[0][path === 'show/mws/member' ? 'toNode' : 'fromNode'].kind).toBe('unknown');
    expect(JSON.stringify(report)).not.toContain('secret-credential');
  });

  it('reports only unavailable on malformed rows with no usable event', async () => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: {
      '0': { mac: client, ap: 'not-a-mac', id: 'secret' }
    } } } });
    expect(payload(await fixture.handlers['get_mesh_events']!({}))).toMatchObject({
      status: 'unavailable', reason: 'unexpected-response', shown: 0, truncated: false,
      sources: { log: 'unexpected-response', members: 'not-requested', interfaces: 'not-requested' }
    });
    expect(fixture.order).toEqual(['POST /rci/show/mws/log']);
  });

  it('skips enrichment on empty, invalid or failed log reads', async () => {
    for (const [log, status] of [[{ log: {} }, 'observed'], [{ wrong: {} }, 'unavailable']] as const) {
      const fixture = setup({ values: { 'POST /rci/show/mws/log': log } });
      expect(payload(await fixture.handlers['get_mesh_events']!({}))).toMatchObject({ status, events: [],
        sources: { members: 'not-requested', interfaces: 'not-requested' } });
      expect(fixture.order).toEqual(['POST /rci/show/mws/log']);
    }
    const failed = setup({ failures: { 'POST /rci/show/mws/log': new AuthError('secret') } });
    expect(payload(await failed.handlers['get_mesh_events']!({}))).toMatchObject({ status: 'unavailable',
      reason: 'authentication-error', truncated: false });
    expect(failed.order).toEqual(['POST /rci/show/mws/log']);
  });

  it('marks actual entry and output trimming only', async () => {
    const log = { log: Object.fromEntries(Array.from({ length: 21 }, (_, index) => [String(index), event])) };
    const fixture = setup({ values: { 'POST /rci/show/mws/log': log } });
    expect(payload(await fixture.handlers['get_mesh_events']!({}))).toMatchObject({ shown: 20, truncated: true });
    const small = setup({ values: { 'POST /rci/show/mws/log': log }, maxBytes: 300 });
    const output = await small.handlers['get_mesh_events']!({});
    expect(Buffer.byteLength(output.content[0]!.text!, 'utf8')).toBeLessThanOrEqual(300);
    expect(payload(output)).toMatchObject({ shown: 0, truncated: true, sources: { log: null } });
  });

  it('skips both optional reads when a single valid event cannot fit the output cap', async () => {
    const fixture = setup({ values: { 'POST /rci/show/mws/log': { log: { '0': event } } }, maxBytes: 300 });
    const output = await fixture.handlers['get_mesh_events']!({});
    expect(fixture.order).toEqual(['POST /rci/show/mws/log']);
    expect(fixture.readMeshLog).toHaveBeenCalledTimes(1);
    expect(fixture.get).not.toHaveBeenCalled();
    expect(payload(output)).toMatchObject({ status: 'observed', reason: null, events: [], shown: 0,
      truncated: true, sources: { log: null, members: 'not-requested', interfaces: 'not-requested' } });
    expect(Buffer.byteLength(output.content[0]!.text!, 'utf8')).toBeLessThanOrEqual(300);
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
