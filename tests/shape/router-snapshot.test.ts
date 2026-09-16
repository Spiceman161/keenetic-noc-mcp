import { describe, expect, it } from 'vitest';
import {
  projectDnsSnapshot,
  projectInterfaceSnapshots,
  projectRouteSnapshot,
  projectSystemSnapshot
} from '../../src/shape/router-snapshot.js';
import { projectInterfaces } from '../../src/shape/internet-diagnostic.js';

describe('router snapshot projections', () => {
  it('keeps only normalized system values', () => {
    expect(projectSystemSnapshot({ uptime: '120', cpuload: 7, memfree: 2048 },
      'KeeneticOS 5.1.4')).toEqual({
      firmware: '5.1.4', uptimeSeconds: 120, cpuLoad: 7, memoryFreeKb: 2048
    });
    expect(projectSystemSnapshot({}, 'KeeneticOS 198.51.100.7').firmware).toBeNull();
    expect(projectSystemSnapshot({}, '5.1.4-private-host').firmware).toBeNull();
    expect(projectSystemSnapshot({}, '5.1.4\npassword=secret').firmware).toBeNull();
  });

  it('aggregates interfaces and VPNs without retaining identifiers or peer data', () => {
    const raw = {
      'WifiMaster0/AccessPoint0': { type: 'AccessPoint', state: 'up', ssid: 'Private SSID' },
      PrivateTunnel: { type: 'Wireguard', link: 'down', description: 'secret', wireguard: {
        'private-key': 'private-sentinel', 'public-key': 'interface-public-sentinel', peer: [{
          online: true, 'public-key': 'peer-public-sentinel', description: 'peer-description-sentinel',
          'preshared-key': 'psk-sentinel', 'remote-address': 'endpoint-sentinel',
          'allowed-ips': ['allowed-ips-sentinel'], 'last-handshake': 'handshake-sentinel',
          rxbytes: 'rx-counter-sentinel', via: 'via-sentinel'
        }]
      } },
      Provider0: { type: 'PPPoE', role: 'inet', connected: true, address: '192.0.2.10' }
    };
    const projected = projectInterfaceSnapshots(raw);
    expect(projected.interfaces.byKind.wifi).toEqual({ total: 1, up: 1, down: 0, unknown: 0 });
    expect(projected.interfaces.byKind.wan.total).toBe(1);
    expect(projected.vpn).toMatchObject({ total: 1, up: 0, down: 1, unknown: 0,
      peersTotal: 1, peersOnline: 0, peersUnknown: 1 });
    const text = JSON.stringify(projected);
    expect(text).not.toMatch(/Private|WifiMaster|Wireguard|sentinel/);
  });

  it.each([
    ['missing', {}, 0],
    ['empty nested', { wireguard: { peer: [] } }, 0],
    ['nested array', { wireguard: { peer: [{ online: true, via: 'via-sentinel' }] } }, 1],
    ['direct array', { peer: [{ link: 'down' }, null] }, 2],
    ['keyed alias', { peers: { first: { online: true }, second: { 'last-handshake': 'sentinel' } } }, 2],
    ['partial keyed nested', { wireguard: { peer: { first: { endpoint: 'sentinel' }, second: null } } }, 2],
    ['malformed scalar', { peer: true }, 0]
  ])('keeps %s peer cardinality unknown in diagnostic and snapshot projections', (_shape, fields, peersTotal) => {
    const raw = { Wireguard0: { type: 'Wireguard', ...fields } };
    const diagnostic = projectInterfaces(raw).vpn.items[0]!;
    const snapshot = projectInterfaceSnapshots(raw).vpn;
    expect(diagnostic).toMatchObject({ peersTotal, peersKnown: 0, peersOnline: 0, underlayInterfaces: [] });
    expect(snapshot).toMatchObject({ peersTotal, peersOnline: 0, peersUnknown: peersTotal });
    expect(JSON.stringify({ diagnostic, snapshot })).not.toContain('sentinel');
  });

  it('uses exact VPN types and counts keyed peers without inspecting their state', () => {
    const projected = projectInterfaceSnapshots({
      Exact: { type: 'OpenVPN', peer: { first: { online: true }, second: { link: 'down' } } },
      NameOnlyWireguard: { type: 'FutureVPN', wireguard: { peer: [{ online: true }] } },
      Excluded: { type: 'OpenConnect', peer: [{ online: true }] },
      Malformed: { type: { name: 'Wireguard' } }
    });
    expect(projected.interfaces.byKind.vpn.total).toBe(1);
    expect(projected.vpn).toMatchObject({ total: 1, peersTotal: 2, peersOnline: 0, peersUnknown: 2 });
  });

  it.each([
    ['OpenConnect0', 'OpenConnect'], ['Gre0', 'GRE'], ['NameHint', 'FutureVPN'],
    ['Lowercase', 'wireguard'], ['CaseVariant', 'WireGuard'], ['Whitespace', ' Wireguard '],
    ['Empty', ''], ['MissingType', undefined], ['NullType', null], ['NumberType', 1],
    ['BooleanType', true], ['ObjectType', { name: 'Wireguard' }], ['ArrayType', ['Wireguard']]
  ])('keeps an unproven %s default route unknown whether it is up or down', (_id, type) => {
    for (const state of ['up', 'down']) {
      const interfaces = { [_id]: { type, state, link: state, global: true, defaultgw: true } };
      const route = [{ destination: '0.0.0.0/0', interface: _id }];
      expect(projectInterfaceSnapshots(interfaces).vpn.total).toBe(0);
      expect(projectRouteSnapshot(route, interfaces)).toMatchObject({ activePath: 'unknown' });
    }
  });

  it('reduces routes and DNS to aggregate state', () => {
    const interfaces = {
      Tunnel9: { type: 'Wireguard', state: 'up' },
      Provider0: { type: 'PPPoE', role: 'inet', state: 'up' }
    };
    expect(projectRouteSnapshot([
      { destination: '0.0.0.0/0', interface: 'Tunnel9', metric: 10, gateway: '198.51.100.1' }
    ], interfaces)).toEqual({ total: 1, usable: 1, rejecting: 0, activePath: 'vpn' });
    expect(projectRouteSnapshot([
      { destination: '0.0.0.0/0', interface: 'Provider0' }
    ], interfaces)).toMatchObject({ activePath: 'unknown' });
    expect(projectDnsSnapshot({ 'proxy-status': { enabled: true, status: 'running',
      server: [{ address: '203.0.113.53', status: 'up' }], host: { private: {} } } })).toEqual({
      enabled: true, state: 'healthy', upstreamsTotal: 1, upstreamsHealthy: 1,
      upstreamsUnhealthy: 0, upstreamsUnknown: 0, staticHostsCount: 1, errorCount: 0
    });
    expect(projectDnsSnapshot({ 'proxy-status': [{
      'proxy-name': 'private',
      'proxy-tls': { 'server-tls': [{ address: '203.0.113.53' }] },
      'proxy-https': { 'server-https': [{ uri: 'https://private.example/path' }] }
    }] })).toMatchObject({ state: 'unknown', upstreamsTotal: 2, upstreamsUnknown: 2 });
  });
});
