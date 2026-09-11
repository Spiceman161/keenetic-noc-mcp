import { describe, expect, it } from 'vitest';
import {
  projectDnsSnapshot,
  projectInterfaceSnapshots,
  projectRouteSnapshot,
  projectSystemSnapshot
} from '../../src/shape/router-snapshot.js';

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
        peer: [{ online: true, 'public-key': 'DO-NOT-STORE', 'remote-address': '198.51.100.7' }]
      } },
      Provider0: { type: 'PPPoE', role: 'inet', connected: true, address: '192.0.2.10' }
    };
    const projected = projectInterfaceSnapshots(raw);
    expect(projected.interfaces.byKind.wifi).toEqual({ total: 1, up: 1, down: 0, unknown: 0 });
    expect(projected.interfaces.byKind.wan.total).toBe(1);
    expect(projected.vpn).toMatchObject({ total: 1, up: 0, down: 1, unknown: 0,
      peersTotal: 1, peersOnline: 1, peersUnknown: 0 });
    const text = JSON.stringify(projected);
    expect(text).not.toMatch(/Private|WifiMaster|Wireguard|DO-NOT-STORE|198\.51/);
  });

  it('reduces routes and DNS to aggregate state', () => {
    const interfaces = {
      Tunnel9: { type: 'Wireguard', state: 'up' },
      Provider0: { type: 'PPPoE', role: 'inet', state: 'up' }
    };
    expect(projectRouteSnapshot([
      { destination: '0.0.0.0/0', interface: 'Tunnel9', metric: 10, gateway: '198.51.100.1' }
    ], interfaces)).toEqual({ total: 1, usable: 1, rejecting: 0, activePath: 'vpn' });
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
