import { describe, expect, it } from 'vitest';
import { projectVpn } from '../../src/tools/vpn.js';
import { projectDns } from '../../src/tools/dns.js';
import { filterLogs, logLines } from '../../src/tools/logs.js';

describe('v0.1 projections', () => {
  it('projects WireGuard peers without private material', () => {
    const result = projectVpn('Wireguard0', { type: 'Wireguard', 'private-key': 'must-not-leak', wireguard: { 'public-key': 'pub', peer: [{ description: 'vps', 'public-key': 'peer-pub', 'preshared-key': 'must-not-leak', online: true, rxbytes: 12, 'remote-endpoint-address': '192.0.2.8' }] } });
    expect(result).toMatchObject({ name: 'Wireguard0', publicKey: 'pub', peers: [{ description: 'vps', publicKey: 'peer-pub', online: true, rxBytes: 12, remoteEndpointAddress: '192.0.2.8' }] });
    expect(JSON.stringify(result)).not.toContain('must-not-leak');
  });
  it('keeps unknown VPN types parseable', () => expect(projectVpn('Tunnel7', { type: 'FutureVPN', state: 'up' })).toMatchObject({ type: 'FutureVPN', state: 'up' }));
  it('projects DNS resolvers and host count', () => expect(projectDns({ 'proxy-status': { enabled: true, server: [{ address: '192.0.2.53', protocol: 'DoT', sni: 'resolver.example' }], host: [{}, {}] } })).toMatchObject({ enabled: true, staticHostsCount: 2, upstreamResolvers: [{ protocol: 'DoT' }] }));
  it('parses, filters case-insensitively and bounds log tails', () => {
    const lines = logLines('00:01 ndm start\n00:02 Wireguard UP\n00:03 wireguard peer');
    expect(filterLogs(lines, { filter: 'WIREGUARD', lines: 1 })).toEqual(['00:03 wireguard peer']);
  });
  it('parses the keyed nested log shape returned by KeeneticOS 5.1.3', () => {
    const lines = logLines({ log: {
      '17': { timestamp: '2026-09-09T01:02:03Z', ident: 'Network', message: {
        level: 'notice', label: 'Interface', message: 'link is up'
      } }
    } });
    expect(lines).toEqual(['2026-09-09T01:02:03Z Network notice Interface link is up']);
  });
});
