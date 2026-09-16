import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { projectVpn } from '../../src/tools/vpn.js';
import { registerVpnTools } from '../../src/tools/vpn.js';
import { projectDns } from '../../src/tools/dns.js';
import { filterLogs, logLines } from '../../src/tools/logs.js';
import type { KeeneticClient } from '../../src/router/client.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

describe('v0.1 projections', () => {
  it('projects only seven interface-level VPN fields', () => {
    const result = projectVpn('Wireguard0', {
      type: 'Wireguard', description: 'safe-description', state: 'up', link: 'up',
      address: '198.51.100.8', uptime: 12, 'private-key': 'private-sentinel',
      wireguard: {
        'public-key': 'interface-public-sentinel', 'listen-port': 51820,
        peer: [{ description: 'peer-description-sentinel', 'public-key': 'peer-public-sentinel',
          'preshared-key': 'psk-sentinel', 'remote-endpoint-address': 'endpoint-sentinel',
          'allowed-ips': ['allowed-ips-sentinel'], 'last-handshake': 'handshake-sentinel',
          rxbytes: 12, via: 'via-sentinel', arbitrary: 'nested-sentinel' }]
      }
    });
    expect(result).toEqual({ name: 'Wireguard0', type: 'Wireguard', description: 'safe-description',
      state: 'up', link: 'up', address: '198.51.100.8', uptime: 12 });
    expect(JSON.stringify(result)).not.toMatch(/sentinel|listen-port|peer|public-key|private-key/i);
  });
  it('normalizes non-scalar interface values without copying them', () => {
    expect(projectVpn('Tunnel7', { type: 'FutureVPN', state: { nested: 'sentinel' } }))
      .toEqual({ name: 'Tunnel7', type: 'FutureVPN', description: '', state: '', link: '', address: null, uptime: null });
  });
  it('lists only all six exact types and keeps the fixed VPN-tool contract', async () => {
    const rows = Object.fromEntries([
      'Wireguard', 'OpenVPN', 'L2TP', 'PPTP', 'IPsec', 'Sstp'
    ].map(type => [`${type}0`, { type, description: 'safe', state: 'up', link: 'up', address: 'safe-address', uptime: 1 }])) as Record<string, unknown>;
    rows['Wireguard0'] = { type: 'Wireguard', description: 'safe', state: 'up', link: 'up',
      address: 'safe-address', uptime: 1, wireguard: { 'private-key': 'private-sentinel',
        'public-key': 'interface-public-sentinel', peer: [{ description: 'peer-description-sentinel',
          'public-key': 'peer-public-sentinel', 'preshared-key': 'psk-sentinel',
          endpoint: 'endpoint-sentinel', 'allowed-ips': ['allowed-ips-sentinel'],
          'last-handshake': 'handshake-sentinel', rxbytes: 'counter-sentinel', via: 'via-sentinel' }] } };
    rows['NameOnly'] = { type: 'FutureVPN', wireguard: { peer: [{ 'public-key': 'peer-sentinel' }] } };
    rows['OpenConnect0'] = { type: 'OpenConnect' };
    for (const [index, type] of ['wireguard', 'WireGuard', ' Wireguard ', '', '   ', null, 1, true,
      { name: 'Wireguard' }, ['Wireguard']].entries()) {
      rows[`Malformed${index}`] = { type, description: 'wireguard vpn', wireguard: { peer: [{ online: true }] } };
    }
    const client = { rci: { get: vi.fn(async () => rows) } } as unknown as KeeneticClient;
    const ctx: ToolContext = { client, maxResponseBytes: 25_000, readOnly: true, backup: stubBackup() };
    const server = new McpServer({ name: 'test', version: '0.0.0' });
    let list: (() => Promise<ToolResult>) | undefined;
    let get: ((args: { name: string }) => Promise<ToolResult>) | undefined;
    const configs: Record<string, any> = {};
    vi.spyOn(server, 'registerTool').mockImplementation(((name: string, config: unknown, handler: unknown) => {
      configs[name] = config;
      if (name === 'list_vpn') list = handler as () => Promise<ToolResult>;
      if (name === 'get_vpn') get = handler as (args: { name: string }) => Promise<ToolResult>;
      return {} as never;
    }) as never);
    registerVpnTools(server, ctx);
    const output = JSON.parse((await list!()).content.map(part => part.text).join(''));
    expect(output.vpn.map((item: any) => item.type)).toEqual(['Wireguard', 'OpenVPN', 'L2TP', 'PPTP', 'IPsec', 'Sstp']);
    expect(Object.keys(output.vpn[0]).sort()).toEqual(['address', 'description', 'link', 'name', 'state', 'type', 'uptime']);
    expect(JSON.stringify(output)).not.toContain('peer-sentinel');
    for (const sentinel of ['private-sentinel', 'interface-public-sentinel', 'peer-description-sentinel',
      'peer-public-sentinel', 'psk-sentinel', 'endpoint-sentinel', 'allowed-ips-sentinel',
      'handshake-sentinel', 'counter-sentinel', 'via-sentinel']) expect(JSON.stringify(output)).not.toContain(sentinel);
    const single = JSON.parse((await get!({ name: 'Wireguard0' })).content.map(part => part.text).join(''));
    expect(single).toEqual(output.vpn[0]);
    expect((await get!({ name: 'NameOnly' })).isError).toBe(true);
    expect(configs['list_vpn'].annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    expect(configs['get_vpn'].annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });
  it('applies the VPN tool response ceiling', async () => {
    const rows = Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`Wireguard${index}`, {
      type: 'Wireguard', description: 'x'.repeat(500), state: 'up', link: 'up'
    }]));
    const client = { rci: { get: vi.fn(async () => rows) } } as unknown as KeeneticClient;
    const ctx: ToolContext = { client, maxResponseBytes: 300, readOnly: true, backup: stubBackup() };
    const server = new McpServer({ name: 'test', version: '0.0.0' });
    let list: (() => Promise<ToolResult>) | undefined;
    vi.spyOn(server, 'registerTool').mockImplementation(((name: string, _config: unknown, handler: unknown) => {
      if (name === 'list_vpn') list = handler as () => Promise<ToolResult>;
      return {} as never;
    }) as never);
    registerVpnTools(server, ctx);
    const result = await list!();
    const text = result.content.map(part => part.text).join('');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(300);
    expect(JSON.parse(text)).toMatchObject({ truncated: true });
  });
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
