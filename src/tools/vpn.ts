import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const VPN = /wireguard|ipsec|openvpn|l2tp|pptp|sstp|openconnect|vpn/i;
const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};

export function projectVpn(name: string, value: unknown): Record<string, unknown> {
  const item = record(value);
  // KeeneticOS 5.1 nests WireGuard-specific runtime state under `wireguard`.
  // Older captured shapes exposed the same fields directly, so retain both.
  const wireguard = record(item['wireguard']);
  const protocol = Object.keys(wireguard).length > 0 ? wireguard : item;
  const peersRaw = protocol['peer'] ?? protocol['peers'];
  const peerEntries = Array.isArray(peersRaw) ? peersRaw.map((v, i) => [String(i), v] as const) : Object.entries(record(peersRaw));
  const peers = peerEntries.map(([id, raw]) => {
    const peer = record(raw);
    return { description: peer['description'] ?? id, publicKey: peer['public-key'] ?? peer['publicKey'] ?? null,
      remoteEndpointAddress: peer['remote-endpoint-address'] ?? peer['remote-address'] ?? peer['endpoint-address'] ?? null,
      remotePort: peer['remote-port'] ?? peer['endpoint-port'] ?? null, online: peer['online'] ?? peer['link'] === 'up',
      rxBytes: peer['rxbytes'] ?? peer['rx-bytes'] ?? 0, txBytes: peer['txbytes'] ?? peer['tx-bytes'] ?? 0,
      lastHandshake: peer['last-handshake'] ?? null };
  });
  return { name, type: item['type'] ?? 'unknown', description: item['description'] ?? '', state: item['state'] ?? '',
    link: item['link'] ?? '', address: item['address'] ?? null, uptime: item['uptime'] ?? null,
    ...(String(item['type']).toLowerCase() === 'wireguard' ? { publicKey: protocol['public-key'] ?? null,
      listenPort: protocol['listen-port'] ?? protocol['port'] ?? null, peers } : {}) };
}

async function all(ctx: ToolContext): Promise<Array<Record<string, unknown>>> {
  const raw = record(await ctx.client.rci.get('show/interface'));
  return Object.entries(raw).filter(([name, value]) => VPN.test(`${name} ${record(value)['type'] ?? ''}`)).map(([name, value]) => projectVpn(name, value));
}

export function registerVpnTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool('list_vpn', { title: 'List VPN interfaces', description: 'Compact status for VPN interfaces and WireGuard peers. Secrets are always redacted.', inputSchema: {}, annotations: READ_ONLY }, guard(async () => ok({ vpn: await all(ctx) }, ctx.maxResponseBytes)));
  server.registerTool('get_vpn', { title: 'Get one VPN interface', description: 'Detailed projected state and protocol-specific runtime fields for one named VPN interface.', inputSchema: { name: z.string() }, annotations: READ_ONLY }, guard(async ({ name }) => {
    const found = (await all(ctx)).find(item => item['name'] === name);
    if (!found) throw new Error(`VPN interface "${name}" was not found. Call list_vpn.`);
    return ok(found, ctx.maxResponseBytes);
  }));
}
