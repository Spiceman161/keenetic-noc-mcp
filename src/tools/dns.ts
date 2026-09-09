import type { McpServer } from '@modelcontextprotocol/server';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';
const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};

export function projectDns(raw: unknown): Record<string, unknown> {
  const root = record(raw); const proxy = record(root['proxy-status'] ?? root['dns-proxy'] ?? root);
  const candidates = proxy['server'] ?? proxy['servers'] ?? proxy['upstream'];
  const values = Array.isArray(candidates) ? candidates : Object.values(record(candidates));
  const upstreamResolvers = values.map(v => { const r = record(v); return {
    address: r['address'] ?? r['server'] ?? null, protocol: r['protocol'] ?? r['type'] ?? null,
    tlsServerName: r['tls-name'] ?? r['sni'] ?? null, status: r['status'] ?? r['state'] ?? null
  }; });
  const hosts = proxy['host'] ?? root['host'];
  return { status: proxy['status'] ?? proxy['state'] ?? (proxy['enabled'] === false ? 'disabled' : 'unknown'),
    enabled: proxy['enabled'] ?? null, upstreamResolvers, staticHostsCount: Array.isArray(hosts) ? hosts.length : Object.keys(record(hosts)).length,
    errors: proxy['error'] ?? proxy['errors'] ?? [] };
}
export function registerDnsTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool('get_dns_status', { title: 'DNS proxy status', description: 'Compact DNS proxy state, upstream resolvers, encrypted-DNS metadata, static host count, and relevant errors.', inputSchema: {}, annotations: READ_ONLY }, guard(async () => ok(projectDns(await ctx.client.rci.get('show/dns-proxy')))));
}
