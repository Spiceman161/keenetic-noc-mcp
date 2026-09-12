import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { readDnsConfigBranch } from '../router/dns-config.js';
import { AuthError, NotSupportedError, RciError, TransportError } from '../router/errors.js';
import { boundedArrayEnvelope } from '../shape/config.js';
import { isDnsConfigShape, isDnsRuntimeShape, projectDnsProxy, projectDnsUpstreams, type DnsUpstreamObservation } from '../shape/dns-diagnostic.js';
import type { SafeReason } from '../shape/internet-diagnostic.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';
const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};

export function projectDns(raw: unknown): Record<string, unknown> {
  if (isDnsRuntimeShape(raw) && Array.isArray(record(raw)['proxy-status'])) {
    const measured = projectDnsProxy(raw);
    return {
      status: measured.status ?? 'unknown',
      enabled: measured.enabled,
      upstreamResolvers: measured.upstreams.items.map(item => ({
        address: item.address,
        protocol: item.protocol,
        tlsServerName: item.tlsServerName,
        status: item.status,
        scope: item.scope,
        port: item.port,
        endpoint: item.endpoint,
        interface: item.interface
      })),
      staticHostsCount: measured.staticHostsCount,
      errors: []
    };
  }
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
export function registerDnsTools(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool('get_dns_status', { title: 'DNS proxy status', description: 'Compact DNS proxy state, upstream resolvers, encrypted-DNS metadata, static host count, and relevant errors.', inputSchema: {}, annotations: READ_ONLY }, guard(ctx, async () => ok(projectDns(await ctx.client.rci.get('show/dns-proxy', 128_000)), ctx.maxResponseBytes)));

  server.registerTool('list_dns_upstreams', {
    title: 'List DNS upstreams',
    description: 'Lists bounded, projected runtime and configured DNS upstream observations without merging unrelated router records.',
    inputSchema: {
      limit: z.number().int().min(1).max(100).optional().default(50)
        .describe('Maximum upstream observations. Defaults to 50.')
    },
    annotations: READ_ONLY
  }, guard(ctx, async ({ limit }) => {
    const sources: Record<string, { status: 'available' | 'unavailable'; reason: SafeReason | null }> = {};
    const upstreams: DnsUpstreamObservation[] = [];
    try {
      const raw = await ctx.client.rci.get('show/dns-proxy', 128_000);
      if (!isDnsRuntimeShape(raw)) {
        sources['runtime'] = { status: 'unavailable', reason: 'unexpected-response' };
      } else {
        const runtime = projectDnsProxy(raw);
        upstreams.push(...runtime.upstreams.items);
        sources['runtime'] = { status: 'available', reason: null };
      }
    } catch (error) {
      if (error instanceof AuthError || error instanceof TransportError) throw error;
      sources['runtime'] = { status: 'unavailable', reason: dnsReason(error) };
    }

    for (const [path, source] of [
      ['dns-proxy', 'dns-proxy-config'],
      ['ip/name-server', 'name-server-config']
    ] as const) {
      let value: unknown;
      try {
        value = (await readDnsConfigBranch(ctx.client, path)).value;
      } catch (error) {
        if (error instanceof AuthError || error instanceof TransportError) throw error;
        sources[source] = { status: 'unavailable', reason: dnsReason(error) };
        continue;
      }
      if (!isDnsConfigShape(value, source)) {
        sources[source] = { status: 'unavailable', reason: 'unexpected-response' };
        continue;
      }
      upstreams.push(...projectDnsUpstreams(value,
        source === 'dns-proxy-config' ? 'dns-proxy-config' : 'name-server-config'));
      sources[source] = { status: 'available', reason: null };
    }
    const selected = upstreams.slice(0, limit);
    return ok(boundedArrayEnvelope({ schemaVersion: 1, sources }, 'upstreams', selected,
      ctx.maxResponseBytes, upstreams.length, selected.length < upstreams.length), ctx.maxResponseBytes);
  }));
}

function dnsReason(error: unknown): SafeReason {
  if (error instanceof NotSupportedError) return 'not-supported';
  if (error instanceof RciError) return error.code === 'response-too-large' ? 'response-too-large' : 'rci-error';
  if (error instanceof TransportError) return 'transport-error';
  if (error instanceof AuthError) return 'authentication-error';
  return 'unexpected-response';
}
