import type { McpServer } from '@modelcontextprotocol/server';
import { readDnsConfigBranch } from '../router/dns-config.js';
import { AuthError, NotSupportedError, RciError, TransportError } from '../router/errors.js';
import {
  budgetDnsDiagnostic,
  buildDnsDiagnostic,
  isDnsConfigShape,
  isDnsRuntimeShape,
  projectDnsInternet,
  projectDnsLogs,
  projectDnsProxy,
  projectDnsRoutes,
  projectDnsUpstreams,
  type DnsDiagnosticEvidence
} from '../shape/dns-diagnostic.js';
import { available, unavailable, type Evidence, type SafeReason } from '../shape/internet-diagnostic.js';
import { readLogEntries, type LogEntry } from './logs.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const INPUT_LIMITS = {
  version: 64_000,
  internet: 64_000,
  dns: 128_000,
  routes: 256_000,
  interfaces: 256_000,
  // KeeneticOS 5.1.3 exposes a fixed 4000-row dispatcher response. The live
  // tupik sample is about 863 KiB, so retain a hard 2 MB input ceiling while
  // projecting only the final 20 DNS-related rows below.
  logs: 2_000_000
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasRecordContent(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).length > 0;
}

function isInternetShape(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const keys = ['checked', 'enabled', 'reliable', 'gateway-accessible', 'dns-accessible', 'internet'] as const;
  if (!keys.some(key => value[key] !== undefined)) return false;
  if (value['checked'] !== undefined && typeof value['checked'] !== 'boolean' && typeof value['checked'] !== 'string') return false;
  return keys.slice(1).every(key => value[key] === undefined || typeof value[key] === 'boolean');
}

function isRouteShape(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.every(row => isRecord(row) && typeof row['destination'] === 'string');
}

function reason(error: unknown): SafeReason {
  if (error instanceof AuthError) return 'authentication-error';
  if (error instanceof TransportError) return 'transport-error';
  if (error instanceof NotSupportedError) return 'not-supported';
  if (error instanceof RciError) return error.code === 'response-too-large' ? 'response-too-large' : 'rci-error';
  return 'unexpected-response';
}

async function settle<T>(operation: () => Promise<T>): Promise<PromiseSettledResult<T>> {
  try {
    return { status: 'fulfilled', value: await operation() };
  } catch (reason) {
    return { status: 'rejected', reason };
  }
}

function projected<T, U>(
  result: PromiseSettledResult<T>,
  valid: (value: T) => boolean,
  project: (value: T) => U
): Evidence<U> {
  if (result.status === 'rejected') return unavailable(reason(result.reason));
  if (!valid(result.value)) return unavailable('unexpected-response');
  try {
    return available(project(result.value));
  } catch {
    return unavailable('unexpected-response');
  }
}

export async function collectDnsDiagnosticEvidence(ctx: ToolContext): Promise<DnsDiagnosticEvidence> {
  // A fresh version read is the whole-router sentinel. Cached capabilities
  // cannot prove that this diagnostic session is still reachable.
  try {
    await ctx.client.rci.get('show/version', INPUT_LIMITS.version);
  } catch (error) {
    if (error instanceof AuthError || error instanceof TransportError) throw error;
  }

  let sessionFailure: TransportError | null = null;
  const poll = async <T>(operation: () => Promise<T>): Promise<PromiseSettledResult<T>> => {
    if (sessionFailure !== null) return { status: 'rejected', reason: sessionFailure };
    const result = await settle(operation);
    if (result.status === 'rejected') {
      if (result.reason instanceof AuthError) throw result.reason;
      if (result.reason instanceof TransportError) sessionFailure = result.reason;
    }
    return result;
  };

  const internetResult = await poll(() => ctx.client.rci.get('show/internet/status', INPUT_LIMITS.internet));
  const runtimeResult = await poll(() => ctx.client.rci.get('show/dns-proxy', INPUT_LIMITS.dns));
  const proxyConfigResult = await poll(() => readDnsConfigBranch(ctx.client, 'dns-proxy'));
  const nameServerResult = await poll(() => readDnsConfigBranch(ctx.client, 'ip/name-server'));
  const routesResult = await poll(() => ctx.client.rci.get('show/ip/route', INPUT_LIMITS.routes));
  const interfacesResult = await poll(() => ctx.client.rci.get('show/interface', INPUT_LIMITS.interfaces));

  const proxyRuntime = projected(runtimeResult, isDnsRuntimeShape, projectDnsProxy);
  const internetReachability = projected(internetResult, isInternetShape, projectDnsInternet);
  const dnsProxyConfig = projected(proxyConfigResult,
    value => isDnsConfigShape(value.value, 'dns-proxy-config'),
    value => {
      const items = projectDnsUpstreams(value.value, 'dns-proxy-config');
      return { items, shown: items.length, total: items.length, truncated: false };
    });
  const nameServerConfig = projected(nameServerResult,
    value => isDnsConfigShape(value.value, 'name-server-config'),
    value => {
      const items = projectDnsUpstreams(value.value, 'name-server-config');
      return { items, shown: items.length, total: items.length, truncated: false };
    });

  const upstreams = [
    ...(proxyRuntime.data?.upstreams.items ?? []),
    ...(dnsProxyConfig.data?.items ?? []),
    ...(nameServerConfig.data?.items ?? [])
  ];
  let routing: DnsDiagnosticEvidence['routing'];
  if (routesResult.status === 'rejected') routing = unavailable(reason(routesResult.reason));
  else if (interfacesResult.status === 'rejected') routing = unavailable(reason(interfacesResult.reason));
  else if (!isRouteShape(routesResult.value) || !hasRecordContent(interfacesResult.value)) {
    routing = unavailable('unexpected-response');
  } else {
    routing = available(projectDnsRoutes(upstreams, routesResult.value, interfacesResult.value));
  }

  // The dispatcher POST is a known read-only show command. Keep this last: a
  // large KeenDNS log response can otherwise starve the core DNS reads.
  const logsResult = await poll(() => readLogEntries(ctx, INPUT_LIMITS.logs));
  const logs = projected<LogEntry[], ReturnType<typeof projectDnsLogs>>(
    logsResult, Array.isArray, projectDnsLogs);
  return { proxyRuntime, internetReachability, dnsProxyConfig, nameServerConfig, routing, logs };
}

export function registerDnsDiagnosticTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'diagnose_dns',
    {
      title: 'Diagnose DNS',
      description:
        'Combines bounded DNS proxy, reachability, configured upstream, routing and recent-log ' +
        'evidence into deterministic findings without issuing an active DNS query.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(async () => {
      const evidence = await collectDnsDiagnosticEvidence(ctx);
      return ok(budgetDnsDiagnostic(buildDnsDiagnostic(evidence), ctx.maxResponseBytes), ctx.maxResponseBytes);
    })
  );
}
