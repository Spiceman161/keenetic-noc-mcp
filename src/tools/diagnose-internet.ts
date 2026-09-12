import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { parseCapabilities, type Capabilities } from '../router/capabilities.js';
import { readConfigState } from '../router/config-state.js';
import { AuthError, NotSupportedError, RciError, TransportError } from '../router/errors.js';
import {
  available,
  budgetInternetDiagnostic,
  buildInternetDiagnostic,
  projectConfiguration,
  projectDefaultRoutes,
  projectDns,
  projectInterfaces,
  projectInternet,
  projectRelatedLogs,
  projectSystem,
  relatedInterfaceIds,
  unavailable,
  type DiagnosticEvidence,
  type Evidence,
  type SafeReason
} from '../shape/internet-diagnostic.js';
import { readLogEntries, type LogEntry } from './logs.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const INPUT_LIMITS = {
  system: 64_000,
  internet: 64_000,
  interfaces: 256_000,
  routes: 256_000,
  dns: 128_000,
  lastChange: 64_000,
  startup: 256_000,
  logs: 256_000
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasRecordContent(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).length > 0;
}

function isRouteArray(value: unknown): value is Array<Record<string, unknown>> {
  return Array.isArray(value) && value.every(row => {
    if (!isRecord(row) || typeof row['destination'] !== 'string' || row['destination'].trim() === '') {
      return false;
    }
    return row['destination'] !== '0.0.0.0/0' ||
      (typeof row['interface'] === 'string' && row['interface'].trim() !== '');
  });
}

function reason(error: unknown): SafeReason {
  if (error instanceof AuthError) return 'authentication-error';
  if (error instanceof TransportError) return 'transport-error';
  if (error instanceof NotSupportedError) return 'not-supported';
  if (error instanceof RciError) {
    return error.code === 'response-too-large' ? 'response-too-large' : 'rci-error';
  }
  return 'unexpected-response';
}

function fromSettled<T, U>(
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

async function settle<T>(operation: () => Promise<T>): Promise<PromiseSettledResult<T>> {
  try {
    return { status: 'fulfilled', value: await operation() };
  } catch (reason) {
    return { status: 'rejected', reason };
  }
}

export function registerInternetDiagnosticTool(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool(
    'diagnose_internet',
    {
      title: 'Diagnose internet connectivity',
      description:
        'Combines bounded system, uplink, IPv4 route, DNS, VPN, configuration and recent-log ' +
        'evidence into deterministic findings for internet-down or internet-slow incidents.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(ctx, async () => {
      // This is the whole-router sentinel. Authentication or transport failure
      // here means none of the later partial evidence can be trusted as current.
      let capabilities: Capabilities;
      let versionAvailable = false;
      try {
        const version = await ctx.client.rci.get<Record<string, unknown>>(
          'show/version', INPUT_LIMITS.system
        );
        capabilities = parseCapabilities(version);
        versionAvailable = Boolean(capabilities.model || capabilities.hwId || capabilities.firmware);
      } catch (error) {
        if (error instanceof AuthError || error instanceof TransportError) throw error;
        capabilities = {
          model: '', hwId: '', firmware: '', components: new Set(), features: new Set()
        };
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
      // KeenDNS can serialize requests internally. Concurrent reads make fast,
      // essential signals miss their deadlines while the large log response is
      // in flight. A transport failure latches the session unavailable so later
      // reads do not multiply the per-request deadline.
      const systemResult = await poll(() =>
        ctx.client.rci.get<Record<string, unknown>>('show/system', INPUT_LIMITS.system));
      const internetResult = await poll(() =>
        ctx.client.rci.get<Record<string, unknown>>('show/internet/status', INPUT_LIMITS.internet));
      const interfacesResult = await poll(() =>
        ctx.client.rci.get<Record<string, unknown>>('show/interface', INPUT_LIMITS.interfaces));
      const routesResult = await poll(() =>
        ctx.client.rci.get<unknown[]>('show/ip/route', INPUT_LIMITS.routes));
      const dnsResult = await poll(() =>
        ctx.client.rci.get<Record<string, unknown>>('show/dns-proxy', INPUT_LIMITS.dns));
      const configurationResult = await poll(() =>
        readConfigState(ctx.client.rci, {
          lastChangeBytes: INPUT_LIMITS.lastChange,
          startupBytes: INPUT_LIMITS.startup,
          skipStartup: ctx.connection?.mode === 'remote',
          propagateSessionErrors: true
        }));

      const system = fromSettled(systemResult, hasRecordContent,
        value => projectSystem(value, capabilities, versionAvailable));
      const internet = fromSettled(internetResult, hasRecordContent, projectInternet);
      const routes = fromSettled(routesResult, isRouteArray, projectDefaultRoutes);
      const dns = fromSettled(dnsResult, hasRecordContent, projectDns);
      const configuration = fromSettled(configurationResult, isRecord, projectConfiguration);

      const interfaceProjection: Evidence<ReturnType<typeof projectInterfaces>> = fromSettled<
        Record<string, unknown>,
        ReturnType<typeof projectInterfaces>
      >(interfacesResult, hasRecordContent, projectInterfaces);
      const interfaces: DiagnosticEvidence['interfaces'] = interfaceProjection.status === 'available' && interfaceProjection.data !== null
        ? available(interfaceProjection.data.interfaces)
        : unavailable(interfaceProjection.reason ?? 'unexpected-response');
      const vpn: DiagnosticEvidence['vpn'] = interfaceProjection.status === 'available' && interfaceProjection.data !== null
        ? available(interfaceProjection.data.vpn)
        : unavailable(interfaceProjection.reason ?? 'unexpected-response');

      const interfaceIds = relatedInterfaceIds(
        internet.data,
        routes.data,
        interfaces.data,
        vpn.data
      );
      // Logs are the slowest and largest source. Read them only after all core
      // evidence is safely collected so a timeout cannot starve those checks.
      const logsResult = await poll(() => readLogEntries(ctx, INPUT_LIMITS.logs));
      const logs = fromSettled<LogEntry[], ReturnType<typeof projectRelatedLogs>>(
        logsResult,
        Array.isArray,
        value => projectRelatedLogs(value, interfaceIds)
      );

      const evidence: DiagnosticEvidence = {
        system,
        internet,
        interfaces,
        routes,
        dns,
        vpn,
        logs,
        configuration
      };
      const report = budgetInternetDiagnostic(buildInternetDiagnostic(evidence), ctx.maxResponseBytes);
      return ok(report, ctx.maxResponseBytes);
    })
  );
}
