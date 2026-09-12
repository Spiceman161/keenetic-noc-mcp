import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import {
  deviceAliases,
  hotspotHosts,
  resolveDeviceRecord,
  validateDeviceSelector
} from '../router/device-state.js';
import { AuthError, NotSupportedError, RciError, TransportError } from '../router/errors.js';
import {
  budgetDeviceDiagnostic,
  buildDeviceDiagnostic,
  projectDeviceAccess,
  projectDeviceAddress,
  projectDeviceConnection,
  projectDeviceDnsContext,
  projectDeviceIdentity,
  projectDeviceLogs,
  projectDeviceRoutingPolicy,
  projectDeviceWifi,
  projectDhcpBinding,
  type DeviceDiagnosticEvidence,
  type DeviceRoutingPolicyEvidence
} from '../shape/device-diagnostic.js';
import { available, unavailable, type Evidence, type SafeReason } from '../shape/internet-diagnostic.js';
import { readLogEntries, type LogEntry } from './logs.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const INPUT_LIMITS = {
  version: 64_000,
  hotspot: 256_000,
  dhcp: 256_000,
  associations: 256_000,
  interfaces: 256_000,
  policies: 128_000,
  internet: 64_000,
  logs: 2_000_000
} as const;

const deviceSelectorSchema = z.union([
  z.strictObject({ mac: z.string().trim().min(1).max(64).describe('Exact MAC address, any case.') }),
  z.strictObject({ ip: z.string().trim().min(1).max(64).describe('Exact current IPv4 address.') }),
  z.strictObject({ name: z.string().trim().min(1).max(256).describe('Registered device name or hostname.') })
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function recordRows(value: unknown): value is Array<Record<string, unknown>> {
  return Array.isArray(value) && value.every(isRecord);
}

export function isDhcpBindingsShape(value: unknown): value is { lease: Array<Record<string, unknown>> } {
  if (!isRecord(value) || !recordRows(value['lease'])) return false;
  return value['lease'].every(row => typeof row['mac'] === 'string' &&
    (row['expires'] === undefined || typeof row['expires'] === 'string' ||
      typeof row['expires'] === 'number'));
}

function isAssociationsShape(value: unknown): boolean {
  return isRecord(value) && recordRows(value['station']);
}

function isInternetShape(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const keys = ['checked', 'dns-accessible', 'internet'];
  return keys.some(key => value[key] !== undefined) && keys.every(key =>
    value[key] === undefined || typeof value[key] === 'boolean' || key === 'checked' && typeof value[key] === 'string');
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

export async function collectDeviceDiagnosticEvidence(
  ctx: ToolContext,
  selector: { mac?: string | undefined; ip?: string | undefined; name?: string | undefined }
): Promise<DeviceDiagnosticEvidence> {
  validateDeviceSelector(selector, true);
  // A fresh version read proves that cached capability data is not being used
  // as evidence for the current session.
  try {
    await ctx.client.rci.get('show/version', INPUT_LIMITS.version);
  } catch (error) {
    if (error instanceof AuthError || error instanceof TransportError) throw error;
  }

  // Identity is the required core source. A partial report about the wrong or
  // missing device would be actively misleading, so this read is fatal.
  const hotspotRaw = await ctx.client.rci.get('show/ip/hotspot', INPUT_LIMITS.hotspot);
  const hosts = hotspotHosts(hotspotRaw);
  if (hosts === null) throw new RciError('Unexpected device-state response.', {
    path: 'show/ip/hotspot', code: 'unexpected-response', ident: 'rci'
  });
  const host = resolveDeviceRecord(hosts, selector, true);
  if (host === undefined) {
    throw new RciError(
      'No device matched. Call list_devices to find its exact name, IP or MAC address.',
      { path: 'show/ip/hotspot', code: 'not-found', ident: 'device' }
    );
  }
  const mac = typeof host['mac'] === 'string' ? host['mac'] : '';

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

  const dhcpResult = await poll(() => ctx.client.rci.get('show/ip/dhcp/bindings', INPUT_LIMITS.dhcp));
  const associationsResult = await poll(() => ctx.client.rci.get('show/associations', INPUT_LIMITS.associations));
  const interfacesResult = await poll(() => ctx.client.rci.get('show/interface', INPUT_LIMITS.interfaces));
  const policiesResult = await poll(() => ctx.client.rci.get('ip/policy', INPUT_LIMITS.policies));
  const internetResult = await poll(() => ctx.client.rci.get('show/internet/status', INPUT_LIMITS.internet));

  const dhcpBinding = projected(dhcpResult, isDhcpBindingsShape,
    value => projectDhcpBinding((value as { lease: Array<Record<string, unknown>> }).lease, mac));
  const associations = projected(associationsResult, isAssociationsShape, value => value);
  const interfaces = projected(interfacesResult, isRecord, value => value);
  const policies = projected(policiesResult, isRecord, value => value);
  const dnsContext = projected(internetResult, isInternetShape, projectDeviceDnsContext);

  const interfaceAvailable = interfaces.status === 'available';
  const connection = available(projectDeviceConnection(host, interfaces.data ?? {}, interfaceAvailable));
  const wifi = available(projectDeviceWifi(host, associations.data ?? { station: [] }, interfaces.data ?? {},
    associations.status === 'available', interfaceAvailable));
  const routingPolicy = policies.status === 'available'
    ? available(projectDeviceRoutingPolicy(host, policies.data, interfaces.data ?? {}, interfaceAvailable))
    : unavailable<DeviceRoutingPolicyEvidence>(
      policies.reason ?? 'unexpected-response');

  // Logs are largest and slowest on KeeneticOS 5.x. Read them only after all
  // core state, and never let their untrusted text create findings.
  const logsResult = await poll(() => readLogEntries(ctx, INPUT_LIMITS.logs));
  const logs = projected<LogEntry[], ReturnType<typeof projectDeviceLogs>>(
    logsResult, Array.isArray, value => projectDeviceLogs(value, deviceAliases(host)));

  return {
    identity: available(projectDeviceIdentity(host)),
    address: available(projectDeviceAddress(host)),
    dhcpBinding,
    connection,
    wifi,
    access: available(projectDeviceAccess(host)),
    routingPolicy,
    dnsContext,
    logs
  };
}

export function registerDeviceDiagnosticTool(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool(
    'diagnose_device',
    {
      title: 'Diagnose one network device',
      description:
        'Combines bounded identity, address, DHCP, connection, Wi-Fi, access, routing-policy, ' +
        'router-wide DNS and recent-log evidence for one device without sending active traffic.',
      inputSchema: deviceSelectorSchema,
      annotations: READ_ONLY
    },
    guard(async selector => {
      const evidence = await collectDeviceDiagnosticEvidence(ctx, selector);
      return ok(budgetDeviceDiagnostic(buildDeviceDiagnostic(evidence), ctx.maxResponseBytes), ctx.maxResponseBytes);
    })
  );
}
