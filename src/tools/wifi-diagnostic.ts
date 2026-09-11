import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { hotspotHosts, resolveDeviceRecord, validateDeviceSelector } from '../router/device-state.js';
import { AuthError, NotSupportedError, RciError, TransportError } from '../router/errors.js';
import type { SafeReason } from '../shape/internet-diagnostic.js';
import {
  budgetWifiClientHealth,
  budgetWifiDiagnostic,
  buildWifiClientHealth,
  buildWifiDiagnostic,
  projectWifiClientEvidence,
  projectWifiTopology
} from '../shape/wifi-diagnostic.js';
import { compactOk, guard, READ_ONLY, type ToolContext } from './registry.js';

const INPUT_LIMITS = { version: 64_000, interfaces: 256_000, associations: 256_000, hotspot: 256_000 } as const;

const selectorSchema = z.union([
  z.strictObject({ mac: z.string().trim().min(1).max(64).describe('Exact MAC address, any case.') }),
  z.strictObject({ ip: z.string().trim().min(1).max(64).describe('Exact current IPv4 address.') }),
  z.strictObject({ name: z.string().trim().min(1).max(256).describe('Registered device name or hostname.') })
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isAssociations(value: unknown): value is { station: Array<Record<string, unknown>> } {
  return isRecord(value) && Array.isArray(value['station']) && value['station'].every(isRecord);
}

function isInterfaces(value: unknown): value is Record<string, Record<string, unknown>> {
  return isRecord(value) && Object.values(value).every(isRecord);
}

function safeReason(error: unknown): SafeReason {
  if (error instanceof AuthError) return 'authentication-error';
  if (error instanceof TransportError) return 'transport-error';
  if (error instanceof NotSupportedError) return 'not-supported';
  if (error instanceof RciError) return error.code === 'response-too-large' ? 'response-too-large' : 'rci-error';
  return 'unexpected-response';
}

interface ReadResult {
  value: unknown;
  state: 'available' | 'unavailable';
  reason: SafeReason | null;
}

function skipped(error: TransportError): ReadResult {
  return { value: null, state: 'unavailable', reason: safeReason(error) };
}

async function read(
  operation: () => Promise<unknown>,
  valid: (value: unknown) => boolean,
  latch: { transport: TransportError | null }
): Promise<ReadResult> {
  if (latch.transport !== null) return skipped(latch.transport);
  try {
    const value = await operation();
    return valid(value)
      ? { value, state: 'available', reason: null }
      : { value: null, state: 'unavailable', reason: 'unexpected-response' };
  } catch (error) {
    if (error instanceof AuthError) throw error;
    if (error instanceof TransportError) latch.transport = error;
    return { value: null, state: 'unavailable', reason: safeReason(error) };
  }
}

export async function collectWifiDiagnostic(ctx: ToolContext) {
  const latch = { transport: null as TransportError | null };
  const version = await read(() => ctx.client.rci.get('show/version', INPUT_LIMITS.version), isRecord, latch);
  const interfaces = await read(() => ctx.client.rci.get('show/interface', INPUT_LIMITS.interfaces), isInterfaces, latch);
  const associations = await read(() => ctx.client.rci.get('show/associations', INPUT_LIMITS.associations), isAssociations, latch);
  const topology = projectWifiTopology(interfaces.value ?? {}, associations.value ?? { station: [] }, {
    version: version.state, interfaces: interfaces.state, associations: associations.state,
    ...(version.reason === null ? {} : { versionReason: version.reason }),
    ...(interfaces.reason === null ? {} : { interfacesReason: interfaces.reason }),
    ...(associations.reason === null ? {} : { associationsReason: associations.reason })
  });
  return buildWifiDiagnostic({ topology: { status: 'available', reason: null, data: topology } });
}

export async function collectWifiClientHealth(
  ctx: ToolContext,
  selector: { mac?: string | undefined; ip?: string | undefined; name?: string | undefined }
) {
  validateDeviceSelector(selector, true);
  const hotspotRaw = await ctx.client.rci.get('show/ip/hotspot', INPUT_LIMITS.hotspot);
  const hosts = hotspotHosts(hotspotRaw);
  if (hosts === null) throw new RciError('Unexpected device-state response.', {
    path: 'show/ip/hotspot', code: 'unexpected-response', ident: 'rci'
  });
  const host = resolveDeviceRecord(hosts, selector, true);
  if (host === undefined) throw new RciError(
    'No device matched. Call list_devices to find its exact name, IP or MAC address.',
    { path: 'show/ip/hotspot', code: 'not-found', ident: 'device' }
  );
  const latch = { transport: null as TransportError | null };
  const associations = await read(() => ctx.client.rci.get('show/associations', INPUT_LIMITS.associations), isAssociations, latch);
  const interfaces = await read(() => ctx.client.rci.get('show/interface', INPUT_LIMITS.interfaces), isInterfaces, latch);
  const evidence = projectWifiClientEvidence(host, associations.value ?? { station: [] }, interfaces.value ?? {}, {
    associations: associations.state, interfaces: interfaces.state,
    ...(associations.reason === null ? {} : { associationsReason: associations.reason }),
    ...(interfaces.reason === null ? {} : { interfacesReason: interfaces.reason })
  });
  return buildWifiClientHealth(evidence);
}

export function registerWifiDiagnosticTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool('diagnose_wifi', {
    title: 'Diagnose Wi-Fi health',
    description: 'Aggregates bounded radio, access-point, association and signal health without exposing client identifiers, SSIDs or BSSIDs.',
    inputSchema: {}, annotations: READ_ONLY
  }, guard(async () => compactOk(
    budgetWifiDiagnostic(await collectWifiDiagnostic(ctx), ctx.maxResponseBytes), ctx.maxResponseBytes
  )));

  server.registerTool('get_wifi_client_health', {
    title: 'Diagnose one Wi-Fi client',
    description: 'Resolves exactly one known device and reports its bounded Wi-Fi association, signal, access-point and radio evidence without active traffic.',
    inputSchema: selectorSchema, annotations: READ_ONLY
  }, guard(async selector => compactOk(
    budgetWifiClientHealth(await collectWifiClientHealth(ctx, selector), ctx.maxResponseBytes), ctx.maxResponseBytes
  )));
}
