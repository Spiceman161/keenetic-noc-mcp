import { readCliConfig } from './config-reader.js';
import { parseSavedChecksum, readLastChange } from './config-state.js';
import type { KeeneticClient } from './client.js';
import { AuthError, NotSupportedError, RciError, RemoteCapabilityError, TransportError } from './errors.js';
import {
  projectDeviceSnapshot,
  projectDnsSnapshot,
  projectInterfaceSnapshots,
  projectRouteSnapshot,
  projectSystemSnapshot,
  projectWifiSnapshot,
  snapshotAvailable,
  snapshotUnavailable,
  type ConfigurationSnapshot,
  type RouterSnapshotV1,
  type SnapshotSource
} from '../shape/router-snapshot.js';
import type { SafeReason } from '../shape/internet-diagnostic.js';
import { isDnsRuntimeShape } from '../shape/dns-diagnostic.js';

const LIMITS = {
  system: 64_000,
  lastChange: 64_000,
  interfaces: 256_000,
  routes: 256_000,
  dns: 128_000,
  associations: 256_000,
  hotspot: 256_000
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeReason(error: unknown): SafeReason {
  if (error instanceof AuthError) return 'authentication-error';
  if (error instanceof TransportError) return 'transport-error';
  if (error instanceof NotSupportedError || error instanceof RemoteCapabilityError) return 'not-supported';
  if (error instanceof RciError) return error.code === 'response-too-large'
    ? 'response-too-large' : 'rci-error';
  return 'unexpected-response';
}

interface AttemptState { sessionFailure: AuthError | TransportError | null }

async function attempt<T>(
  state: AttemptState,
  operation: () => Promise<unknown>,
  valid: (value: unknown) => boolean,
  project: (value: unknown) => T
): Promise<{ source: SnapshotSource<T>; raw: unknown | null }> {
  if (state.sessionFailure !== null) {
    return { source: snapshotUnavailable(safeReason(state.sessionFailure)), raw: null };
  }
  try {
    const value = await operation();
    if (!valid(value)) return { source: snapshotUnavailable('unexpected-response'), raw: null };
    return { source: snapshotAvailable(project(value)), raw: value };
  } catch (error) {
    if (error instanceof AuthError || error instanceof TransportError) state.sessionFailure = error;
    return { source: snapshotUnavailable(safeReason(error)), raw: null };
  }
}

function checksum(value: string | null): string | null {
  return value !== null && /^[0-9a-f]{32}$/i.test(value) ? value.toLowerCase() : null;
}

async function configurationSnapshot(
  client: KeeneticClient,
  state: AttemptState
): Promise<SnapshotSource<ConfigurationSnapshot>> {
  if (state.sessionFailure !== null) return snapshotUnavailable(safeReason(state.sessionFailure));
  let last;
  try {
    last = await readLastChange(client.rci, LIMITS.lastChange);
  } catch (error) {
    if (error instanceof AuthError || error instanceof TransportError) state.sessionFailure = error;
    return snapshotUnavailable(safeReason(error));
  }

  let savedChecksum: string | null = null;
  let savedState: ConfigurationSnapshot['savedState'] = 'unknown';
  let savedReason: string | null = null;
  try {
    const startup = await readCliConfig(client, 'startup');
    if (startup.available) {
      savedChecksum = parseSavedChecksum(startup.lines);
      savedState = savedChecksum === null ? 'unknown' : 'available';
      savedReason = savedChecksum === null ? 'unexpected-response' : null;
    } else {
      savedState = startup.state;
      savedReason = startup.reason;
    }
  } catch (error) {
    if (error instanceof AuthError || error instanceof TransportError) state.sessionFailure = error;
    savedReason = safeReason(error);
    savedState = 'unknown';
  }
  const runningChecksum = checksum(last.checksum);
  if (runningChecksum === null) return snapshotUnavailable('unexpected-response');
  return snapshotAvailable({
    runningChecksum,
    savedChecksum,
    unsavedChanges: runningChecksum === null || savedChecksum === null
      ? null : runningChecksum !== savedChecksum,
    savedState,
    savedReason
  });
}

/** Collects a privacy-minimized point-in-time state summary. */
export async function collectRouterSnapshot(
  client: KeeneticClient,
  now: () => Date = () => new Date()
): Promise<RouterSnapshotV1> {
  // A failed sentinel means there is no trustworthy current router observation.
  const capabilities = await client.capabilities();
  const state: AttemptState = { sessionFailure: null };
  const system = await attempt(state,
    () => client.rci.get('show/system', LIMITS.system),
    value => isRecord(value) && Object.keys(value).length > 0,
    value => projectSystemSnapshot(value, capabilities.firmware));
  const configuration = await configurationSnapshot(client, state);
  const interfaces = await attempt(state,
    () => client.rci.get('show/interface', LIMITS.interfaces),
    value => isRecord(value) && Object.values(value).every(isRecord),
    projectInterfaceSnapshots);
  const routes = await attempt(state,
    () => client.rci.get('show/ip/route', LIMITS.routes),
    value => Array.isArray(value) && value.every(item => isRecord(item) &&
      typeof item['destination'] === 'string'),
    value => projectRouteSnapshot(value, interfaces.raw ?? {}));
  const dns = await attempt(state,
    () => client.rci.get('show/dns-proxy', LIMITS.dns), isDnsRuntimeShape, projectDnsSnapshot);
  const wifi = await attempt(state,
    () => client.rci.get('show/associations', LIMITS.associations),
    value => isRecord(value) && Array.isArray(value['station']) && value['station'].every(isRecord),
    projectWifiSnapshot);
  const devices = await attempt(state,
    () => client.rci.get('show/ip/hotspot', LIMITS.hotspot),
    value => isRecord(value) && Array.isArray(value['host']) && value['host'].every(isRecord),
    projectDeviceSnapshot);

  const interfaceData = interfaces.source.status === 'available' ? interfaces.source.data : null;
  const sources: RouterSnapshotV1['sources'] = {
    system: system.source,
    configuration,
    interfaces: interfaceData === null
      ? snapshotUnavailable(interfaces.source.reason ?? 'unexpected-response')
      : snapshotAvailable(interfaceData.interfaces),
    routes: routes.source,
    dns: dns.source,
    vpn: interfaceData === null
      ? snapshotUnavailable(interfaces.source.reason ?? 'unexpected-response')
      : snapshotAvailable(interfaceData.vpn),
    wifi: wifi.source,
    devices: devices.source
  };
  const complete = Object.values(sources).every(source => source.status === 'available') &&
    sources.configuration.data?.runningChecksum !== null &&
    sources.configuration.data?.savedState === 'available';
  return { schemaVersion: 1, at: now().toISOString(), complete, sources };
}
