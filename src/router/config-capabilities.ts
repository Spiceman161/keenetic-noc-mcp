import { RemoteCapabilityError, RciError } from './errors.js';
import type {
  Rci, RciContentTypeClass, RciPayloadItemShape, RciProbeMetadata, RciResponseShape
} from './rci.js';

export type ConfigCapabilityReason =
  | 'capability-denied'
  | 'not-found'
  | 'http-error'
  | 'rci-error'
  | 'unexpected-shape';

export interface ConfigCapabilityProbe {
  available: boolean;
  transport: 'rci' | 'http';
  httpStatus: number | null;
  contentTypeClass: RciContentTypeClass;
  shape: RciResponseShape;
  items: number | null;
  bytes: number | null;
  payloadShape: RciResponseShape;
  payloadItems: number | null;
  payloadItemShape: RciPayloadItemShape;
  wrapperDepth: number;
  reason: ConfigCapabilityReason | null;
}

export interface ConfigCapabilities {
  runningConfig: ConfigCapabilityProbe;
  startupConfig: ConfigCapabilityProbe;
}

type ProbeReader = Pick<Rci, 'probeGet'>;
type OperationalProbeReader = Pick<Rci, 'probeGet' | 'probeStartupFile'>;

export type CapabilityState = 'available' | 'unavailable' | 'unknown';
export type CapabilityReason =
  | 'not-probed'
  | 'denied'
  | 'not-found'
  | 'http-error'
  | 'rci-error'
  | 'unexpected-response'
  | null;

export interface CapabilityAccess<M extends string> {
  state: CapabilityState;
  method: M | null;
  reason: CapabilityReason;
}

export interface ProbedCapabilities {
  config: {
    runningCli: CapabilityAccess<'rci-show'>;
    runningStructured: CapabilityAccess<'rci-root'>;
    startup: CapabilityAccess<'rci-more' | 'ci-file'>;
    backup: CapabilityAccess<'ci-file'>;
  };
}

function unavailable(
  metadata: RciProbeMetadata,
  reason: ConfigCapabilityReason,
  transport: 'rci' | 'http'
): ConfigCapabilityProbe {
  return { available: false, transport, ...metadata, reason };
}

async function probe(
  read: () => Promise<RciProbeMetadata>,
  transport: 'rci' | 'http' = 'rci'
): Promise<ConfigCapabilityProbe> {
  try {
    const metadata = await read();
    if (metadata.httpStatus === 403) return unavailable(metadata, 'capability-denied', transport);
    if (metadata.httpStatus === 404) return unavailable(metadata, 'not-found', transport);
    if (metadata.httpStatus < 200 || metadata.httpStatus >= 300) return unavailable(metadata, 'http-error', transport);
    if (metadata.payloadShape === 'unknown' || metadata.payloadItems === 0) {
      return unavailable(metadata, 'unexpected-shape', transport);
    }
    return { available: true, transport, ...metadata, reason: null };
  } catch (error) {
    if (error instanceof RemoteCapabilityError) {
      return {
        available: false,
        transport,
        httpStatus: 403,
        contentTypeClass: 'unknown',
        shape: 'unknown',
        items: null,
        bytes: null,
        payloadShape: 'unknown',
        payloadItems: null,
        payloadItemShape: 'unknown',
        wrapperDepth: 0,
        reason: 'capability-denied'
      };
    }
    if (error instanceof RciError) {
      return {
        available: false,
        transport,
        httpStatus: error.code === '404' ? 404 : null,
        contentTypeClass: 'unknown',
        shape: 'unknown',
        items: null,
        bytes: null,
        payloadShape: 'unknown',
        payloadItems: null,
        payloadItemShape: 'unknown',
        wrapperDepth: 0,
        reason: error.code === '404' ? 'not-found' : 'rci-error'
      };
    }
    throw error;
  }
}

/** Probes read-only configuration surfaces without exposing their payloads. */
export async function probeConfigCapabilities(reader: ProbeReader): Promise<ConfigCapabilities> {
  const runningConfig = await probe(() => reader.probeGet('show/running-config', 256_000));
  const startupConfig = await probe(() => reader.probeGet('more?filename=startup-config', 256_000));
  return { runningConfig, startupConfig };
}

function access<M extends string>(
  result: ConfigCapabilityProbe,
  method: M
): CapabilityAccess<M> {
  if (result.available) return { state: 'available', method, reason: null };
  if (result.reason === 'capability-denied') {
    return { state: 'unavailable', method: null, reason: 'denied' };
  }
  if (result.reason === 'not-found') {
    return { state: 'unavailable', method: null, reason: 'not-found' };
  }
  const reason = result.reason === 'unexpected-shape'
    ? 'unexpected-response'
    : result.reason;
  return { state: 'unknown', method: null, reason };
}

function selectStartup(
  rci: CapabilityAccess<'rci-more'>,
  file: CapabilityAccess<'ci-file'> | null
): CapabilityAccess<'rci-more' | 'ci-file'> {
  if (rci.state === 'available') return rci;
  if (file?.state === 'available') return file;
  const uncertain = [rci, file].find(candidate => candidate?.state === 'unknown');
  if (uncertain) return { state: 'unknown', method: null, reason: uncertain.reason };
  if (rci.reason === 'denied' || file?.reason === 'denied') {
    return { state: 'unavailable', method: null, reason: 'denied' };
  }
  return { state: 'unavailable', method: null, reason: file?.reason ?? rci.reason };
}

function configShape(
  result: ConfigCapabilityProbe,
  source: 'rci' | 'file'
): ConfigCapabilityProbe {
  if (!result.available) return result;
  const valid = source === 'file'
    ? result.payloadShape === 'string' && result.contentTypeClass !== 'json'
    : result.contentTypeClass === 'json' && (result.payloadShape === 'string' ||
      (result.payloadShape === 'array' && result.payloadItemShape === 'string'));
  return valid ? result : { ...result, available: false, reason: 'unexpected-shape' };
}

/** Builds the session capability model without returning configuration payloads. */
export async function probeOperationalCapabilities(
  reader: OperationalProbeReader,
  mode: 'lan' | 'remote'
): Promise<ProbedCapabilities & { readonly retryable: boolean }> {
  const runningProbe = configShape(
    await probe(() => reader.probeGet('show/running-config', 256_000)),
    'rci'
  );
  const startupRciProbe = configShape(await probe(
    () => reader.probeGet('more?filename=startup-config', 256_000)
  ), 'rci');
  const startupFileProbe = mode === 'lan'
    ? configShape(await probe(() => reader.probeStartupFile(256_000), 'http'), 'file')
    : null;
  const running = access(runningProbe, 'rci-show');
  const startupRci = access(startupRciProbe, 'rci-more');
  const startupFile = startupFileProbe === null ? null : access(startupFileProbe, 'ci-file');
  return {
    retryable: [runningProbe, startupRciProbe, startupFileProbe].some(result =>
      result?.reason === 'http-error' || result?.reason === 'rci-error' ||
        result?.reason === 'unexpected-shape'
    ),
    config: {
      runningCli: running,
      runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
      startup: selectStartup(startupRci, startupFile),
      backup: startupFile ?? { state: 'unknown', method: null, reason: 'not-probed' }
    }
  };
}

export function hasRecoverableCapabilityFailure(capabilities: ProbedCapabilities): boolean {
  if ('retryable' in capabilities && capabilities.retryable === true) return true;
  return Object.values(capabilities.config).some(value =>
    value.reason === 'http-error' || value.reason === 'rci-error' ||
      value.reason === 'unexpected-response'
  );
}
