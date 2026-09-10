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
  transport: 'rci';
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

function unavailable(
  metadata: RciProbeMetadata,
  reason: ConfigCapabilityReason
): ConfigCapabilityProbe {
  return { available: false, transport: 'rci', ...metadata, reason };
}

async function probe(reader: ProbeReader, path: string): Promise<ConfigCapabilityProbe> {
  try {
    const metadata = await reader.probeGet(path);
    if (metadata.httpStatus === 403) return unavailable(metadata, 'capability-denied');
    if (metadata.httpStatus === 404) return unavailable(metadata, 'not-found');
    if (metadata.httpStatus < 200 || metadata.httpStatus >= 300) return unavailable(metadata, 'http-error');
    if (metadata.payloadShape === 'unknown' || metadata.payloadItems === 0) {
      return unavailable(metadata, 'unexpected-shape');
    }
    return { available: true, transport: 'rci', ...metadata, reason: null };
  } catch (error) {
    if (error instanceof RemoteCapabilityError) {
      return {
        available: false,
        transport: 'rci',
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
        transport: 'rci',
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
  const runningConfig = await probe(reader, 'show/running-config');
  const startupConfig = await probe(reader, 'more?filename=startup-config');
  return { runningConfig, startupConfig };
}
