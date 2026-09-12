import type { Rci } from './rci.js';
import { RciError } from './errors.js';

export interface Capabilities {
  model: string;
  hwId: string;
  firmware: string;
  components: ReadonlySet<string>;
  features: ReadonlySet<string>;
}

function splitList(value: unknown): Set<string> {
  if (typeof value !== 'string' || value.length === 0) return new Set();
  return new Set(
    value
      .split(',')
      .map(part => part.trim())
      .filter(part => part.length > 0)
  );
}

function readString(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  return typeof value === 'string' ? value : '';
}

/** Shapes `show/version` into the capability set the tool registry gates on. */
export function parseCapabilities(version: unknown): Capabilities {
  if (typeof version !== 'object' || version === null || Array.isArray(version)) {
    throw new RciError('show/version returned an unexpected response', {
      path: 'show/version', code: 'unexpected-response', ident: 'rci'
    });
  }
  const root = version as Record<string, unknown>;
  const ndwRaw = root['ndw'];
  const ndw = (typeof ndwRaw === 'object' && ndwRaw !== null ? ndwRaw : {}) as Record<
    string,
    unknown
  >;

  const model = readString(root, 'model');
  const hwId = readString(root, 'hw_id');
  const firmware = readString(root, 'title');
  if (firmware.trim() === '' || model.trim() === '' && hwId.trim() === '') {
    throw new RciError('show/version did not identify a Keenetic router and firmware', {
      path: 'show/version', code: 'unexpected-response', ident: 'rci'
    });
  }
  return {
    model,
    hwId,
    firmware,
    components: splitList(ndw['components']),
    features: splitList(ndw['features'])
  };
}

export async function fetchCapabilities(rci: Rci): Promise<Capabilities> {
  return parseCapabilities(await rci.get('show/version', 64_000));
}
