import { ValidationError } from './errors.js';

export type HostRecord = Record<string, unknown>;

export interface DeviceSelector {
  mac?: string | undefined;
  ip?: string | undefined;
  name?: string | undefined;
}

const SELECTOR_LIMITS = { mac: 64, ip: 64, name: 256 } as const;

/** Name lookup is forgiving about display casing and spaces, but nothing else. */
export function normalizeDeviceName(value: string): string {
  return value.normalize('NFKC').toLowerCase().replace(/\s+/gu, '');
}

function selectorEntries(selector: DeviceSelector): Array<['mac' | 'ip' | 'name', string]> {
  const entries = (Object.entries(selector) as Array<[keyof DeviceSelector, string | undefined]>)
    .filter((entry): entry is [keyof DeviceSelector, string] =>
      typeof entry[1] === 'string' && entry[1].trim() !== '');
  return entries;
}

export function validateDeviceSelector(selector: DeviceSelector, exactlyOne = false): void {
  const entries = selectorEntries(selector);
  if (entries.length === 0 || exactlyOne && entries.length !== 1) {
    throw new ValidationError('Supply exactly one of mac, ip or name to identify the device.');
  }
  if (exactlyOne) {
    for (const [kind, value] of entries) {
      if (value.length > SELECTOR_LIMITS[kind]) {
        throw new ValidationError(`The device ${kind} selector is too long.`);
      }
    }
  }
}

/** Resolves an already bounded hotspot listing without leaking sibling records. */
export function resolveDeviceRecord(
  hosts: readonly HostRecord[],
  selector: DeviceSelector,
  exactlyOne = false
): HostRecord | undefined {
  validateDeviceSelector(selector, exactlyOne);
  const entries = selectorEntries(selector).map(([kind, raw]) => [
    kind,
    kind === 'name' ? normalizeDeviceName(raw) : kind === 'mac' ? raw.toLowerCase() : raw
  ] as const);
  const matches = hosts.filter(host => entries.some(([kind, wanted]) => {
    if (kind === 'mac') return typeof host['mac'] === 'string' &&
      host['mac'].toLowerCase() === wanted;
    if (kind === 'ip') return host['ip'] === wanted;
    return ['name', 'hostname'].some(field => typeof host[field] === 'string' &&
      normalizeDeviceName(host[field]) === wanted);
  }));
  if (matches.length > 1) {
    throw new ValidationError(
      'The device selector is ambiguous after normalization. Supply its exact IP or MAC address.'
    );
  }
  return matches[0];
}

/** Compatibility resolver for tools with one free-form MAC/IP/name argument. */
export function resolveDeviceText(hosts: readonly HostRecord[], value: string): HostRecord | undefined {
  if (value.trim() === '') throw new ValidationError('Device selector must not be blank.');
  if (value.length > SELECTOR_LIMITS.name) throw new ValidationError('Device selector is too long.');
  const wanted = normalizeDeviceName(value);
  const matches = hosts.filter(host => ['mac', 'ip', 'name', 'hostname'].some(field =>
    typeof host[field] === 'string' && normalizeDeviceName(host[field]) === wanted));
  if (matches.length > 1) {
    throw new ValidationError(
      'The device selector is ambiguous after normalization. Supply its exact IP or MAC address.'
    );
  }
  return matches[0];
}

export function deviceAliases(host: HostRecord): string[] {
  return [...new Set(['mac', 'ip', 'name', 'hostname']
    .map(key => host[key])
    .filter((value): value is string => typeof value === 'string' && value.trim() !== ''))];
}

export function hotspotHosts(raw: unknown): HostRecord[] | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const hosts = (raw as Record<string, unknown>)['host'];
  if (!Array.isArray(hosts) || !hosts.every(item => item && typeof item === 'object' && !Array.isArray(item))) {
    return null;
  }
  return hosts as HostRecord[];
}
