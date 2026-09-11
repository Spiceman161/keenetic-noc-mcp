import type { SafeReason } from './internet-diagnostic.js';

export type SnapshotSource<T> =
  | { status: 'available'; reason: null; data: T }
  | { status: 'unavailable'; reason: SafeReason; data: null };

export interface SystemSnapshot {
  firmware: string | null;
  uptimeSeconds: number | null;
  cpuLoad: number | null;
  memoryFreeKb: number | null;
}

export interface ConfigurationSnapshot {
  runningChecksum: string | null;
  savedChecksum: string | null;
  unsavedChanges: boolean | null;
  savedState: 'available' | 'unavailable' | 'unknown';
  savedReason: string | null;
}

export type InterfaceKind = 'wan' | 'lan' | 'wifi' | 'vpn' | 'bridge' | 'other';
export interface StateCounts { total: number; up: number; down: number; unknown: number }
export interface InterfaceSnapshot { total: number; byKind: Record<InterfaceKind, StateCounts> }
export interface VpnSnapshot extends StateCounts {
  peersTotal: number;
  peersOnline: number;
  peersUnknown: number;
}
export interface RouteSnapshot {
  total: number;
  usable: number;
  rejecting: number;
  activePath: 'physical' | 'vpn' | 'ambiguous' | 'none' | 'unknown';
}
export interface DnsSnapshot {
  enabled: boolean | null;
  state: 'healthy' | 'unhealthy' | 'unknown';
  upstreamsTotal: number;
  upstreamsHealthy: number;
  upstreamsUnhealthy: number;
  upstreamsUnknown: number;
  staticHostsCount: number;
  errorCount: number;
}
export interface WifiSnapshot { clientCount: number }
export interface DeviceSnapshot { deviceCount: number; activeCount: number }

export interface RouterSnapshotV1 {
  schemaVersion: 1;
  at: string;
  complete: boolean;
  sources: {
    system: SnapshotSource<SystemSnapshot>;
    configuration: SnapshotSource<ConfigurationSnapshot>;
    interfaces: SnapshotSource<InterfaceSnapshot>;
    routes: SnapshotSource<RouteSnapshot>;
    dns: SnapshotSource<DnsSnapshot>;
    vpn: SnapshotSource<VpnSnapshot>;
    wifi: SnapshotSource<WifiSnapshot>;
    devices: SnapshotSource<DeviceSnapshot>;
  };
}

const KINDS: readonly InterfaceKind[] = ['wan', 'lan', 'wifi', 'vpn', 'bridge', 'other'];
const VPN = /wireguard|ipsec|openvpn|l2tp|pptp|sstp|openconnect|vpn/i;
const DOWN = new Set(['down', 'error', 'failed', 'disabled', 'offline', 'unavailable']);
const UP = new Set(['up', 'running', 'online', 'connected', 'ready']);

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function finite(value: unknown, minimum = 0): number | null {
  const parsed = typeof value === 'number' ? value
    : typeof value === 'string' && value.trim() !== '' ? Number(value) : Number.NaN;
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : null;
}

function count(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value !== null && typeof value === 'object') return Object.keys(value).length;
  return value === undefined || value === null || value === '' ? 0 : 1;
}

function firmwareVersion(value: string): string | null {
  const match = /^\s*(?:KeeneticOS\s+)?(\d\.\d{1,3}(?:\.\d{1,3}){1,2})\s*$/.exec(value);
  return match?.[1] ?? null;
}

function stateOf(value: Record<string, unknown>): 'up' | 'down' | 'unknown' {
  if (value['connected'] === true) return 'up';
  if (value['connected'] === false) return 'down';
  const states = [value['state'], value['link']]
    .filter((item): item is string => typeof item === 'string')
    .map(item => item.toLowerCase());
  if (states.some(item => DOWN.has(item))) return 'down';
  if (states.some(item => UP.has(item))) return 'up';
  return 'unknown';
}

function interfaceKind(id: string, value: Record<string, unknown>): InterfaceKind {
  const type = typeof value['type'] === 'string' ? value['type'] : '';
  if (VPN.test(`${id} ${type}`)) return 'vpn';
  if (id.includes('WifiMaster') || /accesspoint|wifi/i.test(type)) return 'wifi';
  if (value['role'] === 'inet' || value['defaultgw'] === true) return 'wan';
  if (/bridge/i.test(type)) return 'bridge';
  if (/ethernet/i.test(type)) return 'lan';
  return 'other';
}

function blankCounts(): StateCounts { return { total: 0, up: 0, down: 0, unknown: 0 }; }

export function projectSystemSnapshot(raw: unknown, firmware: string): SystemSnapshot {
  const value = record(raw);
  return {
    firmware: firmwareVersion(firmware),
    uptimeSeconds: finite(value['uptime']),
    cpuLoad: finite(value['cpuload']),
    memoryFreeKb: finite(value['memfree'])
  };
}

export function projectInterfaceSnapshots(raw: unknown): {
  interfaces: InterfaceSnapshot;
  vpn: VpnSnapshot;
  kindsById: ReadonlyMap<string, InterfaceKind>;
} {
  const byKind = Object.fromEntries(KINDS.map(kind => [kind, blankCounts()])) as Record<InterfaceKind, StateCounts>;
  const kindsById = new Map<string, InterfaceKind>();
  const vpn: VpnSnapshot = { ...blankCounts(), peersTotal: 0, peersOnline: 0, peersUnknown: 0 };
  for (const [id, rawValue] of Object.entries(record(raw))) {
    const value = record(rawValue);
    const kind = interfaceKind(id, value);
    const state = stateOf(value);
    kindsById.set(id, kind);
    byKind[kind].total += 1;
    byKind[kind][state] += 1;
    if (kind !== 'vpn') continue;
    vpn.total += 1;
    vpn[state] += 1;
    const protocol = Object.keys(record(value['wireguard'])).length > 0 ? record(value['wireguard']) : value;
    const peersRaw = protocol['peer'] ?? protocol['peers'];
    const peers = Array.isArray(peersRaw) ? peersRaw : Object.values(record(peersRaw));
    vpn.peersTotal += peers.length;
    for (const rawPeer of peers) {
      const peer = record(rawPeer);
      const online = peer['online'] === true || peer['link'] === 'up'
        ? true : peer['online'] === false || peer['link'] === 'down' ? false : null;
      if (online === true) vpn.peersOnline += 1;
      if (online === null) vpn.peersUnknown += 1;
    }
  }
  const interfaces = { total: [...kindsById.keys()].length, byKind };
  return { interfaces, vpn, kindsById };
}

export function projectRouteSnapshot(
  raw: unknown,
  interfaces: unknown
): RouteSnapshot {
  const kinds = projectInterfaceSnapshots(interfaces).kindsById;
  const defaults = (Array.isArray(raw) ? raw : []).map(record)
    .filter(route => route['destination'] === '0.0.0.0/0');
  const usable = defaults.filter(route => route['rejecting'] !== true);
  let activePath: RouteSnapshot['activePath'];
  if (defaults.length === 0) activePath = 'none';
  else if (usable.length === 0) activePath = 'none';
  else if (usable.length > 1) activePath = 'ambiguous';
  else {
    const id = usable[0]?.['interface'];
    const kind = typeof id === 'string' ? kinds.get(id) : undefined;
    activePath = kind === 'vpn' ? 'vpn' : kind === undefined ? 'unknown' : 'physical';
  }
  return { total: defaults.length, usable: usable.length,
    rejecting: defaults.length - usable.length, activePath };
}

export function projectDnsSnapshot(raw: unknown): DnsSnapshot {
  const root = record(raw);
  if (Array.isArray(root['proxy-status'])) {
    const upstreams = root['proxy-status'].flatMap(rawProxy => {
      const proxy = record(rawProxy);
      const tls = record(proxy['proxy-tls'])['server-tls'];
      const https = record(proxy['proxy-https'])['server-https'];
      return [
        ...(Array.isArray(tls) ? tls : []),
        ...(Array.isArray(https) ? https : [])
      ];
    });
    return { enabled: null, state: 'unknown', upstreamsTotal: upstreams.length,
      upstreamsHealthy: 0, upstreamsUnhealthy: 0, upstreamsUnknown: upstreams.length,
      staticHostsCount: 0, errorCount: 0 };
  }
  const proxy = record(root['proxy-status'] ?? root['dns-proxy'] ?? root);
  const candidates = proxy['server'] ?? proxy['servers'] ?? proxy['upstream'];
  const upstreams = Array.isArray(candidates) ? candidates : Object.values(record(candidates));
  let upstreamsHealthy = 0;
  let upstreamsUnhealthy = 0;
  let upstreamsUnknown = 0;
  for (const item of upstreams.map(record)) {
    const state = typeof item['status'] === 'string' ? item['status'].toLowerCase()
      : typeof item['state'] === 'string' ? item['state'].toLowerCase() : '';
    if (UP.has(state)) upstreamsHealthy += 1;
    else if (DOWN.has(state)) upstreamsUnhealthy += 1;
    else upstreamsUnknown += 1;
  }
  const rawState = typeof proxy['status'] === 'string' ? proxy['status'].toLowerCase()
    : typeof proxy['state'] === 'string' ? proxy['state'].toLowerCase() : '';
  const errorCount = count(proxy['error'] ?? proxy['errors']);
  const enabled = typeof proxy['enabled'] === 'boolean' ? proxy['enabled'] : null;
  const state = enabled === false || DOWN.has(rawState) || errorCount > 0 ||
    (upstreams.length > 0 && upstreamsUnhealthy === upstreams.length) ? 'unhealthy'
    : UP.has(rawState) || upstreamsHealthy > 0 ? 'healthy' : 'unknown';
  return { enabled, state, upstreamsTotal: upstreams.length, upstreamsHealthy,
    upstreamsUnhealthy, upstreamsUnknown,
    staticHostsCount: count(proxy['host'] ?? root['host']), errorCount };
}

export function projectWifiSnapshot(raw: unknown): WifiSnapshot {
  const station = record(raw)['station'];
  return { clientCount: Array.isArray(station) ? station.length : 0 };
}

export function projectDeviceSnapshot(raw: unknown): DeviceSnapshot {
  const hosts = record(raw)['host'];
  const rows = Array.isArray(hosts) ? hosts.map(record) : [];
  return { deviceCount: rows.length, activeCount: rows.filter(row => row['active'] === true).length };
}

export function snapshotAvailable<T>(data: T): SnapshotSource<T> {
  return { status: 'available', reason: null, data };
}

export function snapshotUnavailable<T>(reason: SafeReason): SnapshotSource<T> {
  return { status: 'unavailable', reason, data: null };
}
