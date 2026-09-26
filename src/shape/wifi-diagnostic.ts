import type { HostRecord } from '../router/device-state.js';
import { redact, redactText } from '../security/redact.js';
import type { Evidence, ListEvidence, SafeReason } from './internet-diagnostic.js';
import { available, unavailable } from './internet-diagnostic.js';

export type WifiCheckStatus = 'pass' | 'warning' | 'fail' | 'unknown' | 'not-applicable';
export type WifiReportStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown' | 'not-applicable';
type SourceState = 'available' | 'unavailable';

export interface WifiRadioSummary {
  id: string;
  state: string | null;
  connected: boolean | null;
  hardwareState: string | null;
  channel: number | null;
  channelWidthMhz: number | null;
}

export interface WifiAccessPointSummary {
  id: string;
  radioId: string | null;
  state: string | null;
  connected: boolean | null;
  enabled: boolean | null;
  clients: number;
}

export interface WifiClientAggregate {
  total: number;
  authenticated: number;
  unauthenticated: number;
  authenticationUnknown: number;
  missingAccessPoint: number;
  missingRadio: number;
}

export interface WifiTopology {
  sourceAvailability: { version: SourceState; interfaces: SourceState; associations: SourceState };
  sourceReasons: { version: SafeReason | null; interfaces: SafeReason | null; associations: SafeReason | null };
  totals: { radios: number | null; accessPoints: number | null; clients: number | null };
  radios: ListEvidence<WifiRadioSummary>;
  accessPoints: ListEvidence<WifiAccessPointSummary>;
  clients: WifiClientAggregate;
  signal: { good: number; usable: number; weak: number; unknown: number };
}

export interface WifiTelemetryAvailability {
  retryCounters: 'not-exposed';
  errorCounters: 'not-exposed';
  channelUtilization: 'not-exposed';
  deauthenticationReasons: 'not-exposed';
  roamingEvents: 'not-exposed';
  environmentScan: 'not-exposed';
}

export interface WifiCheck {
  id: 'sources' | 'radios' | 'access-points' | 'clients' | 'signal';
  status: WifiCheckStatus;
  summary: string;
}

export interface WifiFinding {
  id: 'weak-signal-clients' | 'unauthenticated-clients' | 'association-ap-missing' |
    'association-radio-missing';
  severity: 'critical' | 'warning';
  count: number;
  summary: string;
  relatedChecks: WifiCheck['id'][];
}

export interface WifiDiagnosticEvidence {
  topology: Evidence<WifiTopology>;
  telemetryAvailability: WifiTelemetryAvailability;
}

export interface WifiDiagnosticReport {
  schemaVersion: 1;
  status: WifiReportStatus;
  complete: boolean;
  checks: WifiCheck[];
  findings: WifiFinding[];
  evidence: WifiDiagnosticEvidence;
  untrustedRouterData: true;
  truncated: boolean;
}

export interface WifiClientIdentity {
  mac: string;
  ip: string | null;
  name: string | null;
  hostname: string | null;
  active: boolean | null;
}

export interface WifiClientConnection {
  kind: 'wireless' | 'wired' | 'unknown';
  apId: string | null;
  ssid: string | null;
}

export interface WifiAssociationEvidence {
  associated: boolean;
  authenticated: boolean | null;
  rssiDbm: number | null;
  signal: 'good' | 'usable' | 'weak' | 'unknown';
  txRateMbps: number | null;
  rxRateMbps: number | null;
  mode: string | null;
  channelWidthMhz: number | null;
  mcs: number | null;
  streams: number | null;
  txBytes: number | null;
  rxBytes: number | null;
  capabilities: string[];
  roam: string | null;
}

export interface WifiClientHealthEvidence {
  identity: Evidence<WifiClientIdentity>;
  connection: Evidence<WifiClientConnection>;
  association: Evidence<WifiAssociationEvidence>;
  accessPoint: Evidence<WifiAccessPointSummary>;
  radio: Evidence<WifiRadioSummary>;
  telemetryAvailability: WifiTelemetryAvailability;
}

export interface WifiClientCheck {
  id: 'connection' | 'association' | 'authentication' | 'signal' | 'access-point' | 'radio';
  status: WifiCheckStatus;
  summary: string;
}

export interface WifiClientFinding {
  id: 'wifi-association-missing' | 'wifi-not-authenticated' | 'wifi-signal-weak' |
    'wifi-access-point-missing' | 'wifi-radio-missing';
  severity: 'critical' | 'warning';
  summary: string;
  relatedChecks: WifiClientCheck['id'][];
}

export interface WifiClientHealthReport {
  schemaVersion: 1;
  status: WifiReportStatus;
  complete: boolean;
  checks: WifiClientCheck[];
  findings: WifiClientFinding[];
  evidence: WifiClientHealthEvidence;
  untrustedRouterData: true;
  truncated: boolean;
}

export interface MeshMember {
  ref: string;
  role: 'extender' | 'unknown';
  model: string | null;
  hwId: string | null;
  displayName: string | null;
  associationCount: number | null;
  firmware: string | null;
  parentKind: 'controller' | 'extender' | 'unknown';
  parentRef: string | null;
  backhaul: 'observed' | 'not-observed' | 'unknown';
  medium: 'wireless' | 'wired' | 'unknown';
  authenticated: boolean | null;
  backhaulDetails: { duplex: 'full' | null } | null;
  pollingError: boolean | null;
}

export interface MeshReport {
  schemaVersion: 1;
  status: 'observed' | 'unknown' | 'unavailable';
  reason: SafeReason | 'unverified-empty-array' | 'member-limit' | null;
  configuredMembers: number | null;
  members: MeshMember[];
  shown: number;
  controller: { status: 'derived' | 'unknown'; ref: 'controller' | null; model: string | null; firmware: string | null; associationCount: number | null };
  sources: { members: SafeReason | null; bridge: SafeReason | 'not-requested' | null; version: SafeReason | 'not-requested' | null; associations: SafeReason | 'not-requested' | null };
  truncated: boolean;
  untrustedRouterData: true;
}

const meshRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function meshIdentity(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/[:-]/g, '').toLowerCase();
  return /^[0-9a-f]{12}$/.test(normalized) ? normalized : null;
}

function meshSafeLabel(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const label = value.trim();
  return label.length > 0 && [...label].length <= 48 &&
    /^[\p{L}\p{N} _'()\-]+$/u.test(label) &&
    !/(?:password|passwd|passphrase|token|secret|private|credential|license|bearer|authorization|psk|key|cid)/i.test(label) &&
    !/^[0-9a-f]{12}$/i.test(label) &&
    !/(?:[0-9a-f]{2}-){5}[0-9a-f]{2}/i.test(label) &&
    !/(?:sk-|pk-|ghp_|gho_|xoxb-|AKIA[0-9A-Z]{16})/i.test(label) &&
    !/[\p{L}\p{N}]{20}/u.test(label)
    ? label : null;
}

function meshModel(value: unknown): string | null {
  const label = meshSafeLabel(value);
  return label !== null && (/^KN-\d{4}$/.test(label) ||
    /^[\p{L}][\p{L}\p{N} -]{0,34} \(KN-\d{4}\)$/u.test(label)) ? label : null;
}

function meshFirmware(value: unknown): string | null {
  return typeof value === 'string' && /^\d{1,2}(?:\.\d{1,3}){1,3}$/.test(value) ? value : null;
}

function meshMedium(backhaul: Record<string, unknown> | null): 'wireless' | 'wired' | 'unknown' {
  const uplink = backhaul?.['uplink'];
  return typeof uplink === 'string' && /^WifiMaster\d+\/WifiStation\d+$/.test(uplink)
    ? 'wireless' : typeof uplink === 'string' && /^(?:FastEthernet|GigabitEthernet)\d+\/Vlan\d+$/.test(uplink)
      ? 'wired' : 'unknown';
}

function meshCurrent(row: Record<string, unknown>): boolean {
  const errors = meshRecord(row['rci']) ? row['rci']['errors'] : null;
  const backhaul = meshRecord(row['backhaul']) ? row['backhaul'] : null;
  return errors === 0 && meshMedium(backhaul) !== 'unknown';
}

export function validMeshMembers(value: unknown): value is Array<Record<string, unknown>> {
  return Array.isArray(value) && value.every(row => meshRecord(row) && meshIdentity(row['mac']) !== null &&
    (row['mode'] === undefined || typeof row['mode'] === 'string') &&
    (row['hw_type'] === undefined || typeof row['hw_type'] === 'string') &&
    (row['model'] === undefined || typeof row['model'] === 'string') &&
    (row['fw'] === undefined || typeof row['fw'] === 'string') &&
    (row['fw-release'] === undefined || typeof row['fw-release'] === 'string') &&
    (row['backhaul'] === undefined || (meshRecord(row['backhaul']) &&
      (row['backhaul']['bridge'] === undefined || typeof row['backhaul']['bridge'] === 'string') &&
      (row['backhaul']['uplink'] === undefined || typeof row['backhaul']['uplink'] === 'string') &&
      (row['backhaul']['authenticated'] === undefined || typeof row['backhaul']['authenticated'] === 'boolean'))) &&
    (row['rci'] === undefined || meshRecord(row['rci'])));
}

export function meshParentMarker(rows: Array<Record<string, unknown>>): boolean {
  return rows.some(row => {
    if (!meshCurrent(row)) return false;
    const bridge = meshRecord(row['backhaul']) ? row['backhaul']['bridge'] : null;
    return typeof bridge === 'string' && /^8000[.]([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(bridge);
  });
}

export function projectMeshMembers(
  rows: Array<Record<string, unknown>>,
  bridge: unknown = null,
  version: unknown = null
): MeshReport {
  const localIdentity = meshRecord(bridge) ? meshIdentity(bridge['mac']) : null;
  const identities = rows.map(row => meshIdentity(row['mac']));
  const parents = rows.map(row => {
    if (!meshCurrent(row)) {
      return { kind: 'unknown' as const, identity: null };
    }
    const backhaul = meshRecord(row['backhaul']) ? row['backhaul'] : null;
    const raw = backhaul?.['bridge'];
    if (typeof raw !== 'string') return { kind: 'unknown' as const, identity: null };
    const match = /^(8000|e000)[.]((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$/i.exec(raw);
    return match ? { kind: match[1]!.toLowerCase() === '8000' ? 'controller' as const : 'extender' as const,
      identity: meshIdentity(match[2]) } : { kind: 'unknown' as const, identity: null };
  });
  const controllerMatches = localIdentity === null ? 0 : parents.filter(parent =>
    parent.kind === 'controller' && parent.identity === localIdentity).length;
  const controllerDerived = controllerMatches > 0;
  const members: MeshMember[] = rows.map((row, index) => {
    const backhaul = meshRecord(row['backhaul']) ? row['backhaul'] : null;
    const rci = meshRecord(row['rci']) ? row['rci'] : null;
    const errors = rci?.['errors'];
    const pollingError = typeof errors === 'number' && Number.isInteger(errors) && errors >= 0
      ? errors > 0 : null;
    const medium = meshMedium(backhaul);
    const current = meshCurrent(row);
    const parent = parents[index]!;
    const matches = parent.kind === 'extender' && parent.identity !== null
      ? identities.flatMap((identity, position) => identity === parent.identity && position !== index ? [position] : []) : [];
    return {
      ref: `member-${index + 1}`,
      role: row['mode'] === 'extender' && row['hw_type'] === 'extender' ? 'extender' : 'unknown',
      model: meshModel(row['model']),
      hwId: typeof row['hw_id'] === 'string' && /^KN-\d{4}$/.test(row['hw_id']) ? row['hw_id'] : null,
      displayName: meshSafeLabel(row['known-host']),
      associationCount: typeof row['associations'] === 'number' && Number.isSafeInteger(row['associations']) &&
        row['associations'] >= 0 && row['associations'] <= 100_000 ? row['associations'] : null,
      firmware: current ? meshFirmware(row['fw-release']) ?? meshFirmware(row['fw']) : null,
      parentKind: parent.kind,
      parentRef: parent.kind === 'controller' && controllerDerived && parent.identity === localIdentity
        ? 'controller' : parent.kind === 'extender' && matches.length === 1 ? `member-${matches[0]! + 1}` : null,
      backhaul: current ? 'observed' : backhaul === null && row['fw'] === undefined &&
        row['fw-release'] === undefined && row['rci'] === undefined ? 'not-observed' : 'unknown',
      medium: current ? medium : 'unknown',
      authenticated: current && typeof backhaul?.['authenticated'] === 'boolean' ? backhaul['authenticated'] as boolean : null,
      backhaulDetails: current && medium === 'wired'
        ? { duplex: backhaul?.['duplex'] === 'full' ? 'full' : null } : null,
      pollingError
    };
  });
  return {
    schemaVersion: 1, status: 'observed', reason: null, configuredMembers: rows.length,
    members, shown: members.length,
    controller: { status: controllerDerived ? 'derived' : 'unknown', ref: controllerDerived ? 'controller' : null,
      model: controllerDerived && meshRecord(version) ? meshModel(version['model']) : null,
      firmware: controllerDerived && meshRecord(version) ? meshFirmware(version['release'] ?? version['title']) : null,
      associationCount: null },
    sources: { members: null, bridge: 'not-requested', version: 'not-requested', associations: 'not-requested' },
    truncated: false, untrustedRouterData: true
  };
}

export function emptyMeshReport(status: MeshReport['status'], reason: MeshReport['reason']): MeshReport {
  return { schemaVersion: 1, status, reason, configuredMembers: status === 'observed' ? 0 : null,
    members: [], shown: 0, controller: { status: 'unknown', ref: null, model: null, firmware: null, associationCount: null },
    sources: { members: status === 'unavailable' && reason !== 'member-limit' && reason !== 'unverified-empty-array'
      ? reason : null, bridge: 'not-requested', version: 'not-requested', associations: 'not-requested' },
    truncated: reason === 'member-limit', untrustedRouterData: true };
}

export function budgetMeshReport(report: MeshReport, maxBytes: number): MeshReport {
  while (report.members.length > 0 && Buffer.byteLength(JSON.stringify(redact(report)), 'utf8') > maxBytes) {
    report.members.pop();
    report.shown = report.members.length;
    report.truncated = true;
  }
  if (Buffer.byteLength(JSON.stringify(redact(report)), 'utf8') > maxBytes) {
    report.controller.model = null;
    report.controller.firmware = null;
    report.truncated = true;
  }
  return report;
}

export function controllerAssociations(value: unknown): number | null {
  if (!meshRecord(value) || !Array.isArray(value['station'])) return null;
  let count = 0;
  for (const row of value['station']) {
    if (!meshRecord(row) || typeof row['ap'] !== 'string') return null;
    if (/^WifiMaster\d+\/AccessPoint\d+$/.test(row['ap'])) count += 1;
    else if (!/^WifiMaster\d+\/Backhaul\d+$/.test(row['ap'])) return null;
  }
  return count;
}

export interface MeshEventNode {
  kind: 'controller' | 'extender' | 'unknown';
  ref: string | null;
  displayName: string | null;
}

export interface MeshEvent {
  timestamp: string | null;
  clientRef: string;
  type: 'transition' | 'association' | 'departure';
  fromNode: MeshEventNode | null;
  toNode: MeshEventNode | null;
  fromBandIndex: 0 | 1 | null;
  toBandIndex: 0 | 1 | null;
  roamMethod: 'ft' | null;
}

export interface MeshEventsReport {
  schemaVersion: 1;
  status: 'observed' | 'unavailable';
  reason: SafeReason | null;
  events: MeshEvent[];
  shown: number;
  truncated: boolean;
  sources: { log: SafeReason | null; members: SafeReason | 'not-requested' | null;
    interfaces: SafeReason | 'not-requested' | null };
  untrustedRouterData: true;
}

export function emptyMeshEvents(reason: SafeReason | null = null): MeshEventsReport {
  return { schemaVersion: 1, status: reason === null ? 'observed' : 'unavailable', reason,
    events: [], shown: 0, truncated: false,
    sources: { log: reason, members: 'not-requested', interfaces: 'not-requested' },
    untrustedRouterData: true };
}

export function projectMeshEvents(value: unknown, members: unknown, interfaces: unknown): MeshEventsReport {
  if (!meshRecord(value) || !meshRecord(value['log'])) return emptyMeshEvents('unexpected-response');
  const report = emptyMeshEvents();
  const entries = Object.entries(value['log']);
  const keys = entries.filter(([key]) => /^(?:0|[1-9]\d*)$/.test(key) && Number.isSafeInteger(Number(key)))
    .sort(([first], [second]) => Number(first) - Number(second));
  if (keys.length !== entries.length) report.sources.log = report.reason = 'unexpected-response';
  if (keys.length > 20) report.truncated = true;
  const memberRows = Array.isArray(members) && members.length > 0 && members.length <= 32 && validMeshMembers(members)
    ? members : null;
  const interfaceRows = meshRecord(interfaces) && Object.values(interfaces).every(meshRecord)
    ? Object.values(interfaces) as Array<Record<string, unknown>> : null;
  const clients = new Map<string, string>();
  function endpoint(identity: string): MeshEventNode {
    const matchingMembers = memberRows?.flatMap((row, index) => meshIdentity(row['mac']) === identity
      ? [index] : []) ?? [];
    const matchingInterfaces = interfaceRows?.filter(row => meshIdentity(row['mac']) === identity) ?? [];
    if (matchingMembers.length === 1 && memberRows![matchingMembers[0]!]!['mode'] === 'extender' &&
      memberRows![matchingMembers[0]!]!['hw_type'] === 'extender' &&
      matchingInterfaces.length === 0) {
      const index = matchingMembers[0]!;
      return { kind: 'extender', ref: `member-${index + 1}`,
        displayName: meshSafeLabel(memberRows![index]!['known-host']) };
    }
    if (matchingMembers.length === 0 && matchingInterfaces.length === 1 &&
      matchingInterfaces[0]!['type'] === 'AccessPoint' && matchingInterfaces[0]!['group'] === 'Bridge0') {
      return { kind: 'controller', ref: 'controller', displayName: null };
    }
    return { kind: 'unknown', ref: null, displayName: null };
  }
  for (const [, raw] of keys.slice(0, 20)) {
    if (!meshRecord(raw)) { report.sources.log = report.reason = 'unexpected-response'; continue; }
    const client = meshIdentity(raw['mac']);
    const hasArrival = raw['ap'] !== undefined;
    const hasDeparture = raw['left'] !== undefined;
    const arrival = hasArrival ? meshIdentity(raw['ap']) : null;
    const departure = hasDeparture && meshRecord(raw['left']) ? meshIdentity(raw['left']['ap']) : null;
    if (client === null || (!hasArrival && !hasDeparture) || (hasArrival && arrival === null) ||
      (hasDeparture && departure === null)) {
      report.sources.log = report.reason = 'unexpected-response';
      continue;
    }
    let clientRef = clients.get(client);
    if (clientRef === undefined) {
      clientRef = `client-${clients.size + 1}`;
      clients.set(client, clientRef);
    }
    const band = (candidate: unknown): 0 | 1 | null => candidate === 0 || candidate === 1 ? candidate : null;
    report.events.push({
      timestamp: typeof raw['timestamp'] === 'string' &&
        /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?:[1-9]|[12]\d|3[01])\s+(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(raw['timestamp'])
        ? raw['timestamp'] : null,
      clientRef,
      type: hasArrival && hasDeparture ? 'transition' : hasArrival ? 'association' : 'departure',
      fromNode: departure === null ? null : endpoint(departure),
      toNode: arrival === null ? null : endpoint(arrival),
      fromBandIndex: hasDeparture && meshRecord(raw['left']) ? band(raw['left']['band']) : null,
      toBandIndex: hasArrival ? band(raw['band']) : null,
      roamMethod: raw['roam'] === 'ft' ? 'ft' : null
    });
  }
  report.shown = report.events.length;
  if (report.events.length === 0 && report.reason !== null) report.status = 'unavailable';
  return report;
}

export function budgetMeshEvents(report: MeshEventsReport, maxBytes: number): MeshEventsReport {
  while (report.events.length > 0 && Buffer.byteLength(JSON.stringify(redact(report)), 'utf8') > maxBytes) {
    report.events.pop();
    report.shown = report.events.length;
    report.truncated = true;
  }
  return report;
}

export const WIFI_TELEMETRY_AVAILABILITY: WifiTelemetryAvailability = {
  retryCounters: 'not-exposed',
  errorCounters: 'not-exposed',
  channelUtilization: 'not-exposed',
  deauthenticationReasons: 'not-exposed',
  roamingEvents: 'not-exposed',
  environmentScan: 'not-exposed'
};

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function safeString(value: unknown, max = 120): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const cleaned = redactText(String(value)
    .replace(/\u001b\][^\u0007]*(?:\u0007|$)/g, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim());
  return cleaned === '' ? null : Array.from(cleaned).slice(0, max).join('');
}

function finiteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string' || value.trim() === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function booleanValue(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (value === 'yes') return true;
  if (value === 'no') return false;
  return null;
}

function rssi(value: unknown): number | null {
  const parsed = finiteNumber(value);
  return parsed !== null && parsed >= -127 && parsed <= 0 ? parsed : null;
}

function signal(value: number | null): WifiAssociationEvidence['signal'] {
  if (value === null) return 'unknown';
  if (value >= -60) return 'good';
  if (value >= -70) return 'usable';
  return 'weak';
}

function list<T>(items: T[], total = items.length): ListEvidence<T> {
  return { items, shown: items.length, total, truncated: items.length < total };
}

function radioIdForAp(id: string | null): string | null {
  if (id === null) return null;
  const match = /^(WifiMaster\d+)\/AccessPoint\d+$/.exec(id);
  return match?.[1] ?? null;
}

function isType(value: Record<string, unknown>, expected: string): boolean {
  if (value['type'] === expected) return true;
  return Array.isArray(value['traits']) && value['traits'].includes(expected);
}

function enabled(value: Record<string, unknown>): boolean | null {
  const configuration = safeString(record(record(value['summary'])['layer'])['conf'])?.toLowerCase();
  if (configuration === 'disabled') return false;
  if (configuration === 'running') return true;
  const connected = booleanValue(value['connected']);
  if (connected !== null) return connected;
  return null;
}

function radioSummary(id: string, value: Record<string, unknown>): WifiRadioSummary {
  return {
    id,
    state: safeString(value['state'] ?? value['link']),
    connected: booleanValue(value['connected']),
    hardwareState: safeString(value['hwstate']),
    channel: finiteNumber(value['channel']),
    channelWidthMhz: finiteNumber(value['bandwidth'])
  };
}

function apSummary(id: string, value: Record<string, unknown>, clients: number): WifiAccessPointSummary {
  return {
    id,
    radioId: radioIdForAp(id),
    state: safeString(value['state'] ?? value['link']),
    connected: booleanValue(value['connected']),
    enabled: enabled(value),
    clients
  };
}

export function projectWifiTopology(
  interfacesRaw: unknown,
  associationsRaw: unknown,
  availability: { version?: SourceState; interfaces?: SourceState; associations?: SourceState;
    versionReason?: SafeReason; interfacesReason?: SafeReason; associationsReason?: SafeReason } = {}
): WifiTopology {
  const interfaceState = availability.interfaces ?? 'available';
  const associationState = availability.associations ?? 'available';
  const interfaces = record(interfacesRaw);
  const stations = associationState === 'available' && Array.isArray(record(associationsRaw)['station'])
    ? (record(associationsRaw)['station'] as unknown[]).map(record) : [];
  const radioEntries = interfaceState === 'available'
    ? Object.entries(interfaces).filter(([id, value]) => /^WifiMaster\d+$/.test(id) &&
      isType(record(value), 'WifiMaster')) : [];
  const apEntries = interfaceState === 'available'
    ? Object.entries(interfaces).filter(([id, value]) => radioIdForAp(id) !== null &&
      isType(record(value), 'AccessPoint')) : [];
  const clientCounts = new Map<string, number>();
  for (const station of stations) {
    const ap = safeString(station['ap']);
    if (ap !== null) clientCounts.set(ap, (clientCounts.get(ap) ?? 0) + 1);
  }
  const radios = radioEntries.map(([id, value]) => radioSummary(id, record(value))).slice(0, 16);
  const accessPoints = apEntries.map(([id, value]) => apSummary(id, record(value), clientCounts.get(id) ?? 0)).slice(0, 64);
  const radioIds = new Set(radioEntries.map(([id]) => id));
  const accessPointIds = new Set(apEntries.map(([id]) => id));
  const clientAggregate: WifiClientAggregate = {
    total: stations.length, authenticated: 0, unauthenticated: 0, authenticationUnknown: 0,
    missingAccessPoint: 0, missingRadio: 0
  };
  const buckets = { good: 0, usable: 0, weak: 0, unknown: 0 };
  for (const station of stations) {
    const authenticated = booleanValue(station['authenticated']);
    if (authenticated === true) clientAggregate.authenticated += 1;
    else if (authenticated === false) clientAggregate.unauthenticated += 1;
    else clientAggregate.authenticationUnknown += 1;
    const apId = safeString(station['ap']);
    if (interfaceState === 'available' && (apId === null || !accessPointIds.has(apId))) {
      clientAggregate.missingAccessPoint += 1;
    }
    const masterId = radioIdForAp(apId);
    if (interfaceState === 'available' && (masterId === null || !radioIds.has(masterId))) {
      clientAggregate.missingRadio += 1;
    }
    buckets[signal(rssi(station['rssi']))] += 1;
  }
  return {
    sourceAvailability: { version: availability.version ?? 'available', interfaces: interfaceState,
      associations: associationState },
    sourceReasons: { version: availability.versionReason ?? null, interfaces: availability.interfacesReason ?? null,
      associations: availability.associationsReason ?? null },
    totals: {
      radios: interfaceState === 'available' ? radioEntries.length : null,
      accessPoints: interfaceState === 'available' ? apEntries.length : null,
      clients: associationState === 'available' ? stations.length : null
    },
    radios: list(radios, radioEntries.length),
    accessPoints: list(accessPoints, apEntries.length),
    clients: clientAggregate,
    signal: buckets
  };
}

function topologyCheck(id: WifiCheck['id'], status: WifiCheckStatus, summary: string): WifiCheck {
  return { id, status, summary };
}

export function buildWifiDiagnostic(input: { topology: Evidence<WifiTopology> }): WifiDiagnosticReport {
  const topology = input.topology.data;
  const findings: WifiFinding[] = [];
  if (topology && topology.signal.weak > 0) findings.push({ id: 'weak-signal-clients', severity: 'warning',
    count: topology.signal.weak, summary: 'One or more associated clients have RSSI below -70 dBm.',
    relatedChecks: ['signal'] });
  if (topology && topology.clients.unauthenticated > 0) findings.push({ id: 'unauthenticated-clients', severity: 'critical',
    count: topology.clients.unauthenticated, summary: 'One or more associations explicitly report authenticated=false.',
    relatedChecks: ['clients'] });
  if (topology && topology.clients.missingAccessPoint > 0) findings.push({ id: 'association-ap-missing', severity: 'warning',
    count: topology.clients.missingAccessPoint, summary: 'One or more associations reference an absent access point.',
    relatedChecks: ['access-points', 'clients'] });
  if (topology && topology.clients.missingRadio > 0) findings.push({ id: 'association-radio-missing', severity: 'warning',
    count: topology.clients.missingRadio, summary: 'One or more associations do not resolve to a measured WifiMaster.',
    relatedChecks: ['radios', 'clients'] });
  const interfacesAvailable = topology?.sourceAvailability.interfaces === 'available';
  const associationsAvailable = topology?.sourceAvailability.associations === 'available';
  const versionAvailable = topology?.sourceAvailability.version === 'available';
  const checks: WifiCheck[] = [
    topologyCheck('sources', input.topology.status === 'available' && versionAvailable && interfacesAvailable && associationsAvailable ? 'pass' : 'unknown',
      input.topology.status === 'available' && versionAvailable && interfacesAvailable && associationsAvailable ? 'Version, interface and association sources are available.' : 'One or more Wi-Fi sources are unavailable.'),
    topologyCheck('radios', interfacesAvailable ? 'pass' : 'unknown',
      interfacesAvailable ? 'Bounded radio state was collected.' : 'Radio state is unavailable.'),
    topologyCheck('access-points', !interfacesAvailable ? 'unknown' : (topology?.clients.missingAccessPoint ?? 0) > 0 ? 'warning' : 'pass',
      !interfacesAvailable ? 'Access-point state is unavailable.' : (topology?.clients.missingAccessPoint ?? 0) > 0 ?
        'Some associations reference absent access points.' : 'Access-point references are consistent.'),
    topologyCheck('clients', !associationsAvailable ? 'unknown' : (topology?.clients.unauthenticated ?? 0) > 0 ? 'fail' :
      (topology?.clients.missingAccessPoint ?? 0) > 0 || (topology?.clients.missingRadio ?? 0) > 0 ? 'warning' : 'pass',
      !associationsAvailable ? 'Client association state is unavailable.' : (topology?.clients.unauthenticated ?? 0) > 0 ?
        'Some clients explicitly report failed authentication.' : 'No failed authentication is exposed.'),
    topologyCheck('signal', !associationsAvailable ? 'unknown' : (topology?.signal.weak ?? 0) > 0 ? 'warning' : 'pass',
      !associationsAvailable ? 'Client signal is unavailable.' : (topology?.signal.weak ?? 0) > 0 ?
        'Some clients have weak RSSI.' : 'No measured client has weak RSSI.')
  ];
  const status: WifiReportStatus = checks.some(item => item.status === 'fail') ? 'unhealthy'
    : checks.some(item => item.status === 'warning' || item.status === 'unknown') ?
      checks.every(item => item.status === 'unknown') ? 'unknown' : 'degraded' : 'healthy';
  return {
    schemaVersion: 1, status,
    complete: input.topology.status === 'available' && versionAvailable && interfacesAvailable && associationsAvailable,
    checks, findings,
    evidence: { topology: input.topology, telemetryAvailability: WIFI_TELEMETRY_AVAILABILITY },
    untrustedRouterData: true,
    truncated: topology?.radios.truncated === true || topology?.accessPoints.truncated === true
  };
}

function selectedIdentity(host: HostRecord): WifiClientIdentity {
  return {
    mac: safeString(host['mac'], 64) ?? '',
    ip: safeString(host['ip'], 64),
    name: safeString(host['name'], 256),
    hostname: safeString(host['hostname'], 256),
    active: booleanValue(host['active'])
  };
}

export function projectWifiClientEvidence(
  host: HostRecord,
  associationsRaw: unknown,
  interfacesRaw: unknown,
  availability: { associations?: SourceState; interfaces?: SourceState; associationsReason?: SafeReason; interfacesReason?: SafeReason } = {}
): WifiClientHealthEvidence {
  const associationsAvailable = availability.associations !== 'unavailable';
  const interfacesAvailable = availability.interfaces !== 'unavailable';
  const apId = safeString(host['ap']);
  const ssid = safeString(host['ssid'], 128);
  const stations = associationsAvailable && Array.isArray(record(associationsRaw)['station'])
    ? (record(associationsRaw)['station'] as unknown[]).map(record) : [];
  const mac = safeString(host['mac'], 64);
  const matchingStations = stations.filter(row => mac !== null && typeof row['mac'] === 'string' &&
    row['mac'].toLowerCase() === mac.toLowerCase());
  const station = matchingStations.length === 1 ? matchingStations[0] : undefined;
  const currentApId = safeString(station?.['ap']) ?? apId;
  const nestedInterface = record(host['interface']);
  const interfaceId = safeString(nestedInterface['id'] ?? nestedInterface['name']);
  const kind: WifiClientConnection['kind'] = station !== undefined || apId !== null || ssid !== null ? 'wireless'
    : interfaceId !== null && associationsAvailable ? 'wired' : 'unknown';
  const connection = available<WifiClientConnection>({ kind, apId: currentApId, ssid });
  const base = {
    identity: available(selectedIdentity(host)), connection,
    telemetryAvailability: WIFI_TELEMETRY_AVAILABILITY
  };
  if (kind === 'wired') {
    return { ...base, association: available({ associated: false, authenticated: null, rssiDbm: null,
      signal: 'unknown', txRateMbps: null, rxRateMbps: null, mode: null, channelWidthMhz: null,
      mcs: null, streams: null, txBytes: null, rxBytes: null, capabilities: [], roam: null }),
    accessPoint: unavailable('not-supported'), radio: unavailable('not-supported') };
  }
  const measuredRssi = rssi(station?.['rssi']);
  const associationData: WifiAssociationEvidence = {
    associated: station !== undefined,
    authenticated: booleanValue(station?.['authenticated'] ?? (station === undefined ? host['authenticated'] : undefined)),
    rssiDbm: measuredRssi,
    signal: signal(measuredRssi),
    txRateMbps: finiteNumber(station?.['txrate']),
    rxRateMbps: finiteNumber(station?.['rxrate']),
    mode: safeString(station?.['mode']),
    channelWidthMhz: finiteNumber(station?.['ht']),
    mcs: finiteNumber(station?.['mcs']),
    streams: finiteNumber(station?.['txss']),
    txBytes: finiteNumber(station?.['txbytes']),
    rxBytes: finiteNumber(station?.['rxbytes']),
    capabilities: Array.isArray(station?.['_11']) ? station['_11'].map(item => safeString(item, 16))
      .filter((item): item is string => item !== null).slice(0, 16) : [],
    roam: safeString(station?.['roam'], 32)
  };
  const association = associationsAvailable ? available(associationData)
    : unavailable<WifiAssociationEvidence>(availability.associationsReason ?? 'rci-error');
  const interfaces = record(interfacesRaw);
  const apValue = currentApId !== null ? interfaces[currentApId] : undefined;
  const masterId = radioIdForAp(currentApId);
  const masterValue = masterId !== null ? interfaces[masterId] : undefined;
  const unavailableReason = availability.interfacesReason ?? 'rci-error';
  const accessPoint = !interfacesAvailable ? unavailable<WifiAccessPointSummary>(unavailableReason)
    : currentApId === null || radioIdForAp(currentApId) === null || apValue === undefined ||
      !isType(record(apValue), 'AccessPoint')
      ? unavailable<WifiAccessPointSummary>('unexpected-response')
      : available(apSummary(currentApId, record(apValue), station === undefined ? 0 : 1));
  const radio = !interfacesAvailable ? unavailable<WifiRadioSummary>(unavailableReason)
    : masterId === null || masterValue === undefined || !isType(record(masterValue), 'WifiMaster')
      ? unavailable<WifiRadioSummary>('unexpected-response')
      : available(radioSummary(masterId, record(masterValue)));
  return { ...base, association, accessPoint, radio };
}

function clientCheck(id: WifiClientCheck['id'], status: WifiCheckStatus, summary: string): WifiClientCheck {
  return { id, status, summary };
}

export function buildWifiClientHealth(evidence: WifiClientHealthEvidence): WifiClientHealthReport {
  const connection = evidence.connection.data;
  if (connection?.kind === 'wired') {
    const checks: WifiClientCheck[] = ['connection', 'association', 'authentication', 'signal', 'access-point', 'radio']
      .map(id => clientCheck(id as WifiClientCheck['id'], 'not-applicable', 'The selected device is wired; Wi-Fi telemetry is not applicable.'));
    return { schemaVersion: 1, status: 'not-applicable', complete: true, checks, findings: [], evidence,
      untrustedRouterData: true, truncated: false };
  }
  const association = evidence.association.data;
  const active = evidence.identity.data?.active;
  const findings: WifiClientFinding[] = [];
  if (connection?.kind === 'wireless' && evidence.association.status === 'available' &&
      association?.associated === false && active === true) {
    findings.push({ id: 'wifi-association-missing', severity: 'warning',
      summary: 'The active wireless hotspot has no matching current association.', relatedChecks: ['association'] });
  }
  if (association?.authenticated === false) findings.push({ id: 'wifi-not-authenticated', severity: 'critical',
    summary: 'The selected association explicitly reports authenticated=false.', relatedChecks: ['authentication'] });
  if (association?.signal === 'weak') findings.push({ id: 'wifi-signal-weak', severity: 'warning',
    summary: 'The selected client has RSSI below -70 dBm.', relatedChecks: ['signal'] });
  if (connection?.kind === 'wireless' && evidence.accessPoint.status === 'unavailable' &&
      evidence.accessPoint.reason === 'unexpected-response') {
    findings.push({ id: 'wifi-access-point-missing', severity: 'warning',
      summary: 'The selected association references an absent access point.', relatedChecks: ['access-point'] });
  }
  if (connection?.kind === 'wireless' && evidence.radio.status === 'unavailable' &&
      evidence.radio.reason === 'unexpected-response') {
    findings.push({ id: 'wifi-radio-missing', severity: 'warning',
      summary: 'The selected access-point ID does not resolve to a measured WifiMaster.', relatedChecks: ['radio'] });
  }
  const associationStatus: WifiCheckStatus = evidence.association.status === 'unavailable' ? 'unknown'
    : connection?.kind === 'wireless' && association?.associated === false && active === true ? 'warning'
      : association?.associated === true ? 'pass' : 'unknown';
  const authenticationStatus: WifiCheckStatus = evidence.association.status === 'unavailable' ? 'unknown'
    : association?.authenticated === false ? 'fail' : association?.authenticated === true ? 'pass' : 'unknown';
  const signalStatus: WifiCheckStatus = evidence.association.status === 'unavailable' ? 'unknown'
    : association?.signal === 'weak' ? 'warning' : association?.signal === 'unknown' ? 'unknown' : 'pass';
  const checks = [
    clientCheck('connection', connection?.kind === 'wireless' ? 'pass' : 'unknown',
      connection?.kind === 'wireless' ? 'The selected hotspot record is wireless.' : 'Connection kind is unknown.'),
    clientCheck('association', associationStatus, associationStatus === 'pass' ? 'A matching association is present.' :
      associationStatus === 'warning' ? 'The active wireless device has no matching association.' : 'Association state is unknown.'),
    clientCheck('authentication', authenticationStatus, authenticationStatus === 'fail' ? 'Authentication explicitly failed.' :
      authenticationStatus === 'pass' ? 'Authentication is reported successful.' : 'Authentication state is unknown.'),
    clientCheck('signal', signalStatus, signalStatus === 'warning' ? 'RSSI is below -70 dBm.' :
      signalStatus === 'pass' ? 'RSSI is usable or good.' : 'RSSI is unavailable or invalid.'),
    clientCheck('access-point', evidence.accessPoint.status === 'available' ? 'pass' :
      connection?.kind === 'wireless' && evidence.accessPoint.reason === 'unexpected-response' ? 'warning' : 'unknown',
    evidence.accessPoint.status === 'available' ? 'The referenced access point is present.' : 'Access-point evidence is unavailable.'),
    clientCheck('radio', evidence.radio.status === 'available' ? 'pass' :
      connection?.kind === 'wireless' && evidence.radio.reason === 'unexpected-response' ? 'warning' : 'unknown',
    evidence.radio.status === 'available' ? 'The parent WifiMaster is present.' : 'Radio evidence is unavailable.')
  ];
  const status: WifiReportStatus = checks.some(item => item.status === 'fail') ? 'unhealthy'
    : checks.some(item => item.status === 'warning' || item.status === 'unknown') ?
      checks.every(item => item.status === 'unknown') ? 'unknown' : 'degraded' : 'healthy';
  return { schemaVersion: 1, status,
    complete: [evidence.identity, evidence.connection, evidence.association, evidence.accessPoint, evidence.radio]
      .every(item => item.status === 'available'),
    checks, findings, evidence, untrustedRouterData: true, truncated: false };
}

function bytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(redact(value), null, 2), 'utf8');
}

export function budgetWifiDiagnostic(report: WifiDiagnosticReport, maxBytes: number): WifiDiagnosticReport {
  const topology = report.evidence.topology.data;
  for (const collection of [topology?.accessPoints, topology?.radios]) {
    while (collection && bytes(report) > maxBytes && collection.items.length > 0) {
      collection.items = collection.items.slice(0, Math.floor(collection.items.length / 2));
      collection.shown = collection.items.length;
      collection.truncated = collection.shown < collection.total;
      report.truncated = true;
    }
  }
  if (bytes(report) > maxBytes) {
    for (const item of report.checks) item.summary = '';
    for (const item of report.findings) item.summary = '';
    report.truncated = true;
  }
  return report;
}

export function budgetWifiClientHealth(report: WifiClientHealthReport, maxBytes: number): WifiClientHealthReport {
  const association = report.evidence.association.data;
  if (association && bytes(report) > maxBytes) {
    association.capabilities = [];
    association.txBytes = null;
    association.rxBytes = null;
    association.mcs = null;
    association.streams = null;
    association.roam = null;
    report.truncated = true;
  }
  if (association && bytes(report) > maxBytes) {
    association.txRateMbps = null;
    association.rxRateMbps = null;
    association.mode = null;
    association.channelWidthMhz = null;
    report.truncated = true;
  }
  if (bytes(report) > maxBytes) {
    report.evidence.association = unavailable('response-too-large');
    report.evidence.accessPoint = unavailable('response-too-large');
    report.evidence.radio = unavailable('response-too-large');
    report.complete = false;
    for (const item of report.checks) item.summary = '';
    for (const item of report.findings) item.summary = '';
    report.truncated = true;
  }
  return report;
}
