import { redact, redactText } from '../security/redact.js';
import type { HostRecord } from '../router/device-state.js';
import type { LogEntry } from '../tools/logs.js';
import type {
  DiagnosticStatus,
  Evidence,
  ListEvidence,
  PublicLogEntry
} from './internet-diagnostic.js';

export type DeviceCheckStatus = 'pass' | 'warning' | 'fail' | 'unknown' | 'not-applicable';

export interface DeviceIdentityEvidence {
  mac: string;
  name: string | null;
  hostname: string | null;
  registered: boolean | null;
  active: boolean | null;
  lastSeenSeconds: number | null;
}

export interface DeviceAddressEvidence {
  ipv4: string | null;
  ipv6: ListEvidence<string>;
  hotspotDhcpExpiresSeconds: number | null;
}

export interface DhcpBindingEvidence {
  matched: boolean;
  ipv4: string | null;
  expiresSeconds: number | null;
  via: string | null;
}

export interface DeviceConnectionEvidence {
  kind: 'wired' | 'wireless' | 'unknown';
  interface: string | null;
  ap: string | null;
  ssid: string | null;
  link: string | null;
  interfaceState: string | null;
  interfaceStateAvailable: boolean;
}

export interface DeviceWifiEvidence {
  applicable: boolean;
  associated: boolean | null;
  authenticated: boolean | null;
  rssiDbm: number | null;
  txRateMbps: number | null;
  rxRateMbps: number | null;
  mode: string | null;
  channelWidthMhz: number | null;
  band: string | null;
  associationStateAvailable: boolean;
  interfaceStateAvailable: boolean;
}

export interface DeviceAccessEvidence {
  access: string | null;
  blocked: boolean | null;
  schedule: string | null;
  priority: number | null;
}

export interface PolicyInterfaceEvidence {
  id: string;
  state: 'available' | 'unavailable' | 'unknown';
}

export interface DeviceRoutingPolicyEvidence {
  assigned: string | null;
  present: boolean | null;
  description: string | null;
  permittedInterfaces: ListEvidence<PolicyInterfaceEvidence>;
  interfaceStatesAvailable: boolean;
}

export interface DeviceDnsContextEvidence {
  routerWide: true;
  current: boolean;
  dnsAccessible: boolean | null;
  internet: boolean | null;
}

export interface DeviceLogEvidence extends ListEvidence<PublicLogEntry> {
  scanned: number;
  matched: number;
  untrusted: true;
}

export interface DeviceDiagnosticEvidence {
  identity: Evidence<DeviceIdentityEvidence>;
  address: Evidence<DeviceAddressEvidence>;
  dhcpBinding: Evidence<DhcpBindingEvidence>;
  connection: Evidence<DeviceConnectionEvidence>;
  wifi: Evidence<DeviceWifiEvidence>;
  access: Evidence<DeviceAccessEvidence>;
  routingPolicy: Evidence<DeviceRoutingPolicyEvidence>;
  dnsContext: Evidence<DeviceDnsContextEvidence>;
  logs: Evidence<DeviceLogEvidence>;
}

export interface DeviceDiagnosticCheck {
  id: 'identity' | 'address' | 'connection' | 'wifi' | 'access' |
    'routing-policy' | 'dns-context' | 'recent-logs';
  status: DeviceCheckStatus;
  summary: string;
}

export interface DeviceDiagnosticFinding {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  summary: string;
  relatedChecks: DeviceDiagnosticCheck['id'][];
}

export interface DeviceDiagnosticReport {
  schemaVersion: 1;
  status: DiagnosticStatus;
  complete: boolean;
  checks: DeviceDiagnosticCheck[];
  findings: DeviceDiagnosticFinding[];
  evidence: DeviceDiagnosticEvidence;
  untrustedRouterData: true;
  truncated: boolean;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
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

function nullableBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function nullableNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function list<T>(items: T[], total = items.length): ListEvidence<T> {
  return { items, shown: items.length, total, truncated: items.length < total };
}

function interfaceAvailability(value: Record<string, unknown>): PolicyInterfaceEvidence['state'] {
  if (Object.keys(value).length === 0) return 'unknown';
  if (value['connected'] === false || value['connected'] === 'no') return 'unavailable';
  const states = [value['link'], value['state']].map(item => String(item ?? '').toLowerCase());
  if (states.some(state => ['down', 'error', 'failed', 'disabled', 'offline', 'unavailable'].includes(state))) {
    return 'unavailable';
  }
  if (value['connected'] === true || value['connected'] === 'yes' ||
      states.some(state => ['up', 'ready', 'running', 'online', 'connected'].includes(state))) {
    return 'available';
  }
  return 'unknown';
}

export function projectDeviceIdentity(host: HostRecord): DeviceIdentityEvidence {
  return {
    mac: safeString(host['mac']) ?? '',
    name: safeString(host['name']),
    hostname: safeString(host['hostname']),
    registered: nullableBoolean(host['registered']),
    active: nullableBoolean(host['active']),
    lastSeenSeconds: nullableNumber(host['last-seen'])
  };
}

export function projectDeviceAddress(host: HostRecord): DeviceAddressEvidence {
  const ip6 = Array.isArray(host['ip6'])
    ? host['ip6'].map(value => safeString(value)).filter((value): value is string => value !== null)
    : [];
  return {
    ipv4: safeString(host['ip']),
    ipv6: list(ip6.slice(0, 16), ip6.length),
    hotspotDhcpExpiresSeconds: nullableNumber(record(host['dhcp'])['expires'])
  };
}

export function projectDhcpBinding(rows: readonly Record<string, unknown>[], mac: string): DhcpBindingEvidence {
  const match = rows.find(row =>
    typeof row['mac'] === 'string' && row['mac'].toLowerCase() === mac.toLowerCase());
  return {
    matched: match !== undefined,
    ipv4: safeString(match?.['ip']),
    expiresSeconds: nullableNumber(match?.['expires']),
    via: safeString(match?.['via'])
  };
}

export function projectDeviceConnection(
  host: HostRecord,
  interfacesRaw: unknown,
  interfaceStateAvailable = true
): DeviceConnectionEvidence {
  const interfaces = record(interfacesRaw);
  const nested = record(host['interface']);
  const iface = safeString(nested['id']) ?? safeString(nested['name']);
  const ap = safeString(host['ap']);
  const ssid = safeString(host['ssid']);
  const kind = ap !== null || ssid !== null ? 'wireless' : iface !== null ? 'wired' : 'unknown';
  const selected = record(interfaces[ap ?? iface ?? '']);
  return {
    kind,
    interface: iface,
    ap,
    ssid,
    link: safeString(host['link']),
    interfaceState: safeString(selected['state'] ?? selected['link']),
    interfaceStateAvailable
  };
}

export function projectDeviceWifi(
  host: HostRecord,
  associationsRaw: unknown,
  interfacesRaw: unknown,
  associationStateAvailable = true,
  interfaceStateAvailable = true
): DeviceWifiEvidence {
  const ap = safeString(host['ap']);
  const wireless = ap !== null || safeString(host['ssid']) !== null;
  if (!wireless) {
    return { applicable: false, associated: null, authenticated: null, rssiDbm: null,
      txRateMbps: null, rxRateMbps: null, mode: null, channelWidthMhz: null, band: null,
      associationStateAvailable, interfaceStateAvailable };
  }
  const stations = Array.isArray(record(associationsRaw)['station'])
    ? record(associationsRaw)['station'] as unknown[]
    : [];
  const mac = safeString(host['mac']);
  const station = stations.map(record).find(row =>
    mac !== null && typeof row['mac'] === 'string' && row['mac'].toLowerCase() === mac.toLowerCase());
  const measured = (key: string): unknown => station?.[key] ?? host[key];
  const masterId = ap?.split('/')[0] ?? '';
  const master = record(record(interfacesRaw)[masterId]);
  return {
    applicable: true,
    associated: !associationStateAvailable ? null
      : station === undefined ? false
        : ap === null || safeString(station['ap']) === ap,
    authenticated: nullableBoolean(measured('authenticated')),
    rssiDbm: nullableNumber(measured('rssi')),
    txRateMbps: nullableNumber(measured('txrate')),
    rxRateMbps: nullableNumber(measured('rxrate')),
    mode: safeString(measured('mode')),
    channelWidthMhz: nullableNumber(measured('ht')),
    band: safeString(master['band']),
    associationStateAvailable,
    interfaceStateAvailable
  };
}

export function projectDeviceAccess(host: HostRecord): DeviceAccessEvidence {
  const access = safeString(host['access']);
  return {
    access,
    blocked: access === null ? null : access.toLowerCase() === 'deny',
    schedule: safeString(host['schedule']),
    priority: nullableNumber(host['priority'])
  };
}

export function projectDeviceRoutingPolicy(
  host: HostRecord,
  policiesRaw: unknown,
  interfacesRaw: unknown,
  interfaceStatesAvailable = true
): DeviceRoutingPolicyEvidence {
  const assigned = safeString(host['policy']);
  if (assigned === null) {
    return { assigned: null, present: null, description: null, permittedInterfaces: list([]),
      interfaceStatesAvailable };
  }
  const policies = record(policiesRaw);
  const raw = policies[assigned];
  if (raw === undefined) {
    return { assigned, present: false, description: null, permittedInterfaces: list([]),
      interfaceStatesAvailable };
  }
  const policy = record(raw);
  const permits = Array.isArray(policy['permit']) ? policy['permit'].map(record)
    .filter(item => item['enabled'] !== false && item['no'] !== true) : [];
  const interfaces = record(interfacesRaw);
  const ids = permits.map(item => safeString(item['interface'])).filter((id): id is string => id !== null);
  return {
    assigned,
    present: true,
    description: safeString(policy['description']),
    permittedInterfaces: list(ids.slice(0, 50).map(id => ({ id, state: interfaceAvailability(record(interfaces[id])) })), ids.length),
    interfaceStatesAvailable
  };
}

export function projectDeviceDnsContext(raw: unknown): DeviceDnsContextEvidence {
  const value = record(raw);
  const checked = value['checked'];
  return {
    routerWide: true,
    current: checked === true,
    dnsAccessible: nullableBoolean(value['dns-accessible']),
    internet: nullableBoolean(value['internet'])
  };
}

export function projectDeviceLogs(entries: readonly LogEntry[], aliases: readonly string[]): DeviceLogEvidence {
  const lower = aliases.map(alias => alias.toLocaleLowerCase());
  const matching = entries.filter(entry => lower.some(alias => entry.line.toLocaleLowerCase().includes(alias)));
  const items = matching.slice(-20).map(entry => ({
    timestamp: safeString(entry.timestamp), ident: safeString(entry.ident), level: safeString(entry.level),
    label: safeString(entry.label), line: safeString(entry.line, 512) ?? ''
  }));
  return { ...list(items, matching.length), scanned: entries.length, matched: matching.length, untrusted: true };
}

function check(id: DeviceDiagnosticCheck['id'], status: DeviceCheckStatus, summary: string): DeviceDiagnosticCheck {
  return { id, status, summary };
}

export function buildDeviceDiagnostic(evidence: DeviceDiagnosticEvidence): DeviceDiagnosticReport {
  const findings: DeviceDiagnosticFinding[] = [];
  const identity = evidence.identity.data;
  const address = evidence.address.data;
  const dhcp = evidence.dhcpBinding.data;
  const connection = evidence.connection.data;
  const wifi = evidence.wifi.data;
  const access = evidence.access.data;
  const policy = evidence.routingPolicy.data;
  const dns = evidence.dnsContext.data;

  if (access?.blocked === true) findings.push({ id: 'device-access-blocked', severity: 'critical',
    summary: 'The router explicitly denies this device network access.', relatedChecks: ['access'] });
  if (identity?.active === false) findings.push({ id: 'device-inactive', severity: 'warning',
    summary: 'The router currently reports this known device as inactive.', relatedChecks: ['connection'] });
  if (wifi?.applicable === true && wifi.authenticated === false) findings.push({ id: 'wifi-not-authenticated', severity: 'critical',
    summary: 'The wireless device explicitly reports authenticated=false.', relatedChecks: ['wifi'] });
  if (wifi?.applicable === true && identity?.active === true && wifi.associated === false) findings.push({
    id: 'wifi-association-missing', severity: 'warning',
    summary: 'The active hotspot record has no matching current Wi-Fi association.', relatedChecks: ['wifi']
  });
  const permitted = policy?.permittedInterfaces.items ?? [];
  if (policy?.assigned !== null && policy?.present === false) findings.push({ id: 'routing-policy-missing', severity: 'warning',
    summary: 'The device references a routing policy that is not present.', relatedChecks: ['routing-policy'] });
  if (permitted.length > 0 && permitted.every(item => item.state === 'unavailable')) findings.push({
    id: 'routing-policy-interfaces-unavailable', severity: 'warning',
    summary: 'Every explicitly permitted interface in the assigned policy is unavailable.', relatedChecks: ['routing-policy']
  });

  const addressStatus: DeviceCheckStatus = evidence.address.status === 'unavailable' ? 'unknown'
    : address?.ipv4 !== null || (address?.ipv6.total ?? 0) > 0 || (dhcp?.ipv4 ?? null) !== null ? 'pass' : 'unknown';
  const connectionStatus: DeviceCheckStatus = evidence.connection.status === 'unavailable' ? 'unknown'
    : identity?.active === false ? 'warning'
      : identity?.active === true && connection?.kind !== 'unknown' ? 'pass' : 'unknown';
  const wifiStatus: DeviceCheckStatus = evidence.wifi.status === 'unavailable' ? 'unknown'
    : wifi?.applicable === false ? 'not-applicable'
      : wifi?.authenticated === false ? 'fail'
        : wifi?.associated === false && identity?.active === true ? 'warning'
          : wifi?.associated === true ? 'pass' : 'unknown';
  const accessStatus: DeviceCheckStatus = evidence.access.status === 'unavailable' ? 'unknown'
    : access?.blocked === true ? 'fail' : access?.blocked === false ? 'pass' : 'unknown';
  const policyStatus: DeviceCheckStatus = evidence.routingPolicy.status === 'unavailable' ? 'unknown'
    : policy?.assigned === null ? 'pass'
      : policy?.present === false || permitted.length > 0 && permitted.every(item => item.state === 'unavailable') ? 'warning'
        : policy?.present === true ? 'pass' : 'unknown';
  const dnsStatus: DeviceCheckStatus = evidence.dnsContext.status === 'unavailable' || dns?.current !== true ? 'unknown'
    : dns.dnsAccessible === false ? 'warning' : dns.dnsAccessible === true ? 'pass' : 'unknown';
  const checks = [
    check('identity', evidence.identity.status === 'available' ? 'pass' : 'unknown',
      evidence.identity.status === 'available' ? 'The device resolved to one known router record.' : 'Device identity is unavailable.'),
    check('address', addressStatus, addressStatus === 'pass' ? 'The device has an address in hotspot or DHCP evidence.' :
      'No current address is exposed; static or stale state cannot be distinguished.'),
    check('connection', connectionStatus, connectionStatus === 'pass' ? 'The router reports an active device connection.' :
      connectionStatus === 'warning' ? 'The known device is currently inactive.' : 'Current connection state is unknown.'),
    check('wifi', wifiStatus, wifiStatus === 'not-applicable' ? 'The device is wired; Wi-Fi telemetry is not applicable.' :
      wifiStatus === 'pass' ? 'A matching Wi-Fi association is present.' : wifiStatus === 'fail' ?
        'The device explicitly reports failed Wi-Fi authentication.' : wifiStatus === 'warning' ?
          'Wireless association evidence is inconsistent or absent.' : 'Wi-Fi telemetry is unknown.'),
    check('access', accessStatus, accessStatus === 'fail' ? 'The router explicitly blocks this device.' :
      accessStatus === 'pass' ? 'The device is not explicitly blocked.' : 'Device access state is unknown.'),
    check('routing-policy', policyStatus, policyStatus === 'pass' ? policy?.assigned === null ?
      'No custom routing policy is assigned.' : 'The assigned routing policy is present.' :
      policyStatus === 'warning' ? 'The assigned routing policy is missing or has no available interface.' :
        'Routing policy state is unknown.'),
    check('dns-context', dnsStatus, dnsStatus === 'pass' ? 'The current router-wide check reaches DNS.' :
      dnsStatus === 'warning' ? 'The current router-wide check reports DNS unreachable; this is not device-specific proof.' :
        'Current router-wide DNS context is unknown.'),
    check('recent-logs', evidence.logs.status === 'available' ? 'pass' : 'unknown',
      evidence.logs.status === 'available' ? 'Bounded device-related logs were collected as untrusted context.' :
        'Device-related logs are unavailable.')
  ];
  const core = checks.filter(item => ['identity', 'address', 'connection', 'wifi', 'access', 'routing-policy'].includes(item.id));
  const status: DiagnosticStatus = core.some(item => item.status === 'fail') ? 'unhealthy'
    : core.some(item => item.status === 'warning' || item.status === 'unknown') ? 'degraded'
      : core.every(item => item.status === 'unknown') ? 'unknown' : 'healthy';
  const truncated = evidence.address.data?.ipv6.truncated === true ||
    evidence.routingPolicy.data?.permittedInterfaces.truncated === true || evidence.logs.data?.truncated === true;
  const supplementalComplete = evidence.connection.data?.interfaceStateAvailable !== false &&
    (evidence.wifi.data?.applicable !== true || evidence.wifi.data.interfaceStateAvailable &&
      evidence.wifi.data.associationStateAvailable) &&
    (policy?.assigned === null || policy?.interfaceStatesAvailable !== false);
  return { schemaVersion: 1, status,
    complete: Object.values(evidence).every(item => item.status === 'available') && supplementalComplete,
    checks, findings, evidence, untrustedRouterData: true, truncated };
}

function bytes(report: DeviceDiagnosticReport): number {
  return Buffer.byteLength(JSON.stringify(redact(report), null, 2), 'utf8');
}

function halve<T>(value: ListEvidence<T>): boolean {
  if (value.items.length === 0) return false;
  value.items = value.items.slice(0, Math.floor(value.items.length / 2));
  value.shown = value.items.length;
  value.truncated = value.shown < value.total;
  return true;
}

export function budgetDeviceDiagnostic(report: DeviceDiagnosticReport, maxBytes: number): DeviceDiagnosticReport {
  const logs = report.evidence.logs.data;
  while (logs && bytes(report) > maxBytes && halve(logs)) report.truncated = true;
  const policyInterfaces = report.evidence.routingPolicy.data?.permittedInterfaces;
  while (policyInterfaces && bytes(report) > maxBytes && halve(policyInterfaces)) report.truncated = true;
  const ipv6 = report.evidence.address.data?.ipv6;
  while (ipv6 && bytes(report) > maxBytes && halve(ipv6)) report.truncated = true;
  if (bytes(report) > maxBytes && report.evidence.logs.data !== null) {
    report.evidence.logs = { status: 'unavailable', reason: 'response-too-large', data: null };
    report.complete = false;
    report.truncated = true;
  }
  if (bytes(report) > maxBytes && report.evidence.dhcpBinding.data !== null) {
    report.evidence.dhcpBinding = { status: 'unavailable', reason: 'response-too-large', data: null };
    report.complete = false;
    report.truncated = true;
  }
  if (bytes(report) > maxBytes && report.evidence.dnsContext.data !== null) {
    report.evidence.dnsContext = { status: 'unavailable', reason: 'response-too-large', data: null };
    report.complete = false;
    report.truncated = true;
  }
  report.truncated = report.truncated || report.evidence.address.data?.ipv6.truncated === true ||
    report.evidence.routingPolicy.data?.permittedInterfaces.truncated === true ||
    report.evidence.logs.data?.truncated === true;
  return report;
}
