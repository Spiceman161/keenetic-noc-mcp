import { capText } from './budget.js';
import type { Capabilities } from '../router/capabilities.js';
import type { ConfigState } from '../router/config-state.js';
import type { LogEntry } from '../tools/logs.js';
import { redact, redactText } from '../security/redact.js';

export type DiagnosticStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
export type CheckStatus = 'pass' | 'warning' | 'fail' | 'unknown';
export type SafeReason =
  | 'not-supported'
  | 'rci-error'
  | 'transport-error'
  | 'authentication-error'
  | 'response-too-large'
  | 'unexpected-response';

export interface Evidence<T> {
  status: 'available' | 'unavailable';
  reason: SafeReason | null;
  data: T | null;
}

export interface ListEvidence<T> {
  items: T[];
  shown: number;
  total: number;
  truncated: boolean;
}

export interface SystemEvidence {
  model: string;
  firmware: string;
  versionAvailable: boolean;
  uptimeSeconds: number | null;
  cpuLoad: number | null;
  memoryTotalKb: number | null;
  memoryFreeKb: number | null;
  connectionsTotal: number | null;
  connectionsFree: number | null;
}

export interface InternetEvidence {
  checked: boolean | null;
  checkedAt: string | null;
  enabled: boolean | null;
  reliable: boolean | null;
  gatewayAccessible: boolean | null;
  dnsAccessible: boolean | null;
  captiveAccessible: boolean | null;
  internet: boolean | null;
  gatewayInterface: string | null;
}

export interface InterfaceEvidence {
  id: string;
  type: string;
  link: string;
  state: string;
  connected: boolean | null;
  global: boolean | null;
  defaultGateway: boolean | null;
  internetRole: boolean | null;
}

export interface VpnEvidence extends InterfaceEvidence {
  peersTotal: number;
  peersKnown: number;
  peersOnline: number;
  underlayInterfaces: string[];
}

export interface RouteEvidence {
  destination: '0.0.0.0/0';
  interface: string;
  metric: number | null;
  rejecting: boolean | null;
  floating: boolean | null;
  static: boolean | null;
  proto: string;
  gatewayPresent: boolean;
}

export interface DnsUpstreamEvidence {
  protocol: string;
  status: string;
}

export interface DnsEvidence {
  status: string;
  enabled: boolean | null;
  upstreams: ListEvidence<DnsUpstreamEvidence>;
  staticHostsCount: number;
  errorCount: number;
}

export interface PublicLogEntry {
  timestamp: string | null;
  ident: string | null;
  level: string | null;
  label: string | null;
  line: string;
}

export interface LogEvidence extends ListEvidence<PublicLogEntry> {
  scanned: number;
  matched: number;
  untrusted: true;
}

export interface DiagnosticEvidence {
  system: Evidence<SystemEvidence>;
  internet: Evidence<InternetEvidence>;
  interfaces: Evidence<ListEvidence<InterfaceEvidence>>;
  routes: Evidence<ListEvidence<RouteEvidence>>;
  dns: Evidence<DnsEvidence>;
  vpn: Evidence<ListEvidence<VpnEvidence>>;
  logs: Evidence<LogEvidence>;
  configuration: Evidence<ConfigState>;
}

export interface DiagnosticCheck {
  id: 'system' | 'internet' | 'wan-link' | 'default-route' | 'dns' |
    'vpn-default-route' | 'recent-logs' | 'configuration-state';
  status: CheckStatus;
  summary: string;
}

export interface DiagnosticFinding {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  summary: string;
  relatedChecks: DiagnosticCheck['id'][];
}

export interface InternetDiagnosticReport {
  schemaVersion: 1;
  status: DiagnosticStatus;
  complete: boolean;
  checks: DiagnosticCheck[];
  findings: DiagnosticFinding[];
  evidence: DiagnosticEvidence;
  untrustedRouterData: true;
  truncated: boolean;
}

const VPN = /wireguard|ipsec|openvpn|l2tp|pptp|sstp|openconnect|vpn/i;
const BAD_STATE = new Set(['down', 'error', 'failed', 'disabled', 'offline', 'unavailable']);
const LOG_TERMS = [
  'internet', 'gateway', 'ndhcpc', 'dns-proxy', 'https-dns-proxy',
  'wireguard', 'openvpn', 'ipsec', 'l2tp', 'pptp', 'sstp'
] as const;

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function safeString(value: unknown, max = 120): string {
  if (typeof value !== 'string' && typeof value !== 'number') return '';
  const raw = redactText(String(value)
    .replace(/\u001b\][^\u0007]*(?:\u0007|$)/g, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim());
  return Array.from(raw).slice(0, max).join('');
}

function nullableBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function connected(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (value === 'yes' || value === 'up') return true;
  if (value === 'no' || value === 'down') return false;
  return null;
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

export function available<T>(data: T): Evidence<T> {
  return { status: 'available', reason: null, data };
}

export function unavailable<T>(reason: SafeReason): Evidence<T> {
  return { status: 'unavailable', reason, data: null };
}

export function projectSystem(
  raw: unknown,
  capabilities: Capabilities,
  versionAvailable = true
): SystemEvidence {
  const value = record(raw);
  return {
    model: safeString(capabilities.model),
    firmware: safeString(capabilities.firmware),
    versionAvailable,
    uptimeSeconds: nullableNumber(value['uptime']),
    cpuLoad: nullableNumber(value['cpuload']),
    memoryTotalKb: nullableNumber(value['memtotal']),
    memoryFreeKb: nullableNumber(value['memfree']),
    connectionsTotal: nullableNumber(value['conntotal']),
    connectionsFree: nullableNumber(value['connfree'])
  };
}

export function projectInternet(raw: unknown): InternetEvidence {
  const value = record(raw);
  const gateway = record(value['gateway']);
  const checkedRaw = value['checked'];
  return {
    checked: typeof checkedRaw === 'boolean' ? checkedRaw : typeof checkedRaw === 'string' && checkedRaw !== '' ? true : null,
    checkedAt: typeof checkedRaw === 'string' ? safeString(checkedRaw) || null : null,
    enabled: nullableBoolean(value['enabled']),
    reliable: nullableBoolean(value['reliable']),
    gatewayAccessible: nullableBoolean(value['gateway-accessible']),
    dnsAccessible: nullableBoolean(value['dns-accessible']),
    captiveAccessible: nullableBoolean(value['captive-accessible']),
    internet: nullableBoolean(value['internet']),
    gatewayInterface: safeString(gateway['interface']) || null
  };
}

function peerRecords(item: Record<string, unknown>): Record<string, unknown>[] {
  const protocol = Object.keys(record(item['wireguard'])).length > 0 ? record(item['wireguard']) : item;
  const raw = protocol['peer'] ?? protocol['peers'];
  return Array.isArray(raw) ? raw.map(record) : Object.values(record(raw)).map(record);
}

export function projectInterfaces(raw: unknown): {
  interfaces: ListEvidence<InterfaceEvidence>;
  vpn: ListEvidence<VpnEvidence>;
} {
  const interfaces: InterfaceEvidence[] = [];
  const vpn: VpnEvidence[] = [];
  for (const [rawId, rawValue] of Object.entries(record(raw))) {
    const value = record(rawValue);
    const embeddedId = safeString(value['id']);
    const id = embeddedId || (/^\d+$/.test(rawId) ? '' : safeString(rawId));
    if (!id) continue;
    const base: InterfaceEvidence = {
      id,
      type: safeString(value['type']),
      link: safeString(value['link']),
      state: safeString(value['state']),
      connected: connected(value['connected']),
      global: nullableBoolean(value['global']),
      defaultGateway: nullableBoolean(value['defaultgw']),
      internetRole: typeof value['role'] === 'string' ? value['role'] === 'inet' : null
    };
    interfaces.push(base);
    if (!VPN.test(`${id} ${base.type}`)) continue;
    const peers = peerRecords(value);
    let peersKnown = 0;
    let peersOnline = 0;
    const underlayInterfaces = new Set<string>();
    for (const peer of peers) {
      const online = nullableBoolean(peer['online']) ??
        (peer['link'] === 'up' ? true : peer['link'] === 'down' ? false : null);
      if (online !== null) {
        peersKnown += 1;
        if (online) peersOnline += 1;
      }
      const via = safeString(peer['via']);
      if (via) underlayInterfaces.add(via);
    }
    vpn.push({
      ...base,
      peersTotal: peers.length,
      peersKnown,
      peersOnline,
      underlayInterfaces: [...underlayInterfaces].sort()
    });
  }
  interfaces.sort((a, b) => a.id.localeCompare(b.id));
  vpn.sort((a, b) => a.id.localeCompare(b.id));
  return { interfaces: list(interfaces), vpn: list(vpn) };
}

export function projectDefaultRoutes(raw: unknown): ListEvidence<RouteEvidence> {
  const rows = Array.isArray(raw) ? raw : [];
  const routes = rows.flatMap(row => {
    const value = record(row);
    if (value['destination'] !== '0.0.0.0/0') return [];
    const gateway = typeof value['gateway'] === 'string' ? value['gateway'] : '';
    return [{
      destination: '0.0.0.0/0' as const,
      interface: safeString(value['interface']),
      metric: nullableNumber(value['metric']),
      rejecting: nullableBoolean(value['rejecting']),
      floating: nullableBoolean(value['floating']),
      static: nullableBoolean(value['static']),
      proto: safeString(value['proto']),
      gatewayPresent: gateway !== '' && gateway !== '0.0.0.0'
    }];
  });
  return list(routes);
}

function count(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return value === undefined || value === null || value === '' ? 0 : 1;
}

export function projectDns(raw: unknown): DnsEvidence {
  const root = record(raw);
  const proxy = record(root['proxy-status'] ?? root['dns-proxy'] ?? root);
  const candidates = proxy['server'] ?? proxy['servers'] ?? proxy['upstream'];
  const values = Array.isArray(candidates) ? candidates : Object.values(record(candidates));
  const upstreams = values.map(value => {
    const upstream = record(value);
    return {
      protocol: safeString(upstream['protocol'] ?? upstream['type']),
      status: safeString(upstream['status'] ?? upstream['state'])
    };
  });
  return {
    status: safeString(proxy['status'] ?? proxy['state']),
    enabled: nullableBoolean(proxy['enabled']),
    upstreams: list(upstreams),
    staticHostsCount: count(proxy['host'] ?? root['host']),
    errorCount: count(proxy['error'] ?? proxy['errors'])
  };
}

function publicLogEntry(entry: LogEntry): PublicLogEntry {
  return {
    timestamp: safeString(entry.timestamp) || null,
    ident: safeString(entry.ident) || null,
    level: safeString(entry.level) || null,
    label: safeString(entry.label) || null,
    line: capText(safeString(entry.line, 2_000), 512)
  };
}

export function projectRelatedLogs(entries: readonly LogEntry[], interfaceIds: readonly string[]): LogEvidence {
  const needles = [...LOG_TERMS, ...interfaceIds].map(value => value.toLocaleLowerCase());
  const matched = entries.filter(entry => {
    const searchable = [entry.ident, entry.label, entry.line].filter((value): value is string => value !== null)
      .join(' ').toLocaleLowerCase();
    return needles.some(needle => searchable.includes(needle));
  });
  const items = matched.slice(-20).map(publicLogEntry);
  return {
    ...list(items, matched.length),
    scanned: entries.length,
    matched: matched.length,
    untrusted: true
  };
}

export function projectConfiguration(state: ConfigState): ConfigState {
  const seconds = state.failSafe.secondsLeft;
  return {
    lastChangedAt: safeString(state.lastChangedAt) || null,
    lastChangedBy: safeString(state.lastChangedBy) || null,
    lastChangedVia: safeString(state.lastChangedVia) || null,
    runningChecksum: safeString(state.runningChecksum, 64) || null,
    savedChecksum: safeString(state.savedChecksum, 64) || null,
    unsavedChanges: state.unsavedChanges,
    failSafe: {
      unsaved: state.failSafe.unsaved,
      rollbackPending: state.failSafe.rollbackPending,
      secondsLeft: nullableNumber(seconds)
    }
  };
}

function down(iface: InterfaceEvidence): boolean {
  return BAD_STATE.has(iface.link.toLocaleLowerCase()) ||
    BAD_STATE.has(iface.state.toLocaleLowerCase()) || iface.connected === false;
}

function up(iface: InterfaceEvidence): boolean {
  return !down(iface) && (iface.link.toLocaleLowerCase() === 'up' ||
    iface.state.toLocaleLowerCase() === 'up' || iface.connected === true);
}

function usableRoutes(evidence: DiagnosticEvidence): RouteEvidence[] {
  return evidence.routes.data?.items.filter(route => route.rejecting !== true) ?? [];
}

function internetEvidenceCurrent(internet: InternetEvidence | null): boolean {
  return internet?.checked === true && internet.enabled !== false && internet.reliable !== false;
}

function activeRoutes(evidence: DiagnosticEvidence): {
  items: RouteEvidence[];
  ambiguous: boolean;
} {
  const defaults = new Set((evidence.interfaces.data?.items ?? [])
    .filter(iface => iface.defaultGateway === true).map(iface => iface.id));
  return selectActiveRouteList(
    usableRoutes(evidence),
    internetEvidenceCurrent(evidence.internet.data)
      ? evidence.internet.data?.gatewayInterface ?? null
      : null,
    defaults
  );
}

function selectActiveRouteList(
  routes: RouteEvidence[],
  gatewayInterface: string | null,
  defaultGatewayInterfaces: ReadonlySet<string> = new Set()
): {
  items: RouteEvidence[];
  ambiguous: boolean;
} {
  if (routes.length === 0) return { items: [], ambiguous: false };
  if (gatewayInterface) {
    const selected = routes.filter(route => route.interface === gatewayInterface);
    if (selected.length > 0) return { items: selected, ambiguous: false };
    return { items: [], ambiguous: true };
  }
  if (routes.length === 1) return { items: routes, ambiguous: false };
  const marked = routes.filter(route => defaultGatewayInterfaces.has(route.interface));
  if (marked.length === 1) return { items: marked, ambiguous: false };
  const metrics = routes.map(route => route.metric).filter((metric): metric is number => metric !== null);
  if (metrics.length === routes.length) {
    const minimum = Math.min(...metrics);
    const selected = routes.filter(route => route.metric === minimum);
    if (selected.length === 1) return { items: selected, ambiguous: false };
  }
  return { items: [], ambiguous: true };
}

export function relatedInterfaceIds(
  internet: InternetEvidence | null,
  routes: ListEvidence<RouteEvidence> | null,
  interfaces: ListEvidence<InterfaceEvidence> | null,
  vpns: ListEvidence<VpnEvidence> | null
): string[] {
  const active = selectActiveRouteList(
    routes?.items.filter(route => route.rejecting !== true) ?? [],
    internetEvidenceCurrent(internet) ? internet?.gatewayInterface ?? null : null,
    new Set((interfaces?.items ?? []).filter(iface => iface.defaultGateway === true)
      .map(iface => iface.id))
  );
  const selected = new Set(active.items.map(route => route.interface).filter(Boolean));
  for (const iface of interfaces?.items ?? []) {
    if (iface.global === true || iface.defaultGateway === true || iface.internetRole === true ||
      VPN.test(`${iface.id} ${iface.type}`)) selected.add(iface.id);
  }
  for (const vpn of vpns?.items ?? []) {
    if (!selected.has(vpn.id)) continue;
    for (const underlay of vpn.underlayInterfaces) selected.add(underlay);
  }
  return [...selected].sort();
}

function finding(
  id: string,
  severity: DiagnosticFinding['severity'],
  summary: string,
  relatedChecks: DiagnosticCheck['id'][]
): DiagnosticFinding {
  return { id, severity, summary, relatedChecks };
}

function check(id: DiagnosticCheck['id'], status: CheckStatus, summary: string): DiagnosticCheck {
  return { id, status, summary };
}

export function buildInternetDiagnostic(evidence: DiagnosticEvidence): InternetDiagnosticReport {
  const findings: DiagnosticFinding[] = [];
  const internet = evidence.internet.data;
  const routes = usableRoutes(evidence);
  const active = activeRoutes(evidence);
  const interfaces = evidence.interfaces.data?.items ?? [];
  const vpns = evidence.vpn.data?.items ?? [];
  const internetCurrent = internetEvidenceCurrent(internet);
  const internetConflict = internetCurrent && internet?.internet === true &&
    (internet?.gatewayAccessible === false || internet?.dnsAccessible === false);

  if (internetCurrent && internet?.gatewayAccessible === false && !internetConflict) {
    findings.push(finding('gateway-unreachable', 'critical',
      'The router explicitly reports that its gateway is unreachable.', ['internet', 'wan-link']));
  }
  if (internetCurrent && internet?.internet === false) {
    findings.push(finding('internet-check-failed', 'critical',
      'The router explicitly reports that its internet check failed.', ['internet']));
  }
  if (evidence.routes.status === 'available' && routes.length === 0) {
    const confirmed = internetCurrent && internet?.internet === false;
    findings.push(finding('missing-default-route', confirmed ? 'critical' : 'warning',
      confirmed
        ? 'No usable non-rejecting IPv4 default route was found while the internet check is failing.'
        : 'No usable IPv4 default route was found, but an IPv4 outage is not confirmed.',
      ['default-route', 'internet']));
  }
  if (internetCurrent && internet?.gatewayAccessible === true && internet.dnsAccessible === false &&
    internet.internet !== true) {
    findings.push(finding('dns-unreachable', 'critical',
      'The gateway is reachable but the router explicitly reports DNS as unreachable.', ['dns', 'internet']));
  }
  if (internetConflict) {
    findings.push(finding('conflicting-internet-evidence', 'warning',
      'The internet-status fields conflict, so no causal failure is asserted from them.', ['internet', 'dns']));
  }
  if (active.ambiguous) {
    findings.push(finding('ambiguous-default-route', 'warning',
      'IPv4 default-route evidence is conflicting or ambiguous, so the active path cannot be selected confidently.',
      ['default-route', 'wan-link', 'vpn-default-route']));
  }

  const dns = evidence.dns.data;
  const dnsStates = dns?.upstreams.items.map(item => item.status.toLocaleLowerCase()).filter(Boolean) ?? [];
  const dnsHealthy = dns !== null && dns !== undefined && (
    ['up', 'running', 'available', 'online'].includes(dns.status.toLocaleLowerCase()) ||
    dnsStates.some(state => ['up', 'running', 'available', 'online'].includes(state))
  );
  const dnsUnhealthy = dns !== null && dns !== undefined && (
    dns.enabled === false || BAD_STATE.has(dns.status.toLocaleLowerCase()) || dns.errorCount > 0 ||
    (dnsStates.length > 0 && dnsStates.every(state => BAD_STATE.has(state)))
  );
  if (dnsUnhealthy) {
    findings.push(finding('dns-proxy-unhealthy', 'warning',
      'The DNS proxy or all explicitly reported upstream resolvers are unhealthy.', ['dns']));
  }

  const defaultInterfaces = new Set(active.items.map(route => route.interface).filter(Boolean));
  const defaultVpns = vpns.filter(vpn => defaultInterfaces.has(vpn.id));
  const underlays = new Set(defaultVpns.flatMap(vpn => vpn.underlayInterfaces));
  const physical = interfaces.filter(iface => !VPN.test(`${iface.id} ${iface.type}`));
  const globalPhysical = physical.filter(iface => iface.global === true || iface.defaultGateway === true ||
    iface.internetRole === true);
  const relevantDown = physical.filter(iface => down(iface) && (
    defaultInterfaces.has(iface.id) || underlays.has(iface.id) ||
    (globalPhysical.length === 1 && globalPhysical[0]?.id === iface.id && internetCurrent &&
      !internetConflict && internet?.gatewayAccessible === false)
  ));
  if (relevantDown.length > 0) {
    findings.push(finding('physical-uplink-down', 'critical',
      'A physical interface required by the active internet path is explicitly down.', ['wan-link', 'default-route']));
  }

  for (const vpn of defaultVpns) {
    const peersExplicitlyOffline = vpn.peersTotal > 0 && vpn.peersKnown === vpn.peersTotal && vpn.peersOnline === 0;
    if (down(vpn) || peersExplicitlyOffline) {
      findings.push(finding('vpn-default-route-down', 'critical',
        'The active IPv4 default-route VPN path is unavailable: its interface is down or all explicitly reported peers are offline.',
        ['vpn-default-route', 'default-route']));
    } else if (up(vpn) || vpn.peersOnline > 0) {
      findings.push(finding('vpn-default-route-active', 'info',
        'The active IPv4 default route uses a VPN interface.', ['vpn-default-route', 'default-route']));
    }
  }

  if (evidence.configuration.data?.unsavedChanges === true) {
    findings.push(finding('unsaved-configuration', 'info',
      'Unsaved configuration exists. This is context only and does not establish the cause.',
      ['configuration-state']));
  }

  const internetStatus: CheckStatus = evidence.internet.status === 'unavailable' || !internetCurrent || internetConflict ? 'unknown'
    : internet?.internet === false || internet?.gatewayAccessible === false ? 'fail'
      : internet?.internet === true ? 'pass' : 'unknown';
  const routeStatus: CheckStatus = evidence.routes.status === 'unavailable' ? 'unknown'
    : active.ambiguous || (routes.length === 0 && internet?.internet === true) ? 'warning'
      : routes.length > 0 ? 'pass' : internetCurrent && internet?.internet === false ? 'fail' : 'warning';
  const wanStatus: CheckStatus = evidence.interfaces.status === 'unavailable' ? 'unknown'
    : relevantDown.length > 0 ? 'fail'
      : physical.some(iface => (iface.global === true || iface.defaultGateway === true ||
        iface.internetRole === true) && up(iface)) ? 'pass' : 'unknown';
  const dnsStatus: CheckStatus = internetConflict ? 'unknown'
    : internetCurrent && internet?.gatewayAccessible === true && internet.dnsAccessible === false ? 'fail'
    : dnsUnhealthy ? 'warning'
      : (internetCurrent && internet?.dnsAccessible === true) || dnsHealthy ? 'pass'
        : evidence.dns.status === 'unavailable' ? 'unknown' : 'unknown';
  const knownInterfaces = new Set(interfaces.map(iface => iface.id));
  const defaultRouteUnknown = active.items.some(route => !knownInterfaces.has(route.interface));
  const vpnStatus: CheckStatus = evidence.vpn.status === 'unavailable' || evidence.routes.status === 'unavailable' ||
    routes.length === 0 || active.ambiguous || defaultRouteUnknown ? 'unknown'
    : findings.some(item => item.id === 'vpn-default-route-down') ? 'fail'
      : defaultVpns.some(vpn => !up(vpn) && vpn.peersOnline === 0) ? 'unknown' : 'pass';

  const checks: DiagnosticCheck[] = [
    check('system', evidence.system.status === 'available' && evidence.system.data?.versionAvailable === true
      ? 'pass' : evidence.system.status === 'available' ? 'warning' : 'unknown',
    evidence.system.status === 'available' && evidence.system.data?.versionAvailable === true
      ? 'System health and version evidence are available.'
      : evidence.system.status === 'available' ? 'System health is available but version evidence is unavailable.'
        : 'System health evidence is unavailable.'),
    check('internet', internetStatus, internetStatus === 'pass' ? 'The router internet check passes.' :
      internetStatus === 'fail' ? 'The router reports an internet or gateway failure.' : 'Internet reachability is unknown.'),
    check('wan-link', wanStatus, wanStatus === 'pass' ? 'A global physical uplink is up.' :
      wanStatus === 'fail' ? 'A physical uplink required by the active path is down.' : 'WAN link health is unknown.'),
    check('default-route', routeStatus, routeStatus === 'pass' ? 'A usable IPv4 default route exists.' :
      routeStatus === 'fail' ? 'No usable IPv4 default route exists.' :
        routeStatus === 'warning' ? 'IPv4 default-route evidence is absent, conflicting, or ambiguous.'
          : 'IPv4 default-route state is unknown.'),
    check('dns', dnsStatus, dnsStatus === 'pass' ? 'DNS reachability evidence passes.' :
      dnsStatus === 'fail' ? 'The router reports DNS as unreachable.' :
        dnsStatus === 'warning' ? 'The DNS proxy reports an anomaly.' : 'DNS health is unknown.'),
    check('vpn-default-route', vpnStatus, vpnStatus === 'fail' ? 'The default-route VPN path is unavailable.' :
      vpnStatus === 'unknown' ? 'VPN default-route influence is unknown.' :
        defaultVpns.length > 0 ? 'An available VPN carries the default route.' : 'No VPN carries the default route.'),
    check('recent-logs', evidence.logs.status === 'available' ? 'pass' : 'unknown',
      evidence.logs.status === 'available' ? 'Bounded related logs were collected as untrusted evidence.' : 'Related logs are unavailable.'),
    check('configuration-state', evidence.configuration.status === 'unavailable' ||
      evidence.configuration.data?.unsavedChanges === null ? 'unknown'
      : evidence.configuration.data?.unsavedChanges === true ? 'warning' : 'pass',
    evidence.configuration.status === 'unavailable' ? 'Configuration state is unavailable.'
      : evidence.configuration.data?.unsavedChanges === true ? 'Unsaved configuration exists as non-causal context.'
        : evidence.configuration.data?.unsavedChanges === null ? 'Saved-state comparison is unknown.' : 'No unsaved configuration was detected.')
  ];

  const core = checks.filter(item => ['internet', 'wan-link', 'default-route', 'dns', 'vpn-default-route'].includes(item.id));
  const conclusive = core.filter(item => item.status === 'pass' || item.status === 'fail');
  const status: DiagnosticStatus = findings.some(item => item.severity === 'critical') ||
    core.some(item => item.status === 'fail') ? 'unhealthy'
    : conclusive.length === 0 ? 'unknown'
      : core.some(item => item.status === 'warning' || item.status === 'unknown') ||
        findings.some(item => item.severity === 'warning') ||
        checks.some(item => item.id === 'system' && item.status === 'warning') ? 'degraded' : 'healthy';

  return {
    schemaVersion: 1,
    status,
    complete: Object.values(evidence).every(item => item.status === 'available') &&
      evidence.configuration.data?.unsavedChanges !== null &&
      evidence.system.data?.versionAvailable === true,
    checks,
    findings,
    evidence,
    untrustedRouterData: true,
    truncated: false
  };
}

function serialisedBytes(report: InternetDiagnosticReport): number {
  return Buffer.byteLength(JSON.stringify(redact(report), null, 2), 'utf8');
}

function halve<T>(value: ListEvidence<T>): boolean {
  if (value.items.length === 0) return false;
  value.items = value.items.slice(0, Math.floor(value.items.length / 2));
  value.shown = value.items.length;
  value.truncated = value.shown < value.total;
  return true;
}

/** Keeps checks/findings stable while dropping the least important evidence first. */
export function budgetInternetDiagnostic(
  report: InternetDiagnosticReport,
  maxBytes: number
): InternetDiagnosticReport {
  const shrink = <T>(value: ListEvidence<T> | null | undefined): void => {
    if (!value) return;
    while (serialisedBytes(report) > maxBytes && halve(value)) {
      report.truncated = true;
    }
  };
  shrink(report.evidence.logs.data);
  shrink(report.evidence.routes.data);
  shrink(report.evidence.interfaces.data);
  shrink(report.evidence.dns.data?.upstreams);
  shrink(report.evidence.vpn.data);
  if (serialisedBytes(report) > maxBytes) {
    // The final `ok` call remains the hard boundary when even the fixed
    // schema/check/finding envelope cannot fit the operator's configured cap.
    report.truncated = true;
  }
  return report;
}
