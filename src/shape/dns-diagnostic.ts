import { isIP } from 'node:net';
import { redact, redactText } from '../security/redact.js';
import type { LogEntry } from '../tools/logs.js';
import type { CheckStatus, DiagnosticStatus, Evidence, ListEvidence, PublicLogEntry } from './internet-diagnostic.js';

export type DnsProtocol = 'plain' | 'dot' | 'doh' | 'doh3' | 'unknown';
export type DnsUpstreamSource = 'runtime' | 'dns-proxy-config' | 'name-server-config';

export interface DnsUpstreamObservation {
  source: DnsUpstreamSource;
  scope: string | null;
  protocol: DnsProtocol;
  status: string | null;
  address: string | null;
  port: number | null;
  endpoint: string | null;
  tlsServerName: string | null;
  interface: string | null;
  domain: string | null;
}

export interface DnsProxyEvidence {
  enabled: boolean | null;
  status: string | null;
  staticHostsCount: number;
  errorCount: number;
  upstreams: ListEvidence<DnsUpstreamObservation>;
}

export interface DnsInternetEvidence {
  current: boolean;
  gatewayAccessible: boolean | null;
  dnsAccessible: boolean | null;
  internet: boolean | null;
}

export interface DnsRouteEvidence {
  address: string | null;
  endpoint: string | null;
  interface: string | null;
  destination: string | null;
  state: 'available' | 'unavailable' | 'ambiguous' | 'not-exposed';
}

export interface DnsLogEvidence extends ListEvidence<PublicLogEntry> {
  scanned: number;
  matched: number;
  untrusted: true;
}

export interface DnsDiagnosticEvidence {
  proxyRuntime: Evidence<DnsProxyEvidence>;
  internetReachability: Evidence<DnsInternetEvidence>;
  dnsProxyConfig: Evidence<ListEvidence<DnsUpstreamObservation>>;
  nameServerConfig: Evidence<ListEvidence<DnsUpstreamObservation>>;
  routing: Evidence<ListEvidence<DnsRouteEvidence>>;
  logs: Evidence<DnsLogEvidence>;
}

export interface DnsDiagnosticCheck {
  id: 'proxy-runtime' | 'internet-dns-reachability' | 'upstream-configuration' |
    'encryption' | 'routing' | 'recent-logs';
  status: CheckStatus;
  summary: string;
}

export interface DnsDiagnosticFinding {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  summary: string;
  relatedChecks: DnsDiagnosticCheck['id'][];
}

export interface DnsDiagnosticReport {
  schemaVersion: 1;
  status: DiagnosticStatus;
  complete: boolean;
  checks: DnsDiagnosticCheck[];
  findings: DnsDiagnosticFinding[];
  evidence: DnsDiagnosticEvidence;
  untrustedRouterData: true;
  truncated: boolean;
}

const BAD = new Set(['down', 'error', 'failed', 'disabled', 'offline', 'unavailable']);
const GOOD = new Set(['up', 'ok', 'ready', 'running', 'available', 'online', 'connected']);
const DNS_LOG = /(?:^|[^a-z])(?:dns-proxy|https-dns-proxy|resolver|dot|doh|doh3|tls)(?:[^a-z]|$)/i;

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const RUNTIME_KEYS = new Set([
  'enabled', 'status', 'state', 'server', 'servers', 'upstream', 'host', 'error', 'errors'
]);
const UPSTREAM_KEYS = new Set([
  'address', 'server', 'host', 'url', 'uri', 'endpoint', 'protocol', 'type', 'transport',
  'status', 'state', 'tls-name', 'sni', 'server-name', 'interface', 'via', 'domain', 'suffix',
  'port', 'fqdn', 'format', 'spki'
]);

function hasKnownKey(value: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).some(key => keys.has(key));
}

function validUpstreamContainer(value: unknown): boolean {
  if (value === undefined) return true;
  if (Array.isArray(value)) return value.every(validUpstreamRow);
  const rows = candidateValues(value);
  return rows.length > 0 && rows.every(validUpstreamRow);
}

function validUpstreamRow(value: unknown): boolean {
  if (typeof value === 'string') {
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
      ? cleanDnsEndpoint(value) !== null
      : safeDnsIdentifier(value) !== null;
  }
  const row = record(value);
  if (!hasKnownKey(row, UPSTREAM_KEYS)) return false;
  for (const key of UPSTREAM_KEYS) {
    if (row[key] !== undefined && key !== 'port' && typeof row[key] !== 'string') return false;
  }
  for (const key of ['url', 'uri', 'endpoint'] as const) {
    if (row[key] !== undefined && cleanDnsEndpoint(row[key]) === null) return false;
  }
  if (row['port'] !== undefined && (typeof row['port'] !== 'number' || !Number.isInteger(row['port']) ||
    row['port'] < 1 || row['port'] > 65_535)) return false;
  return true;
}

function validHttpsUpstreamContainer(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  return value.every(item => {
    if (!validUpstreamRow(item)) return false;
    const row = record(item);
    const endpoint = cleanDnsEndpoint(row['url'] ?? row['uri'] ?? row['endpoint']);
    return endpoint !== null && new URL(endpoint).protocol === 'https:';
  });
}

function validMeasuredRuntimeProxy(value: unknown): boolean {
  const proxy = record(value);
  for (const key of ['proxy-name', 'proxy-config', 'proxy-stat'] as const) {
    if (proxy[key] !== undefined && typeof proxy[key] !== 'string') return false;
  }
  if (proxy['proxy-tls'] !== undefined && (!isPlainRecord(proxy['proxy-tls']))) return false;
  if (proxy['proxy-https'] !== undefined && (!isPlainRecord(proxy['proxy-https']))) return false;
  const tls = record(proxy['proxy-tls']);
  const https = record(proxy['proxy-https']);
  const tlsRows = tls['server-tls'];
  const httpsRows = https['server-https'];
  if (tlsRows !== undefined && (!Array.isArray(tlsRows) || !validUpstreamContainer(tlsRows))) return false;
  if (httpsRows !== undefined && !validHttpsUpstreamContainer(httpsRows)) return false;
  return Array.isArray(tlsRows) || Array.isArray(httpsRows) || typeof proxy['proxy-name'] === 'string';
}

export function isDnsRuntimeShape(raw: unknown): boolean {
  const root = record(raw);
  if (Object.keys(root).length === 0) return false;
  if (Array.isArray(root['proxy-status'])) {
    return root['proxy-status'].length > 0 && root['proxy-status'].every(validMeasuredRuntimeProxy);
  }
  const wrapped = root['proxy-status'] ?? root['dns-proxy'];
  const proxy = wrapped === undefined ? root : record(wrapped);
  if (Object.keys(proxy).length === 0 || !hasKnownKey(proxy, RUNTIME_KEYS)) return false;
  for (const key of ['enabled'] as const) {
    if (proxy[key] !== undefined && typeof proxy[key] !== 'boolean') return false;
  }
  for (const key of ['status', 'state'] as const) {
    if (proxy[key] !== undefined && typeof proxy[key] !== 'string') return false;
  }
  return validUpstreamContainer(proxy['server'] ?? proxy['servers'] ?? proxy['upstream']);
}

export function isDnsConfigShape(raw: unknown, source: Exclude<DnsUpstreamSource, 'runtime'>): boolean {
  if (Array.isArray(raw)) return source === 'name-server-config' && validUpstreamContainer(raw);
  const root = record(raw);
  if (Object.keys(root).length === 0) return false;
  if (source === 'dns-proxy-config') {
    const measuredKeys = ['tls', 'https'].filter(key => root[key] !== undefined);
    const measured = measuredKeys.length > 0 && measuredKeys.every(key => {
      if (!isPlainRecord(root[key])) return false;
      const upstream = record(root[key])['upstream'];
      return key === 'https' ? validHttpsUpstreamContainer(upstream)
        : Array.isArray(upstream) && validUpstreamContainer(upstream);
    });
    const route = root['route'];
    if (route !== undefined && !Array.isArray(route)) return false;
    if (measuredKeys.length > 0) return measured;
    const wrapped = root['dns-proxy'];
    const proxy = wrapped === undefined ? root : record(wrapped);
    if (proxy['enabled'] !== undefined && typeof proxy['enabled'] !== 'boolean') return false;
    if (proxy['status'] !== undefined && typeof proxy['status'] !== 'string') return false;
    if (proxy['state'] !== undefined && typeof proxy['state'] !== 'string') return false;
    return hasKnownKey(proxy, RUNTIME_KEYS) &&
      validUpstreamContainer(proxy['server'] ?? proxy['servers'] ?? proxy['upstream']);
  }
  const candidate = root['name-server'] ?? root['server'];
  if (candidate !== undefined) return validUpstreamContainer(candidate);
  return false;
}

function safeString(value: unknown, max = 512): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const cleaned = redactText(String(value)
    .replace(/\u001b\][^\u0007]*(?:\u0007|$)/g, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim());
  const characters = Array.from(cleaned);
  if (characters.length <= max) return cleaned || null;
  for (const marker of ['[REDACTED_KEY]', '[REDACTED]']) {
    const index = cleaned.lastIndexOf(marker, max);
    if (index >= 0 && index + marker.length > max) {
      return `${characters.slice(0, Math.max(0, max - marker.length)).join('').slice(0, index)}${marker}`;
    }
  }
  return characters.slice(0, max).join('') || null;
}

function safeRouterString(value: unknown, max = 512): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  return safeString(sanitizeUrls(String(value)), max);
}

export function cleanDnsEndpoint(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const raw = String(value)
    .replace(/\u001b\][^\u0007]*(?:\u0007|$)/g, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (raw.length === 0 || Array.from(raw).length > 4096) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return null;
  try {
    const url = new URL(raw);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    const segments = url.pathname.split('/').filter(Boolean);
    url.pathname = segments.length === 0 ? '/' : `/${segments.at(-1)}`;
    return safeString(url.toString());
  } catch {
    // A URL-looking value that cannot be parsed cannot be safely stripped of
    // credentials or query secrets. Omit it rather than returning it raw.
    return null;
  }
}

function safeDnsIdentifier(value: unknown): string | null {
  const raw = safeString(value);
  if (raw === null || /[@/?#=\s]/.test(raw)) return null;
  if (isIP(raw) !== 0) return raw;
  return /^(?=.{1,253}$)(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)*[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?$/u.test(raw)
    ? raw
    : null;
}

export function normalizeDnsProtocol(value: unknown, endpoint?: unknown): DnsProtocol {
  const raw = `${safeString(value) ?? ''} ${safeString(endpoint) ?? ''}`.toLocaleLowerCase();
  if (/\bdoh3\b|http\/3|\bquic\b/.test(raw)) return 'doh3';
  if (/\bdoh\b|https:|https-dns/.test(raw)) return 'doh';
  if (/\bdot\b|dns-over-tls|tls:/.test(raw)) return 'dot';
  if (/\b(?:plain|udp|tcp|dns)\b/.test(raw)) return 'plain';
  return 'unknown';
}

function observation(
  raw: unknown,
  source: DnsUpstreamSource,
  forcedProtocol?: DnsProtocol,
  scope: string | null = null
): DnsUpstreamObservation | null {
  if (typeof raw === 'string' || typeof raw === 'number') {
    const scalar = safeString(raw);
    const isEndpoint = scalar !== null && /^[a-z][a-z0-9+.-]*:\/\//i.test(scalar);
    const address = isEndpoint ? null : safeDnsIdentifier(scalar);
    const endpoint = isEndpoint ? cleanDnsEndpoint(scalar) : null;
    if (address === null && endpoint === null) return null;
    return { source, scope, protocol: forcedProtocol ?? (isEndpoint ? normalizeDnsProtocol(undefined, scalar) : 'plain'),
      status: null, address, port: null, endpoint,
      tlsServerName: null, interface: null, domain: null };
  }
  const value = record(raw);
  if (Object.keys(value).length === 0) return null;
  const addressRaw = value['address'] ?? value['server'] ?? value['host'];
  const serverLooksLikeEndpoint = typeof addressRaw === 'string' && /^[a-z][a-z0-9+.-]*:\/\//i.test(addressRaw);
  const endpointRaw = value['url'] ?? value['uri'] ?? value['endpoint'] ??
    (serverLooksLikeEndpoint ? addressRaw : undefined);
  const address = serverLooksLikeEndpoint ? null : safeDnsIdentifier(addressRaw);
  const endpoint = cleanDnsEndpoint(endpointRaw);
  const tlsServerName = safeDnsIdentifier(value['tls-name'] ?? value['sni'] ?? value['server-name']);
  const fqdn = safeDnsIdentifier(value['fqdn']);
  const status = safeRouterString(value['status'] ?? value['state']);
  const iface = safeRouterString(value['interface'] ?? value['via']);
  const domain = safeDnsIdentifier(value['domain'] ?? value['suffix']);
  const protocol = forcedProtocol ?? normalizeDnsProtocol(value['protocol'] ?? value['type'] ?? value['transport'], endpointRaw);
  const port = typeof value['port'] === 'number' && Number.isInteger(value['port']) ? value['port'] : null;
  if ([address, endpoint, tlsServerName, status, iface, domain].every(item => item === null) && protocol === 'unknown') {
    return null;
  }
  return { source, scope, protocol, status, address, port, endpoint,
    tlsServerName: tlsServerName ?? fqdn, interface: iface, domain };
}

function candidateValues(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string' || typeof raw === 'number') return [raw];
  const value = record(raw);
  if (hasKnownKey(value, UPSTREAM_KEYS)) return [value];
  return Object.values(value);
}

export function projectDnsUpstreams(raw: unknown, source: DnsUpstreamSource): DnsUpstreamObservation[] {
  const root = record(raw);
  if (source === 'runtime' && Array.isArray(root['proxy-status'])) {
    return root['proxy-status'].flatMap(rawProxy => {
      const proxy = record(rawProxy);
      const scope = safeRouterString(proxy['proxy-name'], 120);
      const tls = record(proxy['proxy-tls'])['server-tls'];
      const https = record(proxy['proxy-https'])['server-https'];
      return [
        ...candidateValues(tls).map(value => observation(value, source, 'dot', scope)),
        ...candidateValues(https).map(value => observation(value, source, 'doh', scope))
      ].filter((value): value is DnsUpstreamObservation => value !== null);
    });
  }
  if (source === 'dns-proxy-config' && (root['tls'] !== undefined || root['https'] !== undefined)) {
    const tls = record(root['tls'])['upstream'];
    const https = record(root['https'])['upstream'];
    return [
      ...candidateValues(tls).map(value => observation(value, source, 'dot')),
      ...candidateValues(https).map(value => observation(value, source, 'doh'))
    ].filter((value): value is DnsUpstreamObservation => value !== null);
  }
  const proxy = record(root['proxy-status'] ?? root['dns-proxy'] ?? root);
  const candidate = proxy['server'] ?? proxy['servers'] ?? proxy['upstream'] ??
    root['name-server'] ?? root['server'] ?? (source === 'name-server-config' ? raw : undefined);
  const forced = source === 'name-server-config' ? 'plain' : undefined;
  return candidateValues(candidate).map(value => observation(value, source, forced))
    .filter((value): value is DnsUpstreamObservation => value !== null);
}

function count(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return value === undefined || value === null || value === '' ? 0 : 1;
}

function list<T>(items: T[], total = items.length): ListEvidence<T> {
  return { items, shown: items.length, total, truncated: items.length < total };
}

export function projectDnsProxy(raw: unknown): DnsProxyEvidence {
  const root = record(raw);
  const proxy = record(root['proxy-status'] ?? root['dns-proxy'] ?? root);
  const measured = Array.isArray(root['proxy-status']);
  const enabled = typeof proxy['enabled'] === 'boolean' ? proxy['enabled'] : null;
  return {
    enabled,
    status: measured ? null : safeRouterString(proxy['status'] ?? proxy['state'] ?? (enabled === false ? 'disabled' : undefined)),
    staticHostsCount: count(proxy['host'] ?? root['host']),
    errorCount: count(proxy['error'] ?? proxy['errors']),
    upstreams: list(projectDnsUpstreams(raw, 'runtime'))
  };
}

export function projectDnsInternet(raw: unknown): DnsInternetEvidence {
  const value = record(raw);
  const checked = value['checked'];
  return {
    current: (checked === true || recentTimestamp(checked)) &&
      value['enabled'] !== false && value['reliable'] === true,
    gatewayAccessible: typeof value['gateway-accessible'] === 'boolean' ? value['gateway-accessible'] : null,
    dnsAccessible: typeof value['dns-accessible'] === 'boolean' ? value['dns-accessible'] : null,
    internet: typeof value['internet'] === 'boolean' ? value['internet'] : null
  };
}

function recentTimestamp(value: unknown): boolean {
  if (typeof value !== 'string' || value.trim() === '') return false;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return false;
  // Keenetic's legacy timestamp carries router-local wall time with no zone.
  // Without separately collected router timezone evidence it cannot safely
  // prove freshness, because a stale value and a live timezone offset are
  // indistinguishable. Keep reachability unknown for this shape.
  if (!/(?:Z|[+-]\d{2}:?\d{2})$/i.test(value.trim())) {
    return false;
  }
  const age = Date.now() - parsed;
  return age >= -5 * 60_000 && age <= 15 * 60_000;
}

function ipv4Number(value: string): number | null {
  if (isIP(value) !== 4) return null;
  return value.split('.').reduce((result, part) => (result * 256 + Number(part)) >>> 0, 0);
}

function routeMatches(address: string, destination: string): number | null {
  const [network, prefixRaw] = destination.split('/');
  const ip = ipv4Number(address);
  const base = ipv4Number(network ?? '');
  const prefix = prefixRaw === undefined ? 32 : Number(prefixRaw);
  if (ip === null || base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (base & mask) ? prefix : null;
}

export function projectDnsRoutes(
  upstreams: readonly DnsUpstreamObservation[],
  rawRoutes: unknown,
  rawInterfaces: unknown
): ListEvidence<DnsRouteEvidence> {
  const rows = Array.isArray(rawRoutes) ? rawRoutes.map(record) : [];
  const interfaces = record(rawInterfaces);
  const selectedUpstreams = upstreams.slice(0, 200);
  const items = selectedUpstreams.flatMap<DnsRouteEvidence>(upstream => {
    const address = upstream.address;
    if (upstream.interface !== null) {
      const iface = record(interfaces[upstream.interface]);
      if (interfaceAvailability(iface) === 'unavailable') {
        return [{ address, endpoint: upstream.endpoint, interface: upstream.interface, destination: null,
          state: 'unavailable' }];
      }
    }
    if (address === null || isIP(address) === 0) {
      return [{ address, endpoint: upstream.endpoint, interface: upstream.interface, destination: null,
        state: 'not-exposed' }];
    }
    const matches = rows.flatMap(route => {
      if (typeof route['destination'] !== 'string') return [];
      const prefix = routeMatches(address, route['destination']);
      return prefix === null ? [] : [{ route, prefix }];
    });
    if (matches.length === 0) return [{ address, endpoint: upstream.endpoint,
      interface: upstream.interface, destination: null, state: 'not-exposed' as const }];
    const best = Math.max(...matches.map(match => match.prefix));
    const selected = matches.filter(match => match.prefix === best);
    if (selected.length !== 1) return [{ address, endpoint: upstream.endpoint,
      interface: null, destination: null, state: 'ambiguous' as const }];
    const route = selected[0]!.route;
    const iface = safeRouterString(route['interface']);
    const interfaceState = iface === null ? {} : record(interfaces[iface]);
    if (route['rejecting'] === true) return [{ address, endpoint: upstream.endpoint, interface: iface,
      destination: safeRouterString(route['destination']), state: 'unavailable' }];
    if (upstream.interface !== null && iface !== upstream.interface) {
      return [{ address, endpoint: upstream.endpoint, interface: upstream.interface,
        destination: safeRouterString(route['destination']), state: 'ambiguous' }];
    }
    return [{ address, endpoint: upstream.endpoint, interface: iface,
      destination: safeRouterString(route['destination']), state: interfaceAvailability(interfaceState) }];
  });
  return list(items, upstreams.length);
}

function interfaceAvailability(value: Record<string, unknown>): DnsRouteEvidence['state'] {
  if (Object.keys(value).length === 0) return 'not-exposed';
  if (value['connected'] === false || value['connected'] === 'no') return 'unavailable';
  const states = [value['link'], value['state']].map(state => String(state ?? '').toLowerCase());
  if (states.some(state => ['down', 'error', 'failed', 'disabled', 'offline', 'unavailable'].includes(state))) {
    return 'unavailable';
  }
  return value['connected'] === true || value['connected'] === 'yes' || value['connected'] === 'up' ||
    states.some(state => GOOD.has(state)) ? 'available' : 'not-exposed';
}

export function projectDnsLogs(entries: readonly LogEntry[]): DnsLogEvidence {
  const matching = entries.filter(entry => DNS_LOG.test([entry.ident, entry.label, entry.line].filter(Boolean).join(' ')));
  const items = matching.slice(-20).map(entry => ({
    timestamp: safeRouterString(entry.timestamp, 120),
    ident: safeRouterString(entry.ident, 120),
    level: safeRouterString(entry.level, 120),
    label: safeRouterString(entry.label, 120),
    line: safeRouterString(entry.line, 512) ?? ''
  }));
  return { ...list(items, matching.length), scanned: entries.length, matched: matching.length, untrusted: true };
}

function sanitizeUrls(value: string): string {
  return value.replace(/(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s<>'"]+/gi, token =>
    cleanDnsEndpoint(token) ?? '[REDACTED_URL]');
}

function check(id: DnsDiagnosticCheck['id'], status: CheckStatus, summary: string): DnsDiagnosticCheck {
  return { id, status, summary };
}

export function buildDnsDiagnostic(evidence: DnsDiagnosticEvidence): DnsDiagnosticReport {
  const findings: DnsDiagnosticFinding[] = [];
  const proxy = evidence.proxyRuntime.data;
  const internet = evidence.internetReachability.data;
  const runtimeRows = proxy?.upstreams.items ?? [];
  const runtimeStates = runtimeRows.map(item => item.status?.toLowerCase()).filter((v): v is string => Boolean(v));
  const allRuntimeFailed = runtimeRows.length > 0 && runtimeStates.length === runtimeRows.length &&
    runtimeStates.every(state => BAD.has(state));
  const someRuntimeFailed = runtimeStates.some(state => BAD.has(state));
  const someRuntimeGood = runtimeStates.some(state => GOOD.has(state));
  const reachabilityFailed = internet?.current === true && internet.gatewayAccessible === true && internet.dnsAccessible === false;
  const reachabilityConflict = internet?.current === true && internet.internet === true &&
    (internet.gatewayAccessible === false || internet.dnsAccessible === false);
  const proxyFailed = proxy?.enabled === false || proxy?.status !== null && BAD.has(proxy?.status?.toLowerCase() ?? '');

  if (reachabilityFailed && !reachabilityConflict) findings.push({ id: 'dns-reachability-failed', severity: 'critical',
    summary: 'The current router check reaches its gateway but explicitly reports DNS as unreachable.',
    relatedChecks: ['internet-dns-reachability'] });
  if (reachabilityConflict) findings.push({ id: 'conflicting-dns-reachability', severity: 'warning',
    summary: 'The internet status fields conflict, so no DNS outage is asserted from them.',
    relatedChecks: ['internet-dns-reachability'] });
  if (allRuntimeFailed) findings.push({ id: 'all-dns-upstreams-failed', severity: 'critical',
    summary: 'All runtime DNS upstreams with an explicit status are failed.', relatedChecks: ['proxy-runtime'] });
  else if (someRuntimeFailed && someRuntimeGood) findings.push({ id: 'dns-upstream-partial-failure', severity: 'warning',
    summary: 'At least one runtime DNS upstream is failed while another is available.', relatedChecks: ['proxy-runtime'] });
  else if (someRuntimeFailed) findings.push({ id: 'dns-upstream-failure-observed', severity: 'warning',
    summary: 'A runtime DNS upstream is failed, but other upstream states are unknown.', relatedChecks: ['proxy-runtime'] });
  if (proxyFailed && !allRuntimeFailed) findings.push({ id: 'dns-proxy-anomaly', severity: 'warning',
    summary: 'The DNS proxy explicitly reports a disabled or failed state.', relatedChecks: ['proxy-runtime'] });

  const configs = [...(evidence.dnsProxyConfig.data?.items ?? []), ...(evidence.nameServerConfig.data?.items ?? [])];
  const protocolObservations = [...(proxy?.upstreams.items ?? []), ...configs];
  const encrypted = protocolObservations.some(item => ['dot', 'doh', 'doh3'].includes(item.protocol));
  const routing = evidence.routing.data?.items ?? [];
  const routingFailed = routing.some(item => item.state === 'unavailable');
  const routingAmbiguous = routing.some(item => item.state === 'ambiguous' || item.state === 'not-exposed');
  if (routingFailed) findings.push({ id: 'dns-upstream-route-unavailable', severity: 'warning',
    summary: 'A deterministically selected DNS upstream path uses an unavailable interface.', relatedChecks: ['routing'] });

  const proxyStatus: CheckStatus = evidence.proxyRuntime.status === 'unavailable' ? 'unknown'
    : allRuntimeFailed ? 'fail' : proxyFailed || someRuntimeFailed ? 'warning'
      : runtimeRows.length > 0 || someRuntimeGood || proxy?.status && GOOD.has(proxy.status.toLowerCase()) ? 'pass' : 'unknown';
  const reachabilityStatus: CheckStatus = evidence.internetReachability.status === 'unavailable' || internet?.current !== true ||
    reachabilityConflict ? 'unknown'
    : reachabilityFailed ? 'fail' : internet.dnsAccessible === true ? 'pass' : 'unknown';
  const configUnavailable = [evidence.dnsProxyConfig, evidence.nameServerConfig]
    .filter(item => item.status === 'unavailable').length;
  const configStatus: CheckStatus = configUnavailable === 2 ? 'unknown' : configUnavailable === 1 ? 'warning' : 'pass';
  const routingStatus: CheckStatus = evidence.routing.status === 'unavailable' ? 'unknown'
    : routingFailed ? 'warning' : routingAmbiguous ? 'unknown' : routing.length > 0 ? 'pass' : 'unknown';
  const checks = [
    check('proxy-runtime', proxyStatus, proxyStatus === 'pass' ? 'DNS proxy exposes runtime upstreams with no explicit failure state.' :
      proxyStatus === 'fail' ? 'All explicitly reported runtime upstreams are failed.' :
        proxyStatus === 'warning' ? 'The DNS proxy reports an anomaly.' : 'DNS proxy runtime health is unknown.'),
    check('internet-dns-reachability', reachabilityStatus, reachabilityStatus === 'pass' ? 'The current router check reaches DNS.' :
      reachabilityStatus === 'fail' ? 'The gateway is reachable but DNS is not.' : 'Current DNS reachability is unknown.'),
    check('upstream-configuration', configStatus, configStatus === 'warning' ?
      'Only part of the DNS upstream configuration was available.' : configs.length > 0 ? 'DNS upstream configuration was projected.' :
      configStatus === 'unknown' ? 'DNS upstream configuration is unavailable.' :
        'No explicit upstream was exposed; runtime upstreams may be learned automatically.'),
    check('encryption', protocolObservations.length === 0 ? 'unknown' : 'pass', encrypted ?
      'At least one encrypted DNS upstream is configured or observed; this does not prove TLS reachability.' :
      protocolObservations.length > 0 ? 'No encrypted DNS upstream was identified in the available evidence.' :
        'DNS encryption configuration is unknown.'),
    check('routing', routingStatus, routingStatus === 'pass' ? 'DNS upstream routes resolve to available interfaces.' :
      routingStatus === 'warning' ? 'A DNS upstream path is unavailable.' : 'DNS upstream routing is unknown or not exposed.'),
    check('recent-logs', evidence.logs.status === 'available' ? 'pass' : 'unknown', evidence.logs.status === 'available' ?
      'Bounded DNS-related logs were collected as untrusted context.' : 'DNS-related logs are unavailable.')
  ];
  const core = checks.filter(item => ['proxy-runtime', 'internet-dns-reachability',
    'upstream-configuration'].includes(item.id) || item.id === 'routing' && item.status !== 'unknown');
  const status: DiagnosticStatus = core.some(item => item.status === 'fail') ? 'unhealthy'
    : core.some(item => item.status === 'warning' || item.status === 'unknown') ? 'degraded' : 'healthy';
  const truncated = evidence.proxyRuntime.data?.upstreams.truncated === true ||
    evidence.dnsProxyConfig.data?.truncated === true || evidence.nameServerConfig.data?.truncated === true ||
    evidence.routing.data?.truncated === true || evidence.logs.data?.truncated === true;
  return { schemaVersion: 1, status, complete: Object.values(evidence).every(item => item.status === 'available'),
    checks, findings, evidence, untrustedRouterData: true, truncated };
}

function bytes(report: DnsDiagnosticReport): number {
  return Buffer.byteLength(JSON.stringify(redact(report), null, 2), 'utf8');
}

function halve<T>(listValue: ListEvidence<T>): boolean {
  if (listValue.items.length === 0) return false;
  listValue.items = listValue.items.slice(0, Math.floor(listValue.items.length / 2));
  listValue.shown = listValue.items.length;
  listValue.truncated = listValue.shown < listValue.total;
  return true;
}

export function budgetDnsDiagnostic(report: DnsDiagnosticReport, maxBytes: number): DnsDiagnosticReport {
  const shrink = <T>(value: ListEvidence<T> | null | undefined): void => {
    if (!value) return;
    while (bytes(report) > maxBytes && halve(value)) report.truncated = true;
  };
  shrink(report.evidence.logs.data);
  shrink(report.evidence.routing.data);
  shrink(report.evidence.dnsProxyConfig.data);
  shrink(report.evidence.nameServerConfig.data);
  shrink(report.evidence.proxyRuntime.data?.upstreams);
  report.truncated = report.truncated || report.evidence.proxyRuntime.data?.upstreams.truncated === true ||
    report.evidence.dnsProxyConfig.data?.truncated === true || report.evidence.nameServerConfig.data?.truncated === true ||
    report.evidence.routing.data?.truncated === true || report.evidence.logs.data?.truncated === true;
  if (bytes(report) > maxBytes) report.truncated = true;
  return report;
}
