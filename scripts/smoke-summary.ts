import type { LogEntry } from '../src/tools/logs.js';
import type { ConfigCapabilities, ConfigCapabilityProbe } from '../src/router/config-capabilities.js';

const SAFE_DNS_FIELDS = new Set([
  'proxy-status', 'dns-proxy', 'server', 'servers', 'upstream', 'name-server',
  'address', 'host', 'url', 'uri', 'endpoint', 'protocol', 'type', 'transport',
  'status', 'state', 'enabled', 'tls-name', 'sni', 'server-name', 'interface',
  'via', 'domain', 'suffix', 'error', 'errors', 'count', 'host',
  'proxy-name', 'proxy-config', 'proxy-stat', 'proxy-tls', 'server-tls',
  'proxy-https', 'server-https', 'tls', 'https', 'route', 'port', 'fqdn',
  'format', 'auto', 'enable', 'disable', 'reject'
]);
const SAFE_DNS_ENUMS = new Set([
  'dns', 'plain', 'udp', 'tcp', 'tls', 'dot', 'https', 'doh', 'doh3', 'http2', 'http3', 'quic',
  'up', 'down', 'ok', 'ready', 'running', 'available', 'online', 'connected', 'error', 'failed',
  'disabled', 'offline', 'unavailable', 'unknown'
]);
const SAFE_DEVICE_FIELDS = new Set([
  'lease', 'mac', 'ip', 'hostname', 'name', 'via', 'expires'
]);

function shape(value: unknown): string {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  return typeof value === 'object' ? 'object' : typeof value;
}

/** Summarizes DNS payload structure without retaining values or dynamic keys. */
function createShapeSummary(value: unknown, safeFields: ReadonlySet<string>): Record<string, unknown> {
  const fields = new Map<string, { path: string; shapes: Set<string>; items: Set<number>; values: Set<string> }>();
  let truncated = false;
  const add = (path: string, child: unknown, key?: string): void => {
    let field = fields.get(path);
    if (!field) {
      field = { path, shapes: new Set(), items: new Set(), values: new Set() };
      fields.set(path, field);
    }
    field.shapes.add(shape(child));
    if (Array.isArray(child)) field.items.add(child.length);
    else if (child && typeof child === 'object') field.items.add(Object.keys(child).length);
    if (typeof child === 'string' && ['protocol', 'type', 'transport', 'status', 'state'].includes(key ?? '')) {
      const normalized = child.toLocaleLowerCase();
      if (SAFE_DNS_ENUMS.has(normalized)) field.values.add(normalized);
    }
  };
  const visit = (node: unknown, path: string, depth: number): void => {
    if (depth > 8 || fields.size >= 100) {
      truncated = true;
      return;
    }
    if (Array.isArray(node)) {
      add(`${path}[]`, node);
      if (node.length > 3) truncated = true;
      for (const child of node.slice(0, 3)) visit(child, `${path}[]`, depth + 1);
      return;
    }
    if (!node || typeof node !== 'object') return;
    const entries = Object.entries(node as Record<string, unknown>);
    if (entries.length > 100) truncated = true;
    for (const [rawKey, child] of entries.slice(0, 100)) {
      const key = safeFields.has(rawKey) ? rawKey : /^\d+$/.test(rawKey) ? '<index>' : '<dynamic>';
      const childPath = path ? `${path}.${key}` : key;
      add(childPath, child, rawKey);
      visit(child, childPath, depth + 1);
    }
  };
  visit(value, '', 0);
  const projected = [...fields.values()].map(field => ({
    path: field.path,
    shape: field.shapes.size === 1 ? [...field.shapes][0] : 'mixed',
    items: field.items.size === 0 ? null : field.items.size === 1 ? [...field.items][0] : [...field.items].sort((a, b) => a - b),
    ...(field.values.size > 0 ? { values: [...field.values].sort() } : {})
  }));
  return { status: 'passed', shape: shape(value), fields: projected.sort((a, b) => a.path.localeCompare(b.path)),
    truncated };
}

/** Summarizes DNS structure without returning endpoints, domains or dynamic keys. */
export function createDnsShapeSummary(value: unknown): Record<string, unknown> {
  return createShapeSummary(value, SAFE_DNS_FIELDS);
}

/** Summarizes the live-proven DHCP binding wrapper without returning device data. */
export function createDeviceShapeSummary(value: unknown): Record<string, unknown> {
  return createShapeSummary(value, SAFE_DEVICE_FIELDS);
}

/** Classifies a probe failure without copying router-controlled error text. */
export function createUnavailableSmokeSummary(error: unknown): Record<string, unknown> {
  const rawCode = typeof error === 'object' && error !== null && 'code' in error &&
    typeof error.code === 'string' ? error.code : null;
  const code = rawCode !== null && (/^\d{3}$/.test(rawCode) || rawCode === 'response-too-large')
    ? rawCode
    : null;
  return { status: 'unavailable', errorClass: error instanceof Error ? error.name : 'UnknownError', code };
}

interface FilterOutcome {
  available: boolean;
  matched: number | null;
}

function outcome(value: FilterOutcome, reason: string): Record<string, unknown> {
  return value.available
    ? { status: 'passed', matched: value.matched ?? 0 }
    : { status: 'skipped', reason };
}

/** Converts live log results into a summary that cannot contain router values. */
export function createLogSmokeSummary(
  entries: readonly LogEntry[],
  filters: { interface: FilterOutcome; timeRange: FilterOutcome; deviceAlias: FilterOutcome }
): Record<string, unknown> {
  const timestampKinds = { iso: 0, epoch: 0, other: 0, missing: 0 };
  for (const entry of entries) {
    if (entry.timestamp === null) timestampKinds.missing += 1;
    else if (/^\d{4}-\d{2}-\d{2}(?:T| )/.test(entry.timestamp)) timestampKinds.iso += 1;
    else if (/^\d{10}(?:\d{3})?$/.test(entry.timestamp)) timestampKinds.epoch += 1;
    else timestampKinds.other += 1;
  }
  return {
    dispatcher: 'passed', total: entries.length,
    fields: ['timestamp', 'ident', 'level', 'label', 'line'],
    timestampShape: entries.length === 0 ? { status: 'skipped', reason: 'no-log-rows', counts: timestampKinds } : {
      status: 'passed', counts: timestampKinds
    },
    interfaceFilter: outcome(filters.interface, 'no-candidate'),
    timeRange: outcome(filters.timeRange, 'no-candidate'),
    deviceAlias: outcome(filters.deviceAlias, 'no-candidate')
  };
}

function safeConfigProbe(probe: ConfigCapabilityProbe): ConfigCapabilityProbe {
  return {
    available: probe.available,
    transport: probe.transport,
    httpStatus: probe.httpStatus,
    contentTypeClass: probe.contentTypeClass,
    shape: probe.shape,
    items: probe.items,
    bytes: probe.bytes,
    payloadShape: probe.payloadShape,
    payloadItems: probe.payloadItems,
    payloadItemShape: probe.payloadItemShape,
    wrapperDepth: probe.wrapperDepth,
    reason: probe.reason
  };
}

/** Whitelists anonymous config probe fields at the live-output boundary. */
export function createConfigSmokeSummary(capabilities: ConfigCapabilities): ConfigCapabilities {
  return {
    runningConfig: safeConfigProbe(capabilities.runningConfig),
    startupConfig: safeConfigProbe(capabilities.startupConfig)
  };
}
