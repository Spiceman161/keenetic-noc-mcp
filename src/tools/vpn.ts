import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { AuthError, RciError, TransportError, ValidationError } from '../router/errors.js';
import { readStructuredRunningConfig } from '../router/config-reader.js';
import { isVpnInterfaceType } from '../shape/project.js';
import { compactOk, guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};
const scalar = (value: unknown, fallback: string | null): string | number | boolean | null =>
  typeof value === 'string' || typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value)) ? value : fallback;

const INTERFACE_INPUT_LIMIT = 256_000;
const INTERFACE_DETAIL_LIMIT = 100;
const PEER_DETAIL_LIMIT = 100;
const JOIN_KEY_LIMIT = 256;
const ALLOWED_IP_LIMIT = 32;
const ALLOWED_IP_STRING_LIMIT = 128;

type EvidenceStatus = 'complete' | 'partial' | 'unavailable';
type EvidenceReason = 'partial-data' | 'unexpected-response' | 'response-too-large' | 'rci-error' | null;
type HandshakeEvidence = 'present' | 'absent' | 'unknown' | 'invalid';
type HandshakeAgeEvidence = 'observed' | 'absent' | 'unknown';

interface WireguardPeer {
  peerIndex: number;
  description: string | null;
  endpoint: { host: string; port: number } | null;
  enabled: boolean | null;
  online: boolean | null;
  handshake: HandshakeEvidence;
  handshakeAgeEvidence: HandshakeAgeEvidence;
  handshakeAgeSeconds: number | null;
  rxBytes: number | null;
  txBytes: number | null;
  allowedIps: Array<{ address: string; mask: string }> | null;
  persistentKeepaliveSeconds: number | null;
  /** Ephemeral exact-match material. It is removed before public serialization. */
  runtimePublicKey?: string | null;
}

interface PeerCounts {
  peersObserved: number;
  peersWithHandshakeEvidence: number;
  peersWithoutHandshakeEvidence: number;
  peersWithUnknownHandshakeEvidence: number;
  peersWithInvalidHandshakeEvidence: number;
  peersWithObservedHandshakeAge: number;
  peersWithoutReportedHandshakeAge: number;
  peersWithUnknownHandshakeAge: number;
  peersOnline: number;
  peersOffline: number;
}

interface WireguardInterface {
  id: string;
  name: string | null;
  description: string | null;
  address: string | null;
  state: 'up' | 'down' | 'unknown';
  link: 'up' | 'down' | 'unknown';
  defaultGateway: boolean | null;
  peerEvidenceStatus: EvidenceStatus;
  peersObserved: number | null;
  peersWithHandshakeEvidence: number | null;
  peersWithoutHandshakeEvidence: number | null;
  peersWithUnknownHandshakeEvidence: number | null;
  peersWithInvalidHandshakeEvidence: number | null;
  peersWithObservedHandshakeAge: number | null;
  peersWithoutReportedHandshakeAge: number | null;
  peersWithUnknownHandshakeAge: number | null;
  peersOnline: number | null;
  peersOffline: number | null;
  peers: WireguardPeer[];
  peersShown: number;
  peersTotal: number | null;
  peersTruncated: boolean;
}

interface WireguardStatus {
  schemaVersion: 1;
  evidenceStatus: EvidenceStatus;
  evidenceReason: EvidenceReason;
  peersObserved: number | null;
  peersWithHandshakeEvidence: number | null;
  peersWithoutHandshakeEvidence: number | null;
  peersWithUnknownHandshakeEvidence: number | null;
  peersWithInvalidHandshakeEvidence: number | null;
  peersWithObservedHandshakeAge: number | null;
  peersWithoutReportedHandshakeAge: number | null;
  peersWithUnknownHandshakeAge: number | null;
  peersOnline: number | null;
  peersOffline: number | null;
  interfaces: WireguardInterface[];
  shown: number;
  total: number | null;
  truncated: boolean;
}

function strictRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function emptyPeerCounts(): PeerCounts {
  return {
    peersObserved: 0,
    peersWithHandshakeEvidence: 0,
    peersWithoutHandshakeEvidence: 0,
    peersWithUnknownHandshakeEvidence: 0,
    peersWithInvalidHandshakeEvidence: 0,
    peersWithObservedHandshakeAge: 0,
    peersWithoutReportedHandshakeAge: 0,
    peersWithUnknownHandshakeAge: 0,
    peersOnline: 0,
    peersOffline: 0
  };
}

function addPeerCounts(total: PeerCounts, value: PeerCounts): void {
  total.peersObserved += value.peersObserved;
  total.peersWithHandshakeEvidence += value.peersWithHandshakeEvidence;
  total.peersWithoutHandshakeEvidence += value.peersWithoutHandshakeEvidence;
  total.peersWithUnknownHandshakeEvidence += value.peersWithUnknownHandshakeEvidence;
  total.peersWithInvalidHandshakeEvidence += value.peersWithInvalidHandshakeEvidence;
  total.peersWithObservedHandshakeAge += value.peersWithObservedHandshakeAge;
  total.peersWithoutReportedHandshakeAge += value.peersWithoutReportedHandshakeAge;
  total.peersWithUnknownHandshakeAge += value.peersWithUnknownHandshakeAge;
  total.peersOnline += value.peersOnline;
  total.peersOffline += value.peersOffline;
}

function state(value: unknown): 'up' | 'down' | 'unknown' {
  return value === 'up' || value === 'down' ? value : 'unknown';
}

function safeCounter(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

function safeString(value: unknown, maxLength: number): string | null {
  return typeof value === 'string' && value.length <= maxLength ? value : null;
}

function nullableBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function handshake(value: unknown): HandshakeEvidence {
  if (value === undefined || value === null) return 'absent';
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 'invalid';
  return value === 0 ? 'unknown' : 'present';
}

function handshakeAge(value: unknown): { evidence: HandshakeAgeEvidence; seconds: number | null } {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 2_147_483_647) {
    return { evidence: 'unknown', seconds: null };
  }
  if (value === 2_147_483_647) return { evidence: 'absent', seconds: null };
  return { evidence: 'observed', seconds: value };
}

function projectPeer(value: Record<string, unknown>, peerIndex: number): WireguardPeer {
  const lastHandshake = value['last-handshake'];
  const age = handshakeAge(lastHandshake);
  const host = safeString(value['remote-endpoint-address'], 256);
  const port = value['remote-port'];
  return {
    peerIndex,
    description: safeString(value['description'], 256),
    endpoint: host !== null && typeof port === 'number' && Number.isSafeInteger(port) && port >= 1 && port <= 65_535
      ? { host, port }
      : null,
    enabled: nullableBoolean(value['enabled']),
    online: nullableBoolean(value['online']),
    handshake: handshake(lastHandshake),
    handshakeAgeEvidence: age.evidence,
    handshakeAgeSeconds: age.seconds,
    rxBytes: safeCounter(value['rxbytes']),
    txBytes: safeCounter(value['txbytes']),
    allowedIps: null,
    persistentKeepaliveSeconds: null,
    runtimePublicKey: safeString(value['public-key'], JOIN_KEY_LIMIT)
  };
}

function peerCounts(peers: readonly WireguardPeer[]): PeerCounts {
  const counts = emptyPeerCounts();
  for (const peer of peers) {
    counts.peersObserved += 1;
    switch (peer.handshake) {
      case 'present': counts.peersWithHandshakeEvidence += 1; break;
      case 'absent': counts.peersWithoutHandshakeEvidence += 1; break;
      case 'unknown': counts.peersWithUnknownHandshakeEvidence += 1; break;
      case 'invalid': counts.peersWithInvalidHandshakeEvidence += 1; break;
    }
    switch (peer.handshakeAgeEvidence) {
      case 'observed': counts.peersWithObservedHandshakeAge += 1; break;
      case 'absent': counts.peersWithoutReportedHandshakeAge += 1; break;
      case 'unknown': counts.peersWithUnknownHandshakeAge += 1; break;
    }
    if (peer.online === true) counts.peersOnline += 1;
    if (peer.online === false) counts.peersOffline += 1;
  }
  return counts;
}

interface PeerCollection {
  usable: boolean;
  partial: boolean;
  peers: WireguardPeer[];
}

function parsePeerCollection(value: unknown): PeerCollection | null {
  const entries = Array.isArray(value)
    ? value
    : strictRecord(value)
      ? Object.values(value)
      : null;
  if (entries === null) return null;
  const peers: WireguardPeer[] = [];
  let malformed = false;
  for (const entry of entries) {
    if (!strictRecord(entry)) {
      malformed = true;
      continue;
    }
    peers.push(projectPeer(entry, peers.length + 1));
  }
  return { usable: entries.length === 0 || peers.length > 0, partial: malformed, peers };
}

interface SelectedPeers {
  status: EvidenceStatus;
  peers: WireguardPeer[];
}

/** The nested observed collection is primary; these are the existing compatibility aliases. */
function selectPeers(iface: Record<string, unknown>): SelectedPeers {
  const hasWireguard = Object.prototype.hasOwnProperty.call(iface, 'wireguard');
  const wireguard = iface['wireguard'];
  const nested = strictRecord(wireguard) ? wireguard : undefined;
  // A missing measured container can use the established direct aliases. A
  // present non-record container is malformed, but its contents stay opaque.
  const candidates = [nested?.['peer'], nested?.['peers'], iface['peer'], iface['peers']];
  let malformedCandidate = hasWireguard && !strictRecord(wireguard);
  for (const candidate of candidates) {
    if (candidate === undefined) continue;
    const parsed = parsePeerCollection(candidate);
    if (parsed === null || !parsed.usable) {
      malformedCandidate = true;
      continue;
    }
    return {
      status: malformedCandidate || parsed.partial ? 'partial' : 'complete',
      peers: parsed.peers
    };
  }
  return { status: 'unavailable', peers: [] };
}

function projectWireguardInterface(id: string, iface: Record<string, unknown>): WireguardInterface {
  const selected = selectPeers(iface);
  if (selected.status === 'unavailable') {
    return {
      id,
      name: safeString(iface['interface-name'], 128),
      description: safeString(iface['description'], 256),
      address: safeString(iface['address'], 256),
      state: state(iface['state']),
      link: state(iface['link']),
      defaultGateway: typeof iface['defaultgw'] === 'boolean' ? iface['defaultgw'] : null,
      peerEvidenceStatus: 'unavailable',
      peersObserved: null,
      peersWithHandshakeEvidence: null,
      peersWithoutHandshakeEvidence: null,
      peersWithUnknownHandshakeEvidence: null,
      peersWithInvalidHandshakeEvidence: null,
      peersWithObservedHandshakeAge: null,
      peersWithoutReportedHandshakeAge: null,
      peersWithUnknownHandshakeAge: null,
      peersOnline: null,
      peersOffline: null,
      peers: [],
      peersShown: 0,
      peersTotal: null,
      peersTruncated: false
    };
  }
  const counts = peerCounts(selected.peers);
  const peers = selected.peers.slice(0, PEER_DETAIL_LIMIT);
  return {
    id,
    name: safeString(iface['interface-name'], 128),
    description: safeString(iface['description'], 256),
    address: safeString(iface['address'], 256),
    state: state(iface['state']),
    link: state(iface['link']),
    defaultGateway: typeof iface['defaultgw'] === 'boolean' ? iface['defaultgw'] : null,
    peerEvidenceStatus: selected.status,
    ...counts,
    peers,
    peersShown: peers.length,
    peersTotal: selected.peers.length,
    peersTruncated: peers.length < selected.peers.length
  };
}

function unavailable(reason: Exclude<EvidenceReason, null | 'partial-data'>): WireguardStatus {
  return {
    schemaVersion: 1,
    evidenceStatus: 'unavailable',
    evidenceReason: reason,
    peersObserved: null,
    peersWithHandshakeEvidence: null,
    peersWithoutHandshakeEvidence: null,
    peersWithUnknownHandshakeEvidence: null,
    peersWithInvalidHandshakeEvidence: null,
    peersWithObservedHandshakeAge: null,
    peersWithoutReportedHandshakeAge: null,
    peersWithUnknownHandshakeAge: null,
    peersOnline: null,
    peersOffline: null,
    interfaces: [],
    shown: 0,
    total: null,
    truncated: false
  };
}

function sourceStatus(raw: unknown): WireguardStatus {
  if (!strictRecord(raw) || Object.keys(raw).length === 0) return unavailable('unexpected-response');
  let validInterfaceRows = 0;
  let structuralDefect = false;
  const interfaces: WireguardInterface[] = [];
  for (const [id, value] of Object.entries(raw)) {
    if (!strictRecord(value)) {
      structuralDefect = true;
      continue;
    }
    if (typeof value['type'] !== 'string') {
      structuralDefect = true;
      continue;
    }
    validInterfaceRows += 1;
    if (isVpnInterfaceType(value['type']) && value['type'] === 'Wireguard') {
      const iface = projectWireguardInterface(id, value);
      interfaces.push(iface);
      if (iface.peerEvidenceStatus !== 'complete') structuralDefect = true;
    }
  }
  if (validInterfaceRows === 0) return unavailable('unexpected-response');

  const counts = emptyPeerCounts();
  let hasUsablePeers = false;
  for (const iface of interfaces) {
    if (iface.peerEvidenceStatus === 'unavailable') continue;
    hasUsablePeers = true;
    addPeerCounts(counts, {
      peersObserved: iface.peersObserved!,
      peersWithHandshakeEvidence: iface.peersWithHandshakeEvidence!,
      peersWithoutHandshakeEvidence: iface.peersWithoutHandshakeEvidence!,
      peersWithUnknownHandshakeEvidence: iface.peersWithUnknownHandshakeEvidence!,
      peersWithInvalidHandshakeEvidence: iface.peersWithInvalidHandshakeEvidence!,
      peersWithObservedHandshakeAge: iface.peersWithObservedHandshakeAge!,
      peersWithoutReportedHandshakeAge: iface.peersWithoutReportedHandshakeAge!,
      peersWithUnknownHandshakeAge: iface.peersWithUnknownHandshakeAge!,
      peersOnline: iface.peersOnline!,
      peersOffline: iface.peersOffline!
    });
  }
  const noWireguard = interfaces.length === 0;
  return {
    schemaVersion: 1,
    evidenceStatus: structuralDefect ? 'partial' : 'complete',
    evidenceReason: structuralDefect ? 'partial-data' : null,
    peersObserved: hasUsablePeers || noWireguard ? counts.peersObserved : null,
    peersWithHandshakeEvidence: hasUsablePeers || noWireguard ? counts.peersWithHandshakeEvidence : null,
    peersWithoutHandshakeEvidence: hasUsablePeers || noWireguard ? counts.peersWithoutHandshakeEvidence : null,
    peersWithUnknownHandshakeEvidence: hasUsablePeers || noWireguard ? counts.peersWithUnknownHandshakeEvidence : null,
    peersWithInvalidHandshakeEvidence: hasUsablePeers || noWireguard ? counts.peersWithInvalidHandshakeEvidence : null,
    peersWithObservedHandshakeAge: hasUsablePeers || noWireguard ? counts.peersWithObservedHandshakeAge : null,
    peersWithoutReportedHandshakeAge: hasUsablePeers || noWireguard ? counts.peersWithoutReportedHandshakeAge : null,
    peersWithUnknownHandshakeAge: hasUsablePeers || noWireguard ? counts.peersWithUnknownHandshakeAge : null,
    peersOnline: hasUsablePeers || noWireguard ? counts.peersOnline : null,
    peersOffline: hasUsablePeers || noWireguard ? counts.peersOffline : null,
    interfaces: interfaces.slice(0, INTERFACE_DETAIL_LIMIT),
    shown: Math.min(interfaces.length, INTERFACE_DETAIL_LIMIT),
    total: interfaces.length,
    truncated: interfaces.length > INTERFACE_DETAIL_LIMIT
  };
}

function reduceReason(current: EvidenceReason, next: EvidenceReason): EvidenceReason {
  const priority: Record<Exclude<EvidenceReason, null>, number> = {
    'partial-data': 1,
    'unexpected-response': 2,
    'rci-error': 3,
    'response-too-large': 4
  };
  if (next === null) return current;
  if (current === null || priority[next] > priority[current]) return next;
  return current;
}

function configInterfaces(value: unknown): Record<string, unknown> | null {
  if (!strictRecord(value)) return null;
  const keys = Object.keys(value);
  if (keys.length === 0) return null;
  if (Object.prototype.hasOwnProperty.call(value, 'interface')) {
    return keys.length === 1 && strictRecord(value['interface']) ? value['interface'] : null;
  }
  return value;
}

function allowedIps(value: Record<string, unknown>): { value: Array<{ address: string; mask: string }> | null; partial: boolean } {
  if (!Object.prototype.hasOwnProperty.call(value, 'allow-ips')) return { value: [], partial: false };
  const pairs = value['allow-ips'];
  if (!Array.isArray(pairs) || pairs.length > ALLOWED_IP_LIMIT) return { value: null, partial: true };
  const projected: Array<{ address: string; mask: string }> = [];
  for (const pair of pairs) {
    if (!strictRecord(pair)) return { value: null, partial: true };
    const address = safeString(pair['address'], ALLOWED_IP_STRING_LIMIT);
    const mask = safeString(pair['mask'], ALLOWED_IP_STRING_LIMIT);
    if (address === null || mask === null) return { value: null, partial: true };
    projected.push({ address, mask });
  }
  return { value: projected, partial: false };
}

function persistentKeepalive(value: Record<string, unknown>): { value: number | null; partial: boolean } {
  if (!Object.prototype.hasOwnProperty.call(value, 'keepalive-interval')) return { value: null, partial: false };
  const keepalive = value['keepalive-interval'];
  const interval = strictRecord(keepalive) ? keepalive['interval'] : undefined;
  return typeof interval === 'number' && Number.isSafeInteger(interval) && interval >= 0
    ? { value: interval, partial: false }
    : { value: null, partial: true };
}

function configFailureReason(error: unknown): EvidenceReason {
  if (error instanceof AuthError || error instanceof TransportError) return 'partial-data';
  if (error instanceof RciError) {
    if (error.code === 'response-too-large') return 'response-too-large';
    if (error.code === 'unexpected-response') return 'unexpected-response';
  }
  return 'rci-error';
}

async function enrichWireguardStatus(status: WireguardStatus, ctx: ToolContext): Promise<WireguardStatus> {
  if (status.evidenceStatus === 'unavailable' || !status.interfaces.some(iface => iface.peers.length > 0)) return status;
  let reason = status.evidenceReason;
  try {
    const read = await readStructuredRunningConfig(ctx.client, 'interfaces');
    const data = strictRecord(read.data) ? read.data : null;
    const interfaces = configInterfaces(data?.['interface']);
    if (interfaces === null) throw new RciError('the WireGuard configuration branch has an unexpected shape', {
      path: 'interface', code: 'unexpected-response', ident: 'rci'
    });
    for (const runtimeInterface of status.interfaces) {
      if (runtimeInterface.peers.length === 0) continue;
      const configInterface = interfaces[runtimeInterface.id];
      const wireguard = strictRecord(configInterface) ? configInterface['wireguard'] : undefined;
      const configPeers = strictRecord(wireguard) ? wireguard['peer'] : undefined;
      if (!Array.isArray(configPeers)) {
        reason = reduceReason(reason, 'partial-data');
        continue;
      }
      const index = new Map<string, Record<string, unknown> | null>();
      let malformedConfigPeer = false;
      for (const candidate of configPeers) {
        if (!strictRecord(candidate)) {
          malformedConfigPeer = true;
          continue;
        }
        const key = safeString(candidate['key'], JOIN_KEY_LIMIT);
        if (key === null) {
          malformedConfigPeer = true;
          continue;
        }
        index.set(key, index.has(key) ? null : candidate);
      }
      if (malformedConfigPeer) reason = reduceReason(reason, 'partial-data');
      for (const peer of runtimeInterface.peers) {
        const configPeer = peer.runtimePublicKey === null || peer.runtimePublicKey === undefined
          ? undefined
          : index.get(peer.runtimePublicKey);
        if (configPeer === undefined || configPeer === null) {
          reason = reduceReason(reason, 'partial-data');
          continue;
        }
        const ranges = allowedIps(configPeer);
        const keepalive = persistentKeepalive(configPeer);
        peer.allowedIps = ranges.value;
        peer.persistentKeepaliveSeconds = keepalive.value;
        if (ranges.partial || keepalive.partial) reason = reduceReason(reason, 'partial-data');
      }
    }
  } catch (error) {
    reason = reduceReason(reason, configFailureReason(error));
  }
  return { ...status, evidenceStatus: reason === null ? 'complete' : 'partial', evidenceReason: reason };
}

function publicWireguardStatus(status: WireguardStatus): WireguardStatus {
  return {
    ...status,
    interfaces: status.interfaces.map(iface => ({
      ...iface,
      peers: iface.peers.map(({ runtimePublicKey: _runtimePublicKey, ...peer }) => peer)
    }))
  };
}

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

/** Drop peer detail before interfaces, while preserving the fixed status and aggregate envelope. */
function budgetWireguardStatus(status: WireguardStatus, maxBytes: number): WireguardStatus {
  const interfaces = status.interfaces.map(iface => ({ ...iface, peers: [...iface.peers] }));
  let result: WireguardStatus = { ...status, interfaces, shown: interfaces.length };
  while (byteLength(result) > maxBytes) {
    const peerInterface = result.interfaces.findLast(iface => iface.peers.length > 0);
    if (peerInterface) {
      peerInterface.peers = peerInterface.peers.slice(0, Math.floor(peerInterface.peers.length / 2));
      peerInterface.peersShown = peerInterface.peers.length;
      peerInterface.peersTruncated = true;
      result = { ...result, truncated: true };
      continue;
    }
    if (result.interfaces.length > 0) {
      result = {
        ...result,
        interfaces: result.interfaces.slice(0, -1),
        shown: result.interfaces.length - 1,
        truncated: true
      };
      continue;
    }
    return result;
  }
  return result;
}

export function projectVpn(name: string, value: unknown): Record<string, unknown> {
  const item = record(value);
  return {
    name,
    type: scalar(item['type'], 'unknown'),
    description: scalar(item['description'], ''),
    state: scalar(item['state'], ''),
    link: scalar(item['link'], ''),
    address: scalar(item['address'], null),
    uptime: scalar(item['uptime'], null)
  };
}

async function all(ctx: ToolContext): Promise<Array<Record<string, unknown>>> {
  const raw = record(await ctx.client.rci.get('show/interface'));
  return Object.entries(raw)
    .filter(([, value]) => isVpnInterfaceType(record(value)['type']))
    .map(([name, value]) => projectVpn(name, value));
}

export function registerVpnTools(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool('list_vpn', { title: 'List VPN interfaces', description: 'Compact interface observations for exactly classified VPN interfaces.', inputSchema: {}, annotations: READ_ONLY }, guard(ctx, async () => ok({ vpn: await all(ctx) }, ctx.maxResponseBytes)));
  server.registerTool('get_vpn', { title: 'Get one VPN interface', description: 'Interface observations for one exactly classified VPN interface.', inputSchema: { name: z.string() }, annotations: READ_ONLY }, guard(ctx, async ({ name }) => {
    const found = (await all(ctx)).find(item => item['name'] === name);
    if (!found) throw new ValidationError(`VPN interface "${name}" was not found. Call list_vpn.`);
    return ok(found, ctx.maxResponseBytes);
  }));
  server.registerTool('get_wireguard_status', {
    title: 'Get WireGuard runtime status evidence',
    description: 'Bounded current WireGuard interface, peer, authoritative handshake-age seconds, declared endpoint, configured structured Allowed IP pairs, persistent keepalive seconds, nullable enabled/online observations, handshake-presence, and counter evidence only; not a health or Internet/reachability verdict.',
    inputSchema: {},
    annotations: READ_ONLY
  }, guard(ctx, async () => {
    try {
      const runtime = sourceStatus(await ctx.client.rci.get('show/interface', INTERFACE_INPUT_LIMIT));
      return compactOk(budgetWireguardStatus(publicWireguardStatus(await enrichWireguardStatus(runtime, ctx)),
        ctx.maxResponseBytes), ctx.maxResponseBytes);
    } catch (error) {
      if (!(error instanceof RciError)) throw error;
      return compactOk(unavailable(error.code === 'response-too-large' ? 'response-too-large' : 'rci-error'),
        ctx.maxResponseBytes);
    }
  }));
}
