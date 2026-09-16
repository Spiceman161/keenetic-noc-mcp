import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { RciError, ValidationError } from '../router/errors.js';
import { isVpnInterfaceType } from '../shape/project.js';
import { compactOk, guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};
const scalar = (value: unknown, fallback: string | null): string | number | boolean | null =>
  typeof value === 'string' || typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value)) ? value : fallback;

const INTERFACE_INPUT_LIMIT = 256_000;
const INTERFACE_DETAIL_LIMIT = 100;
const PEER_DETAIL_LIMIT = 100;

type EvidenceStatus = 'complete' | 'partial' | 'unavailable';
type EvidenceReason = 'partial-data' | 'unexpected-response' | 'response-too-large' | 'rci-error' | null;
type HandshakeEvidence = 'present' | 'absent' | 'unknown' | 'invalid';

interface WireguardPeer {
  peerIndex: number;
  handshake: HandshakeEvidence;
  rxBytes: number | null;
  txBytes: number | null;
}

interface PeerCounts {
  peersObserved: number;
  peersWithHandshakeEvidence: number;
  peersWithoutHandshakeEvidence: number;
  peersWithUnknownHandshakeEvidence: number;
  peersWithInvalidHandshakeEvidence: number;
}

interface WireguardInterface {
  id: string;
  state: 'up' | 'down' | 'unknown';
  link: 'up' | 'down' | 'unknown';
  defaultGateway: boolean | null;
  peerEvidenceStatus: EvidenceStatus;
  peersObserved: number | null;
  peersWithHandshakeEvidence: number | null;
  peersWithoutHandshakeEvidence: number | null;
  peersWithUnknownHandshakeEvidence: number | null;
  peersWithInvalidHandshakeEvidence: number | null;
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
    peersWithInvalidHandshakeEvidence: 0
  };
}

function addPeerCounts(total: PeerCounts, value: PeerCounts): void {
  total.peersObserved += value.peersObserved;
  total.peersWithHandshakeEvidence += value.peersWithHandshakeEvidence;
  total.peersWithoutHandshakeEvidence += value.peersWithoutHandshakeEvidence;
  total.peersWithUnknownHandshakeEvidence += value.peersWithUnknownHandshakeEvidence;
  total.peersWithInvalidHandshakeEvidence += value.peersWithInvalidHandshakeEvidence;
}

function state(value: unknown): 'up' | 'down' | 'unknown' {
  return value === 'up' || value === 'down' ? value : 'unknown';
}

function safeCounter(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

function handshake(value: unknown): HandshakeEvidence {
  if (value === undefined || value === null) return 'absent';
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 'invalid';
  return value === 0 ? 'unknown' : 'present';
}

function projectPeer(value: Record<string, unknown>, peerIndex: number): WireguardPeer {
  return {
    peerIndex,
    handshake: handshake(value['last-handshake']),
    rxBytes: safeCounter(value['rxbytes']),
    txBytes: safeCounter(value['txbytes'])
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
  const wireguard = strictRecord(iface['wireguard']) ? iface['wireguard'] : {};
  const candidates = [wireguard['peer'], wireguard['peers'], iface['peer'], iface['peers']];
  let malformedCandidate = false;
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
      state: state(iface['state']),
      link: state(iface['link']),
      defaultGateway: typeof iface['defaultgw'] === 'boolean' ? iface['defaultgw'] : null,
      peerEvidenceStatus: 'unavailable',
      peersObserved: null,
      peersWithHandshakeEvidence: null,
      peersWithoutHandshakeEvidence: null,
      peersWithUnknownHandshakeEvidence: null,
      peersWithInvalidHandshakeEvidence: null,
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
      peersWithInvalidHandshakeEvidence: iface.peersWithInvalidHandshakeEvidence!
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
    interfaces: interfaces.slice(0, INTERFACE_DETAIL_LIMIT),
    shown: Math.min(interfaces.length, INTERFACE_DETAIL_LIMIT),
    total: interfaces.length,
    truncated: interfaces.length > INTERFACE_DETAIL_LIMIT
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
    description: 'Bounded current WireGuard interface, peer, handshake-presence, and counter evidence only; not a health or Internet/reachability verdict.',
    inputSchema: {},
    annotations: READ_ONLY
  }, guard(ctx, async () => {
    try {
      return compactOk(budgetWireguardStatus(
        sourceStatus(await ctx.client.rci.get('show/interface', INTERFACE_INPUT_LIMIT)),
        ctx.maxResponseBytes
      ), ctx.maxResponseBytes);
    } catch (error) {
      if (!(error instanceof RciError)) throw error;
      return compactOk(unavailable(error.code === 'response-too-large' ? 'response-too-large' : 'rci-error'),
        ctx.maxResponseBytes);
    }
  }));
}
