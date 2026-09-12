import type { InterfaceKind, RouterSnapshotV1 } from './router-snapshot.js';

export const COMPARISON_DOMAINS = [
  'system', 'configuration', 'interfaces', 'routes', 'dns', 'vpn', 'wifi', 'devices'
] as const;

export type ComparisonDomain = typeof COMPARISON_DOMAINS[number];
export type SafeState = string | boolean | null;

export type StateChange =
  | { domain: ComparisonDomain; metric: string; kind: 'state'; from: SafeState; to: SafeState }
  | { domain: ComparisonDomain; metric: string; kind: 'count'; from: number; to: number;
    delta: number; anomaly: 'spike' | 'drop' | null }
  | { domain: 'configuration'; metric: 'runningChecksum' | 'savedChecksum';
    kind: 'fingerprint'; changed: true };

export interface CoverageGap {
  domain: ComparisonDomain;
  from: { status: 'available' | 'unavailable'; reason: string | null };
  to: { status: 'available' | 'unavailable'; reason: string | null };
}

export interface FingerprintGap {
  domain: 'configuration';
  metric: 'runningChecksum' | 'savedChecksum';
  fromKnown: boolean;
  toKnown: boolean;
}

export interface TemporalComparison {
  elapsedSeconds: number;
  intermediateSnapshots: number;
  continuity: 'adjacent-observations' | 'non-adjacent-observations';
  rebootEvidence: 'uptime-reset' | 'not-detected' | 'unknown';
  clock: 'consistent' | 'possible-adjustment' | 'unknown';
}

export interface SnapshotDifference {
  status: 'changed' | 'unchanged' | 'indeterminate';
  complete: boolean;
  fromAt: string;
  toAt: string;
  temporal: TemporalComparison;
  summary: { comparedDomains: number; changedDomains: number; changeCount: number;
    anomalyCount: number };
  changes: StateChange[];
  coverage: CoverageGap[];
  fingerprintCoverage: FingerprintGap[];
  uncertainty: string[];
}

const INTERFACE_KINDS: readonly InterfaceKind[] = [
  'wan', 'lan', 'wifi', 'vpn', 'bridge', 'other'
];

function sourceState(source: { status: 'available' | 'unavailable'; reason: string | null }): CoverageGap['from'] {
  return source.status === 'available'
    ? { status: 'available', reason: null }
    : { status: 'unavailable', reason: source.reason };
}

function anomaly(from: number, to: number): 'spike' | 'drop' | null {
  const delta = to - from;
  if (Math.abs(delta) < 5) return null;
  const relative = from === 0 ? (to === 0 ? 0 : Number.POSITIVE_INFINITY) : Math.abs(delta) / from;
  return relative >= 0.5 ? delta > 0 ? 'spike' : 'drop' : null;
}

function countChange(
  changes: StateChange[], domain: ComparisonDomain, metric: string,
  from: number, to: number, detectAnomaly = false
): void {
  if (from === to) return;
  changes.push({ domain, metric, kind: 'count', from, to, delta: to - from,
    anomaly: detectAnomaly ? anomaly(from, to) : null });
}

function stateChange(
  changes: StateChange[], domain: ComparisonDomain, metric: string,
  from: SafeState, to: SafeState
): void {
  if (from !== to) changes.push({ domain, metric, kind: 'state', from, to });
}

function temporal(from: RouterSnapshotV1, to: RouterSnapshotV1, intermediateSnapshots: number): {
  value: TemporalComparison; uncertainty: string[]
} {
  const elapsedSeconds = (Date.parse(to.at) - Date.parse(from.at)) / 1_000;
  const fromUptime = from.sources.system.data?.uptimeSeconds ?? null;
  const toUptime = to.sources.system.data?.uptimeSeconds ?? null;
  let rebootEvidence: TemporalComparison['rebootEvidence'] = 'unknown';
  let clock: TemporalComparison['clock'] = 'unknown';
  const uncertainty: string[] = [];
  if (fromUptime !== null && toUptime !== null) {
    if (toUptime < fromUptime) {
      rebootEvidence = 'uptime-reset';
      clock = 'unknown';
      uncertainty.push('reboot-or-clock-ordering-possible');
    } else {
      rebootEvidence = 'not-detected';
      clock = Math.abs((toUptime - fromUptime) - elapsedSeconds) > 300
        ? 'possible-adjustment' : 'consistent';
      if (clock === 'possible-adjustment') uncertainty.push('clock-adjustment-possible');
    }
  } else {
    uncertainty.push('uptime-unavailable');
  }
  if (intermediateSnapshots > 0) uncertainty.push('non-adjacent-observations');
  return { value: { elapsedSeconds, intermediateSnapshots,
    continuity: intermediateSnapshots === 0 ? 'adjacent-observations' : 'non-adjacent-observations',
    rebootEvidence, clock }, uncertainty };
}

/** Compares only explicitly allowlisted aggregate fields from two canonical snapshots. */
export function compareSnapshots(
  from: RouterSnapshotV1,
  to: RouterSnapshotV1,
  domains: readonly ComparisonDomain[] = COMPARISON_DOMAINS,
  intermediateSnapshots = 0,
  historyIncomplete = false
): SnapshotDifference {
  const changes: StateChange[] = [];
  const coverage: CoverageGap[] = [];
  const fingerprintCoverage: FingerprintGap[] = [];
  const changedDomains = new Set<ComparisonDomain>();
  let comparedDomains = 0;

  for (const domain of domains) {
    const before = from.sources[domain];
    const after = to.sources[domain];
    if (before.status !== 'available' || after.status !== 'available') {
      coverage.push({ domain, from: sourceState(before), to: sourceState(after) });
      continue;
    }
    comparedDomains += 1;
    const start = changes.length;
    switch (domain) {
      case 'system': {
        const beforeData = from.sources.system.data;
        const afterData = to.sources.system.data;
        if (beforeData === null || afterData === null) break;
        stateChange(changes, domain, 'firmware', beforeData.firmware, afterData.firmware);
        break;
      }
      case 'configuration': {
        const beforeData = from.sources.configuration.data;
        const afterData = to.sources.configuration.data;
        if (beforeData === null || afterData === null) break;
        if (beforeData.runningChecksum !== null && afterData.runningChecksum !== null &&
            beforeData.runningChecksum !== afterData.runningChecksum) {
          changes.push({ domain, metric: 'runningChecksum', kind: 'fingerprint', changed: true });
        } else if (beforeData.runningChecksum === null || afterData.runningChecksum === null) {
          fingerprintCoverage.push({ domain, metric: 'runningChecksum',
            fromKnown: beforeData.runningChecksum !== null, toKnown: afterData.runningChecksum !== null });
        }
        if (beforeData.savedChecksum !== null && afterData.savedChecksum !== null &&
            beforeData.savedChecksum !== afterData.savedChecksum) {
          changes.push({ domain, metric: 'savedChecksum', kind: 'fingerprint', changed: true });
        } else if (beforeData.savedChecksum === null || afterData.savedChecksum === null) {
          fingerprintCoverage.push({ domain, metric: 'savedChecksum',
            fromKnown: beforeData.savedChecksum !== null, toKnown: afterData.savedChecksum !== null });
        }
        stateChange(changes, domain, 'unsavedChanges', beforeData.unsavedChanges,
          afterData.unsavedChanges);
        stateChange(changes, domain, 'savedState', beforeData.savedState, afterData.savedState);
        break;
      }
      case 'interfaces': {
        const beforeData = from.sources.interfaces.data;
        const afterData = to.sources.interfaces.data;
        if (beforeData === null || afterData === null) break;
        countChange(changes, domain, 'total', beforeData.total, afterData.total);
        for (const kind of INTERFACE_KINDS) {
          for (const state of ['total', 'up', 'down', 'unknown'] as const) {
            countChange(changes, domain, `${kind}.${state}`,
              beforeData.byKind[kind][state], afterData.byKind[kind][state]);
          }
        }
        break;
      }
      case 'routes': {
        const beforeData = from.sources.routes.data;
        const afterData = to.sources.routes.data;
        if (beforeData === null || afterData === null) break;
        countChange(changes, domain, 'total', beforeData.total, afterData.total);
        countChange(changes, domain, 'usable', beforeData.usable, afterData.usable);
        countChange(changes, domain, 'rejecting', beforeData.rejecting, afterData.rejecting);
        stateChange(changes, domain, 'activePath', beforeData.activePath, afterData.activePath);
        break;
      }
      case 'dns': {
        const beforeData = from.sources.dns.data;
        const afterData = to.sources.dns.data;
        if (beforeData === null || afterData === null) break;
        stateChange(changes, domain, 'enabled', beforeData.enabled, afterData.enabled);
        stateChange(changes, domain, 'state', beforeData.state, afterData.state);
        for (const metric of ['upstreamsTotal', 'upstreamsHealthy', 'upstreamsUnhealthy',
          'upstreamsUnknown', 'staticHostsCount', 'errorCount'] as const) {
          countChange(changes, domain, metric, beforeData[metric], afterData[metric]);
        }
        break;
      }
      case 'vpn': {
        const beforeData = from.sources.vpn.data;
        const afterData = to.sources.vpn.data;
        if (beforeData === null || afterData === null) break;
        for (const metric of ['total', 'up', 'down', 'unknown', 'peersTotal', 'peersOnline',
          'peersUnknown'] as const) {
          countChange(changes, domain, metric, beforeData[metric], afterData[metric]);
        }
        break;
      }
      case 'wifi': {
        const beforeData = from.sources.wifi.data;
        const afterData = to.sources.wifi.data;
        if (beforeData === null || afterData === null) break;
        countChange(changes, domain, 'clientCount', beforeData.clientCount,
          afterData.clientCount, true);
        break;
      }
      case 'devices': {
        const beforeData = from.sources.devices.data;
        const afterData = to.sources.devices.data;
        if (beforeData === null || afterData === null) break;
        countChange(changes, domain, 'deviceCount', beforeData.deviceCount, afterData.deviceCount);
        countChange(changes, domain, 'activeCount', beforeData.activeCount,
          afterData.activeCount, true);
        break;
      }
    }
    if (changes.length > start) changedDomains.add(domain);
  }

  const assessed = temporal(from, to, intermediateSnapshots);
  const uncertainty = [...assessed.uncertainty];
  if (!from.complete || !to.complete) uncertainty.push('partial-snapshot');
  if (coverage.length > 0) uncertainty.push('source-unavailable');
  if (fingerprintCoverage.length > 0) uncertainty.push('fingerprint-unavailable');
  if (historyIncomplete) uncertainty.push('history-records-skipped');
  const uniqueUncertainty = [...new Set(uncertainty)];
  const temporalUncertain = assessed.value.clock === 'possible-adjustment' ||
    assessed.value.rebootEvidence === 'uptime-reset';
  const status = changes.length > 0 ? 'changed'
    : coverage.length > 0 || fingerprintCoverage.length > 0 || temporalUncertain
      ? 'indeterminate' : 'unchanged';
  const complete = coverage.length === 0 && fingerprintCoverage.length === 0 && !historyIncomplete &&
    assessed.value.clock !== 'possible-adjustment' && assessed.value.rebootEvidence !== 'uptime-reset';
  return {
    status, complete, fromAt: from.at, toAt: to.at, temporal: assessed.value,
    summary: { comparedDomains, changedDomains: changedDomains.size, changeCount: changes.length,
      anomalyCount: changes.filter(change => change.kind === 'count' && change.anomaly !== null).length },
    changes, coverage, fingerprintCoverage, uncertainty: uniqueUncertainty
  };
}

export function uniqueDomains(domains?: readonly ComparisonDomain[]): ComparisonDomain[] {
  return domains === undefined ? [...COMPARISON_DOMAINS] : [...new Set(domains)];
}
