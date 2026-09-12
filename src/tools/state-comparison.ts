import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import type { SnapshotListResult } from '../router/snapshot-store.js';
import { ValidationError } from '../router/errors.js';
import type { RouterSnapshotV1 } from '../shape/router-snapshot.js';
import {
  COMPARISON_DOMAINS,
  compareSnapshots,
  uniqueDomains,
  type ComparisonDomain,
  type CoverageGap,
  type FingerprintGap,
  type SnapshotDifference,
  type StateChange,
  type TemporalComparison
} from '../shape/state-comparison.js';
import { compactOk, guard, READ_ONLY, type ToolContext, type ToolResult } from './registry.js';

const domainSchema = z.enum(COMPARISON_DOMAINS);
const timestampSchema = z.string().datetime({ offset: true });
const domainsSchema = z.array(domainSchema).min(1).max(COMPARISON_DOMAINS.length).optional();

interface HistoryMetadata {
  loaded: number;
  skipped: number;
  unsupportedVersions: number;
  retainedHistoryOnly: true;
}

interface ChangeCollection {
  items: StateChange[];
  shown: number;
  total: number;
  truncated: boolean;
}

interface ComparisonReport {
  schemaVersion: 1;
  status: SnapshotDifference['status'] | 'insufficient-history';
  correlationOnly: true;
  complete: boolean;
  selection: {
    requestedFrom: string | null;
    requestedTo: string | null;
    fromAt: string | null;
    toAt: string | null;
    policy: 'latest-pair' | 'exact' | 'exact-to-previous' | 'exact-from-latest';
  };
  temporal: TemporalComparison | null;
  history: HistoryMetadata;
  summary: SnapshotDifference['summary'];
  changes: ChangeCollection;
  coverage: CoverageGap[];
  fingerprintCoverage: FingerprintGap[];
  uncertainty: string[];
  truncated: boolean;
}

interface RecentEvent {
  fromAt: string;
  toAt: string;
  status: SnapshotDifference['status'];
  complete: boolean;
  temporal: TemporalComparison | null;
  summary: SnapshotDifference['summary'];
  changes: ChangeCollection;
  coverage: CoverageGap[];
  fingerprintCoverage: FingerprintGap[];
  uncertainty: string[];
  truncated: boolean;
}

interface RecentReport {
  schemaVersion: 1;
  status: 'available' | 'partial' | 'insufficient-history';
  correlationOnly: true;
  window: { requestedSince: string | null; requestedUntil: string | null;
    firstAt: string | null; lastAt: string | null };
  history: HistoryMetadata;
  comparisonsConsidered: number;
  unchangedComparisons: number;
  events: { items: RecentEvent[]; shown: number; total: number; truncated: boolean };
  uncertainty: string[];
  truncated: boolean;
}

function bytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function historyMetadata(listed: SnapshotListResult): HistoryMetadata {
  return { loaded: listed.snapshots.length, skipped: listed.skipped,
    unsupportedVersions: listed.unsupportedVersions ?? 0, retainedHistoryOnly: true };
}

function sorted(snapshots: readonly RouterSnapshotV1[]): RouterSnapshotV1[] {
  return [...snapshots].sort((left, right) => left.at.localeCompare(right.at));
}

function groups(snapshots: readonly RouterSnapshotV1[]): RouterSnapshotV1[][] {
  const result: RouterSnapshotV1[][] = [];
  for (const snapshot of sorted(snapshots)) {
    const last = result[result.length - 1];
    if (last?.[0]?.at === snapshot.at) last.push(snapshot);
    else result.push([snapshot]);
  }
  return result;
}

function emptySummary(): SnapshotDifference['summary'] {
  return { comparedDomains: 0, changedDomains: 0, changeCount: 0, anomalyCount: 0 };
}

function reportFromDifference(
  difference: SnapshotDifference,
  selection: ComparisonReport['selection'],
  history: HistoryMetadata,
  unsupported: boolean
): ComparisonReport {
  const uncertainty = [...difference.uncertainty];
  if (unsupported) uncertainty.push('unsupported-snapshot-version');
  return {
    schemaVersion: 1, status: difference.status, correlationOnly: true,
    complete: difference.complete && !unsupported,
    selection, temporal: difference.temporal, history, summary: difference.summary,
    changes: { items: difference.changes, shown: difference.changes.length,
      total: difference.changes.length, truncated: false },
    coverage: difference.coverage, fingerprintCoverage: difference.fingerprintCoverage,
    uncertainty: [...new Set(uncertainty)], truncated: false
  };
}

function indeterminateReport(
  selection: ComparisonReport['selection'],
  history: HistoryMetadata,
  status: 'indeterminate' | 'insufficient-history',
  uncertainty: string[]
): ComparisonReport {
  if (history.skipped > 0) uncertainty.push('history-records-skipped');
  if (history.unsupportedVersions > 0) uncertainty.push('unsupported-snapshot-version');
  return { schemaVersion: 1, status, correlationOnly: true, complete: false, selection,
    temporal: null, history, summary: emptySummary(),
    changes: { items: [], shown: 0, total: 0, truncated: false }, coverage: [],
    fingerprintCoverage: [],
    uncertainty: [...new Set(uncertainty)], truncated: false };
}

function exactGroup(all: RouterSnapshotV1[][], at: string): RouterSnapshotV1[] | undefined {
  return all.find(group => group[0]?.at === at);
}

function comparisonReport(
  listed: SnapshotListResult,
  requestedFrom: string | null,
  requestedTo: string | null,
  domains: readonly ComparisonDomain[]
): ComparisonReport {
  const all = groups(listed.snapshots);
  const history = historyMetadata(listed);
  const policy: ComparisonReport['selection']['policy'] = requestedFrom !== null && requestedTo !== null
    ? 'exact' : requestedFrom !== null ? 'exact-from-latest'
      : requestedTo !== null ? 'exact-to-previous' : 'latest-pair';
  const baseSelection: ComparisonReport['selection'] = {
    requestedFrom, requestedTo, fromAt: null, toAt: null, policy
  };
  if (all.length < 2) {
    return indeterminateReport(baseSelection, history, 'insufficient-history', ['insufficient-history']);
  }

  let fromGroup: RouterSnapshotV1[] | undefined;
  let toGroup: RouterSnapshotV1[] | undefined;
  if (requestedTo !== null) toGroup = exactGroup(all, requestedTo);
  else if (requestedFrom !== null) {
    const latest = all[all.length - 1];
    toGroup = latest !== undefined && latest[0]!.at > requestedFrom ? latest : undefined;
  } else toGroup = all[all.length - 1];
  if (requestedFrom !== null) fromGroup = exactGroup(all, requestedFrom);
  else {
    const toIndex = toGroup === undefined ? -1 : all.indexOf(toGroup);
    fromGroup = toIndex > 0 ? all[toIndex - 1] : undefined;
  }
  const selection = { ...baseSelection, fromAt: fromGroup?.[0]?.at ?? null,
    toAt: toGroup?.[0]?.at ?? null };
  if (fromGroup === undefined || toGroup === undefined) {
    return indeterminateReport(selection, history, 'insufficient-history', ['snapshot-not-found']);
  }
  if (fromGroup.length !== 1 || toGroup.length !== 1) {
    return indeterminateReport(selection, history, 'indeterminate', ['ambiguous-timestamp']);
  }
  const from = fromGroup[0]!;
  const to = toGroup[0]!;
  if (from.at >= to.at) {
    return indeterminateReport(selection, history, 'indeterminate', ['invalid-observation-order']);
  }
  const intermediate = Math.max(0, all.indexOf(toGroup) - all.indexOf(fromGroup) - 1);
  return reportFromDifference(compareSnapshots(from, to, domains, intermediate, listed.skipped > 0),
    selection, history, history.unsupportedVersions > 0);
}

function boundedComparison(report: ComparisonReport, maxBytes: number): Record<string, unknown> {
  const result = { ...report, changes: { ...report.changes, items: [...report.changes.items] },
    coverage: [...report.coverage], fingerprintCoverage: [...report.fingerprintCoverage],
    uncertainty: [...report.uncertainty] };
  while (bytes(result) > maxBytes && result.changes.items.length > 0) {
    result.changes.items.pop();
    result.changes.shown = result.changes.items.length;
    result.changes.truncated = true;
    result.truncated = true;
  }
  while (bytes(result) > maxBytes && result.coverage.length > 0) {
    result.coverage.pop();
    result.truncated = true;
  }
  while (bytes(result) > maxBytes && result.fingerprintCoverage.length > 0) {
    result.fingerprintCoverage.pop();
    result.truncated = true;
  }
  while (bytes(result) > maxBytes && result.uncertainty.length > 1) {
    result.uncertainty.pop();
    result.truncated = true;
  }
  if (bytes(result) > maxBytes) {
    return { schemaVersion: 1, status: report.status, correlationOnly: true,
      complete: false, selection: report.selection, summary: report.summary,
      changes: { items: [], shown: 0, total: report.changes.total, truncated: true },
      truncated: true };
  }
  return result;
}

function eventFromDifference(difference: SnapshotDifference): RecentEvent {
  return { fromAt: difference.fromAt, toAt: difference.toAt, status: difference.status,
    complete: difference.complete, temporal: difference.temporal, summary: difference.summary,
    changes: { items: difference.changes, shown: difference.changes.length,
      total: difference.changes.length, truncated: false },
    coverage: difference.coverage, fingerprintCoverage: difference.fingerprintCoverage,
    uncertainty: difference.uncertainty, truncated: false };
}

function ambiguousEvent(fromAt: string, toAt: string): RecentEvent {
  return { fromAt, toAt, status: 'indeterminate', complete: false, temporal: null,
    summary: emptySummary(), changes: { items: [], shown: 0, total: 0, truncated: false },
    coverage: [], fingerprintCoverage: [], uncertainty: ['ambiguous-timestamp'], truncated: false };
}

function recentReport(
  listed: SnapshotListResult,
  since: string | null,
  until: string | null,
  limit: number,
  domains: readonly ComparisonDomain[]
): RecentReport {
  const all = groups(listed.snapshots);
  const history = historyMetadata(listed);
  const globalUncertainty: string[] = [];
  if (listed.skipped > 0) globalUncertainty.push('history-records-skipped');
  if (history.unsupportedVersions > 0) globalUncertainty.push('unsupported-snapshot-version');
  const window = { requestedSince: since, requestedUntil: until,
    firstAt: null as string | null, lastAt: null as string | null };
  if (all.length < 2) {
    return { schemaVersion: 1, status: 'insufficient-history', correlationOnly: true,
      window, history, comparisonsConsidered: 0, unchangedComparisons: 0,
      events: { items: [], shown: 0, total: 0, truncated: false },
      uncertainty: [...globalUncertainty, 'insufficient-history'], truncated: false };
  }

  const events: RecentEvent[] = [];
  let considered = 0;
  let unchanged = 0;
  for (let index = 1; index < all.length; index += 1) {
    const fromGroup = all[index - 1]!;
    const toGroup = all[index]!;
    const toAt = toGroup[0]!.at;
    if (since !== null && toAt < since || until !== null && toAt > until) continue;
    window.firstAt ??= fromGroup[0]!.at;
    window.lastAt = toAt;
    considered += 1;
    if (fromGroup.length !== 1 || toGroup.length !== 1) {
      events.push(ambiguousEvent(fromGroup[0]!.at, toAt));
      continue;
    }
    const difference = compareSnapshots(fromGroup[0]!, toGroup[0]!, domains, 0,
      listed.skipped > 0);
    if (difference.status === 'unchanged') unchanged += 1;
    else events.push(eventFromDifference(difference));
  }
  if (considered === 0) {
    return { schemaVersion: 1, status: 'insufficient-history', correlationOnly: true,
      window, history, comparisonsConsidered: 0, unchangedComparisons: 0,
      events: { items: [], shown: 0, total: 0, truncated: false },
      uncertainty: [...globalUncertainty, 'no-comparisons-in-window'], truncated: false };
  }
  const total = events.length;
  const selected = events.slice(-limit).reverse();
  const truncated = selected.length < total;
  return { schemaVersion: 1,
    status: globalUncertainty.length > 0 || events.some(event => !event.complete) ? 'partial' : 'available',
    correlationOnly: true, window, history, comparisonsConsidered: considered,
    unchangedComparisons: unchanged,
    events: { items: selected, shown: selected.length, total, truncated },
    uncertainty: globalUncertainty, truncated };
}

function boundedRecent(report: RecentReport, maxBytes: number): Record<string, unknown> {
  const result: RecentReport = { ...report, uncertainty: [...report.uncertainty],
    events: { ...report.events, items: report.events.items.map(event => ({ ...event,
      changes: { ...event.changes, items: [...event.changes.items] },
      coverage: [...event.coverage], fingerprintCoverage: [...event.fingerprintCoverage],
      uncertainty: [...event.uncertainty] })) } };
  for (let index = result.events.items.length - 1; bytes(result) > maxBytes && index >= 0; index -= 1) {
    const event = result.events.items[index]!;
    while (bytes(result) > maxBytes && event.changes.items.length > 0) {
      event.changes.items.pop();
      event.changes.shown = event.changes.items.length;
      event.changes.truncated = true;
      event.truncated = true;
      result.truncated = true;
    }
    while (bytes(result) > maxBytes && event.coverage.length > 0) {
      event.coverage.pop();
      event.truncated = true;
      result.truncated = true;
    }
    while (bytes(result) > maxBytes && event.fingerprintCoverage.length > 0) {
      event.fingerprintCoverage.pop();
      event.truncated = true;
      result.truncated = true;
    }
    while (bytes(result) > maxBytes && event.uncertainty.length > 1) {
      event.uncertainty.pop();
      event.truncated = true;
      result.truncated = true;
    }
  }
  while (bytes(result) > maxBytes && result.events.items.length > 0) {
    result.events.items.pop();
    result.events.shown = result.events.items.length;
    result.events.truncated = true;
    result.truncated = true;
  }
  if (bytes(result) > maxBytes) {
    return { schemaVersion: 1, status: report.status, correlationOnly: true,
      window: report.window, comparisonsConsidered: report.comparisonsConsidered,
      unchangedComparisons: report.unchangedComparisons,
      events: { items: [], shown: 0, total: report.events.total, truncated: true },
      truncated: true };
  }
  return { ...result };
}

async function listHistory(ctx: ToolContext): Promise<SnapshotListResult | null> {
  if (ctx.snapshotHistory === undefined) return null;
  try { return await ctx.snapshotHistory.list(); }
  catch { return null; }
}

function unavailableHistoryReport(
  requestedFrom: string | null,
  requestedTo: string | null
): ComparisonReport {
  const policy: ComparisonReport['selection']['policy'] = requestedFrom !== null && requestedTo !== null
    ? 'exact' : requestedFrom !== null ? 'exact-from-latest'
      : requestedTo !== null ? 'exact-to-previous' : 'latest-pair';
  return indeterminateReport({ requestedFrom, requestedTo, fromAt: null, toAt: null,
    policy }, { loaded: 0, skipped: 0, unsupportedVersions: 0,
    retainedHistoryOnly: true }, 'indeterminate', ['history-unavailable']);
}

function normalizeTimestamp(value: string | undefined): string | null {
  return value === undefined ? null : new Date(value).toISOString();
}

export function registerStateComparisonTools(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool('compare_router_state', {
    title: 'Compare two stored router observations',
    description: 'Compares two locally stored privacy-minimized router observations without reading the live router, creating a snapshot, or claiming causality.',
    inputSchema: {
      from_at: timestampSchema.optional().describe('Exact baseline snapshot time; defaults according to the documented selection policy.'),
      to_at: timestampSchema.optional().describe('Exact target snapshot time; defaults to the newest stored observation.'),
      domains: domainsSchema.describe('Optional allowlist of state domains to compare; defaults to every snapshot domain.')
    },
    annotations: READ_ONLY
  }, guard(async ({ from_at, to_at, domains }): Promise<ToolResult> => {
    const from = normalizeTimestamp(from_at);
    const to = normalizeTimestamp(to_at);
    if (from !== null && to !== null && from >= to) {
      throw new ValidationError('from_at must be earlier than to_at.');
    }
    const listed = await listHistory(ctx);
    if (listed === null) return compactOk(boundedComparison(unavailableHistoryReport(from, to),
      ctx.maxResponseBytes), ctx.maxResponseBytes);
    const report = comparisonReport(listed, from, to, uniqueDomains(domains));
    return compactOk(boundedComparison(report, ctx.maxResponseBytes), ctx.maxResponseBytes);
  }));

  server.registerTool('get_recent_changes', {
    title: 'Read recent changes between stored observations',
    description: 'Finds bounded differences between locally stored router observations without live router access, automatic capture, or causal claims.',
    inputSchema: {
      since: timestampSchema.optional().describe('Inclusive lower bound for the target observation time.'),
      until: timestampSchema.optional().describe('Inclusive upper bound for the target observation time.'),
      limit: z.number().int().min(1).max(50).optional().default(10)
        .describe('Maximum newest changed or indeterminate observation intervals to return.'),
      domains: domainsSchema.describe('Optional allowlist of state domains to compare; defaults to every snapshot domain.')
    },
    annotations: READ_ONLY
  }, guard(async ({ since, until, limit, domains }): Promise<ToolResult> => {
    const normalizedSince = normalizeTimestamp(since);
    const normalizedUntil = normalizeTimestamp(until);
    if (normalizedSince !== null && normalizedUntil !== null && normalizedSince > normalizedUntil) {
      throw new ValidationError('since must not be later than until.');
    }
    const listed = await listHistory(ctx);
    if (listed === null) {
      const report: RecentReport = { schemaVersion: 1, status: 'partial', correlationOnly: true,
        window: { requestedSince: normalizedSince, requestedUntil: normalizedUntil,
          firstAt: null, lastAt: null },
        history: { loaded: 0, skipped: 0, unsupportedVersions: 0, retainedHistoryOnly: true },
        comparisonsConsidered: 0, unchangedComparisons: 0,
        events: { items: [], shown: 0, total: 0, truncated: false },
        uncertainty: ['history-unavailable'], truncated: false };
      return compactOk(boundedRecent(report, ctx.maxResponseBytes), ctx.maxResponseBytes);
    }
    return compactOk(boundedRecent(recentReport(listed, normalizedSince, normalizedUntil,
      limit, uniqueDomains(domains)), ctx.maxResponseBytes), ctx.maxResponseBytes);
  }));
}
