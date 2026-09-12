import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import type { KeeneticClient } from '../../src/router/client.js';
import type { RouterSnapshotV1 } from '../../src/shape/router-snapshot.js';
import { registerStateComparisonTools } from '../../src/tools/state-comparison.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, any>) => Promise<ToolResult>;

function snapshot(at: string, clients: number, uptime: number): RouterSnapshotV1 {
  const available = <T>(data: T) => ({ status: 'available' as const, reason: null, data });
  const zero = { total: 0, up: 0, down: 0, unknown: 0 };
  return { schemaVersion: 1, at, complete: true, sources: {
    system: available({ firmware: '5.1.4', uptimeSeconds: uptime, cpuLoad: 1, memoryFreeKb: 1 }),
    configuration: available({ runningChecksum: 'a'.repeat(32), savedChecksum: 'a'.repeat(32),
      unsavedChanges: false, savedState: 'available', savedReason: null }),
    interfaces: available({ total: 0, byKind: { wan: zero, lan: zero, wifi: zero,
      vpn: zero, bridge: zero, other: zero } }),
    routes: available({ total: 0, usable: 0, rejecting: 0, activePath: 'none' }),
    dns: available({ enabled: true, state: 'healthy', upstreamsTotal: 0,
      upstreamsHealthy: 0, upstreamsUnhealthy: 0, upstreamsUnknown: 0,
      staticHostsCount: 0, errorCount: 0 }),
    vpn: available({ ...zero, peersTotal: 0, peersOnline: 0, peersUnknown: 0 }),
    wifi: available({ clientCount: clients }),
    devices: available({ deviceCount: clients, activeCount: clients })
  } };
}

function harness(
  snapshots: RouterSnapshotV1[],
  opts: { skipped?: number; unsupportedVersions?: number; maxResponseBytes?: number;
    fail?: Error } = {}
) {
  const rci = { get: vi.fn(), post: vi.fn(), getText: vi.fn() };
  const client = { rci } as unknown as KeeneticClient;
  const list = opts.fail === undefined
    ? vi.fn(async () => ({ snapshots, skipped: opts.skipped ?? 0,
      ...(opts.unsupportedVersions === undefined ? {} : {
        unsupportedVersions: opts.unsupportedVersions
      }) }))
    : vi.fn(async () => { throw opts.fail; });
  const ctx: ToolContext = { client, maxResponseBytes: opts.maxResponseBytes ?? 25_000,
    readOnly: true, backup: stubBackup(), snapshotHistory: { list } };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const registrations: Record<string, any> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, config: unknown,
    handler: Handler) => {
    handlers[name] = handler;
    registrations[name] = config;
    return {} as never;
  }) as never);
  registerStateComparisonTools(server, ctx);
  return { handlers, registrations, list, rci };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(item => item.text).join(''));
}

describe('state comparison tools', () => {
  it('registers both tools read-only and compares the latest pair without RCI', async () => {
    const first = snapshot('2026-09-11T10:00:00.000Z', 2, 100);
    const second = snapshot('2026-09-11T10:01:00.000Z', 8, 160);
    const { handlers, registrations, rci } = harness([first, second]);
    expect(Object.keys(handlers).sort()).toEqual(['compare_router_state', 'get_recent_changes']);
    expect(registrations['compare_router_state'].annotations).toMatchObject({
      readOnlyHint: true, openWorldHint: false
    });
    const out = payload(await handlers['compare_router_state']!({ domains: ['wifi'] }));
    expect(out).toMatchObject({ status: 'changed', correlationOnly: true,
      selection: { policy: 'latest-pair', fromAt: first.at, toAt: second.at },
      changes: { total: 1, shown: 1 } });
    expect(rci.get).not.toHaveBeenCalled();
    expect(rci.post).not.toHaveBeenCalled();
  });

  it('supports exact endpoint policies and refuses ambiguous timestamps', async () => {
    const first = snapshot('2026-09-11T10:00:00.000Z', 2, 100);
    const middle = snapshot('2026-09-11T10:01:00.000Z', 3, 160);
    const last = snapshot('2026-09-11T10:02:00.000Z', 4, 220);
    const { handlers } = harness([first, middle, last]);
    const fromOnly = payload(await handlers['compare_router_state']!({ from_at: first.at,
      domains: ['wifi'] }));
    expect(fromOnly.selection).toMatchObject({ policy: 'exact-from-latest', toAt: last.at });
    expect(fromOnly.temporal.intermediateSnapshots).toBe(1);
    const toOnly = payload(await handlers['compare_router_state']!({ to_at: middle.at,
      domains: ['wifi'] }));
    expect(toOnly.selection).toMatchObject({ policy: 'exact-to-previous', fromAt: first.at });

    const duplicated = harness([first, middle, { ...middle }, last]);
    const ambiguous = payload(await duplicated.handlers['compare_router_state']!({
      from_at: first.at, to_at: middle.at, domains: ['wifi']
    }));
    expect(ambiguous).toMatchObject({ status: 'indeterminate', complete: false });
    expect(ambiguous.uncertainty).toContain('ambiguous-timestamp');

    const latestOnly = payload(await handlers['compare_router_state']!({
      from_at: last.at, domains: ['wifi']
    }));
    expect(latestOnly).toMatchObject({ status: 'insufficient-history',
      uncertainty: expect.arrayContaining(['snapshot-not-found']) });
  });

  it('rejects reversed exact endpoints before attempting to read history', async () => {
    const first = snapshot('2026-09-11T10:00:00.000Z', 2, 100);
    const last = snapshot('2026-09-11T10:01:00.000Z', 3, 160);
    const { handlers, list } = harness([first, last]);
    const result = await handlers['compare_router_state']!({ from_at: last.at, to_at: first.at });
    expect(result.isError).toBe(true);
    expect(list).not.toHaveBeenCalled();
  });

  it('returns newest changed intervals, suppresses unchanged ones and honors the inclusive window', async () => {
    const points = [
      snapshot('2026-09-11T10:00:00.000Z', 1, 100),
      snapshot('2026-09-11T10:01:00.000Z', 1, 160),
      snapshot('2026-09-11T10:02:00.000Z', 2, 220),
      snapshot('2026-09-11T10:03:00.000Z', 3, 280)
    ];
    const { handlers } = harness(points);
    const out = payload(await handlers['get_recent_changes']!({
      since: points[1]!.at, until: points[3]!.at, limit: 1, domains: ['wifi', 'wifi']
    }));
    expect(out).toMatchObject({ comparisonsConsidered: 3, unchangedComparisons: 1,
      events: { shown: 1, total: 2, truncated: true } });
    expect(out.events.items[0]).toMatchObject({ fromAt: points[2]!.at, toAt: points[3]!.at });
  });

  it('surfaces skipped and future-version history without exposing record data', async () => {
    const points = [snapshot('2026-09-11T10:00:00.000Z', 1, 100),
      snapshot('2026-09-11T10:01:00.000Z', 2, 160)];
    const { handlers } = harness(points, { skipped: 2, unsupportedVersions: 1 });
    const out = payload(await handlers['compare_router_state']!({ domains: ['wifi'] }));
    expect(out).toMatchObject({ complete: false,
      history: { skipped: 2, unsupportedVersions: 1 } });
    expect(out.uncertainty).toEqual(expect.arrayContaining([
      'history-records-skipped', 'unsupported-snapshot-version'
    ]));
  });

  it('does not emit equal intervals solely because global history is incomplete', async () => {
    const points = [snapshot('2026-09-11T10:00:00.000Z', 1, 100),
      snapshot('2026-09-11T10:01:00.000Z', 1, 160),
      snapshot('2026-09-11T10:02:00.000Z', 2, 220)];
    points[1]!.complete = false;
    points[1]!.sources.dns = { status: 'unavailable', reason: 'rci-error', data: null };
    const { handlers } = harness(points, { skipped: 1 });
    const out = payload(await handlers['get_recent_changes']!({ domains: ['wifi'], limit: 1 }));
    expect(out).toMatchObject({ status: 'partial', unchangedComparisons: 1,
      events: { total: 1, shown: 1 } });
    expect(out.events.items[0].status).toBe('changed');
  });

  it('retains intervals whose requested configuration fingerprints are unknown', async () => {
    const points = [snapshot('2026-09-11T10:00:00.000Z', 1, 100),
      snapshot('2026-09-11T10:01:00.000Z', 1, 160)];
    for (const point of points) {
      point.complete = false;
      point.sources.configuration.data!.savedChecksum = null;
      point.sources.configuration.data!.savedState = 'unknown';
      point.sources.configuration.data!.savedReason = 'unexpected-response';
      point.sources.configuration.data!.unsavedChanges = null;
    }
    const { handlers } = harness(points);
    const out = payload(await handlers['get_recent_changes']!({
      domains: ['configuration'], limit: 10
    }));
    expect(out).toMatchObject({ status: 'partial', unchangedComparisons: 0,
      events: { total: 1, shown: 1, items: [{ status: 'indeterminate' }] } });
  });

  it('does not describe an empty requested window as evidence of no changes', async () => {
    const points = [snapshot('2026-09-11T10:00:00.000Z', 1, 100),
      snapshot('2026-09-11T10:01:00.000Z', 2, 160)];
    const { handlers } = harness(points);
    const out = payload(await handlers['get_recent_changes']!({
      since: '2026-09-12T00:00:00.000Z', limit: 10
    }));
    expect(out).toMatchObject({ status: 'insufficient-history', comparisonsConsidered: 0,
      window: { firstAt: null, lastAt: null } });
    expect(out.uncertainty).toContain('no-comparisons-in-window');
  });

  it('turns unavailable readers into a safe local result without leaking error paths', async () => {
    const { handlers } = harness([], { fail: new Error('/private/state/home secret') });
    const result = await handlers['compare_router_state']!({});
    expect(result.isError).toBeUndefined();
    expect(result.content[0]!.text).not.toMatch(/private|secret/);
    expect(payload(result).uncertainty).toContain('history-unavailable');
    const selected = payload(await handlers['compare_router_state']!({
      from_at: '2026-09-11T10:00:00Z'
    }));
    expect(selected.selection).toMatchObject({
      requestedFrom: '2026-09-11T10:00:00.000Z', policy: 'exact-from-latest'
    });
  });

  it('bounds recent results while preserving the required envelope and newest events', async () => {
    const points = Array.from({ length: 20 }, (_, index) => snapshot(
      new Date(Date.parse('2026-09-11T10:00:00.000Z') + index * 60_000).toISOString(),
      index, 100 + index * 60));
    const { handlers } = harness(points, { maxResponseBytes: 2_000 });
    const result = await handlers['get_recent_changes']!({ limit: 50 });
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(2_000);
    expect(payload(result)).toMatchObject({ schemaVersion: 1, correlationOnly: true,
      truncated: true });
  });

  it('bounds a dense direct comparison without dropping its selection envelope', async () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 0, 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 20, 160);
    const interfaceData = after.sources.interfaces.data!;
    interfaceData.byKind = Object.fromEntries(
      Object.keys(interfaceData.byKind).map(kind => [kind,
        { total: 20, up: 10, down: 5, unknown: 5 }])
    ) as typeof interfaceData.byKind;
    interfaceData.total = 120;
    const { handlers } = harness([before, after], { maxResponseBytes: 2_000 });
    const result = await handlers['compare_router_state']!({});
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(2_000);
    expect(payload(result)).toMatchObject({ schemaVersion: 1, correlationOnly: true,
      selection: { fromAt: before.at, toAt: after.at }, truncated: true });
  });

  it('preserves a minimal versioned envelope for a very tight embedded context', async () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 0, 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 20, 160);
    const { handlers } = harness([before, after], { maxResponseBytes: 500 });
    for (const [name, args] of [
      ['compare_router_state', {}], ['get_recent_changes', { limit: 10 }]
    ] as const) {
      const result = await handlers[name]!(args);
      expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(500);
      expect(payload(result)).toMatchObject({ schemaVersion: 1, correlationOnly: true,
        truncated: true });
    }
  });

  it('trims interval details before dropping the sole newest indeterminate event', async () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 1, 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 1, 160);
    for (const domain of ['system', 'configuration', 'interfaces', 'routes', 'dns', 'vpn',
      'wifi', 'devices'] as const) {
      before.sources[domain] = { status: 'unavailable', reason: 'not-supported', data: null } as never;
      after.sources[domain] = { status: 'unavailable', reason: 'rci-error', data: null } as never;
    }
    before.complete = false;
    after.complete = false;
    const { handlers } = harness([before, after], { maxResponseBytes: 1_800 });
    const result = await handlers['get_recent_changes']!({ limit: 10 });
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(1_800);
    expect(out).toMatchObject({ truncated: true, events: { shown: 1, total: 1,
      items: [{ fromAt: before.at, toAt: after.at, status: 'indeterminate', truncated: true }] } });
  });
});
