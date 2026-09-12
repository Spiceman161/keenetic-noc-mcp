import { describe, expect, it } from 'vitest';
import { compareSnapshots } from '../../src/shape/state-comparison.js';
import type { RouterSnapshotV1 } from '../../src/shape/router-snapshot.js';

function snapshot(at: string, uptimeSeconds = 100): RouterSnapshotV1 {
  const available = <T>(data: T) => ({ status: 'available' as const, reason: null, data });
  return { schemaVersion: 1, at, complete: true, sources: {
    system: available({ firmware: '5.1.4', uptimeSeconds, cpuLoad: 7, memoryFreeKb: 2048 }),
    configuration: available({ runningChecksum: 'a'.repeat(32), savedChecksum: 'a'.repeat(32),
      unsavedChanges: false, savedState: 'available', savedReason: null }),
    interfaces: available({ total: 2, byKind: {
      wan: { total: 1, up: 1, down: 0, unknown: 0 },
      lan: { total: 1, up: 1, down: 0, unknown: 0 },
      wifi: { total: 0, up: 0, down: 0, unknown: 0 },
      vpn: { total: 0, up: 0, down: 0, unknown: 0 },
      bridge: { total: 0, up: 0, down: 0, unknown: 0 },
      other: { total: 0, up: 0, down: 0, unknown: 0 }
    } }),
    routes: available({ total: 1, usable: 1, rejecting: 0, activePath: 'physical' }),
    dns: available({ enabled: true, state: 'healthy', upstreamsTotal: 1,
      upstreamsHealthy: 1, upstreamsUnhealthy: 0, upstreamsUnknown: 0,
      staticHostsCount: 1, errorCount: 0 }),
    vpn: available({ total: 0, up: 0, down: 0, unknown: 0,
      peersTotal: 0, peersOnline: 0, peersUnknown: 0 }),
    wifi: available({ clientCount: 10 }),
    devices: available({ deviceCount: 20, activeCount: 10 })
  } };
}

describe('router state comparison', () => {
  it('reports an identical complete pair without treating volatile system gauges as changes', () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 160);
    after.sources.system.data!.cpuLoad = 99;
    after.sources.system.data!.memoryFreeKb = 1;
    expect(compareSnapshots(before, after)).toMatchObject({
      status: 'unchanged', complete: true,
      summary: { comparedDomains: 8, changedDomains: 0, changeCount: 0, anomalyCount: 0 },
      changes: []
    });
  });

  it('compares allowlisted state and count fields without exposing checksum values', () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 160);
    after.sources.configuration.data!.runningChecksum = 'b'.repeat(32);
    after.sources.routes.data!.activePath = 'vpn';
    after.sources.interfaces.data!.byKind.vpn = { total: 1, up: 1, down: 0, unknown: 0 };
    after.sources.interfaces.data!.total = 3;
    after.sources.dns.data!.state = 'unhealthy';
    after.sources.vpn.data!.peersOnline = 1;
    after.sources.vpn.data!.peersTotal = 1;
    after.sources.wifi.data!.clientCount = 4;
    after.sources.devices.data!.activeCount = 5;
    const result = compareSnapshots(before, after);
    expect(result.status).toBe('changed');
    expect(result.changes).toEqual(expect.arrayContaining([
      { domain: 'configuration', metric: 'runningChecksum', kind: 'fingerprint', changed: true },
      { domain: 'routes', metric: 'activePath', kind: 'state', from: 'physical', to: 'vpn' },
      { domain: 'wifi', metric: 'clientCount', kind: 'count', from: 10, to: 4,
        delta: -6, anomaly: 'drop' }
    ]));
    expect(JSON.stringify(result)).not.toContain('bbbbbbbb');
  });

  it('keeps unavailable sources separate from router state changes', () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 160);
    after.complete = false;
    after.sources.dns = { status: 'unavailable', reason: 'rci-error', data: null };
    const result = compareSnapshots(before, after, ['dns']);
    expect(result).toMatchObject({ status: 'indeterminate', complete: false, changes: [],
      coverage: [{ domain: 'dns', from: { status: 'available' },
        to: { status: 'unavailable', reason: 'rci-error' } }] });
  });

  it('does not call an unknown configuration fingerprint a change', () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 160);
    before.complete = false;
    before.sources.configuration.data!.savedChecksum = null;
    before.sources.configuration.data!.savedState = 'unknown';
    before.sources.configuration.data!.savedReason = 'unexpected-response';
    before.sources.configuration.data!.unsavedChanges = null;
    after.sources.configuration.data!.savedState = 'unknown';
    after.sources.configuration.data!.savedReason = 'unexpected-response';
    after.sources.configuration.data!.unsavedChanges = null;
    const result = compareSnapshots(before, after, ['configuration']);
    expect(result.changes).not.toContainEqual(expect.objectContaining({
      metric: 'savedChecksum', kind: 'fingerprint'
    }));
    expect(result).toMatchObject({ status: 'indeterminate', complete: false,
      fingerprintCoverage: [{ metric: 'savedChecksum', fromKnown: false, toKnown: true }] });
  });

  it('keeps two unknown fingerprints indeterminate instead of calling them equal', () => {
    const before = snapshot('2026-09-11T10:00:00.000Z', 100);
    const after = snapshot('2026-09-11T10:01:00.000Z', 160);
    for (const item of [before, after]) {
      item.complete = false;
      item.sources.configuration.data!.runningChecksum = null;
      item.sources.configuration.data!.savedChecksum = null;
      item.sources.configuration.data!.savedState = 'unknown';
      item.sources.configuration.data!.savedReason = 'unexpected-response';
      item.sources.configuration.data!.unsavedChanges = null;
    }
    const result = compareSnapshots(before, after, ['configuration']);
    expect(result).toMatchObject({ status: 'indeterminate', complete: false,
      fingerprintCoverage: expect.arrayContaining([
        expect.objectContaining({ metric: 'runningChecksum', fromKnown: false, toKnown: false }),
        expect.objectContaining({ metric: 'savedChecksum', fromKnown: false, toKnown: false })
      ]) });
  });

  it('uses exact inclusive anomaly thresholds including a zero baseline', () => {
    const cases = [
      [10, 15, 'spike'], [10, 14, null], [20, 25, null], [0, 5, 'spike'], [5, 0, 'drop']
    ] as const;
    for (const [fromCount, toCount, expected] of cases) {
      const before = snapshot('2026-09-11T10:00:00.000Z', 100);
      const after = snapshot('2026-09-11T10:01:00.000Z', 160);
      before.sources.wifi.data!.clientCount = fromCount;
      after.sources.wifi.data!.clientCount = toCount;
      expect(compareSnapshots(before, after, ['wifi']).changes[0]).toMatchObject({ anomaly: expected });
    }
  });

  it('marks uptime resets, clock divergence and non-adjacent observations conservatively', () => {
    const reboot = compareSnapshots(snapshot('2026-09-11T10:00:00.000Z', 1_000),
      snapshot('2026-09-11T10:10:00.000Z', 10));
    expect(reboot).toMatchObject({ complete: false,
      status: 'indeterminate',
      temporal: { rebootEvidence: 'uptime-reset', clock: 'unknown' } });
    expect(reboot.uncertainty).toContain('reboot-or-clock-ordering-possible');

    const shifted = compareSnapshots(snapshot('2026-09-11T10:00:00.000Z', 100),
      snapshot('2026-09-11T11:00:00.000Z', 200), undefined, 2);
    expect(shifted).toMatchObject({ complete: false, temporal: {
      intermediateSnapshots: 2, continuity: 'non-adjacent-observations',
      clock: 'possible-adjustment'
    } });
  });
});
