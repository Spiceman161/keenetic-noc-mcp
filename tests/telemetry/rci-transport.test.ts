import { describe, expect, it } from 'vitest';
import {
  RciTransportCollector,
  currentRciTransportCollector,
  runWithRciTransportCollector
} from '../../src/telemetry/rci-transport.js';

function remote(retainEdgeIps = true, endpoint = 'https://edge.keenetic.pro/rci/'): RciTransportCollector {
  return new RciTransportCollector({
    connection: { mode: 'remote', endpoint },
    retainEdgeIps
  });
}

describe('RCI transport telemetry collector', () => {
  it('captures only bounded canonical, first-seen remote attempt evidence', () => {
    const collector = remote();
    runWithRciTransportCollector(collector, () => {
      const operation = currentRciTransportCollector()?.beginOperation();
      operation?.normalAttempt();
      operation?.observedEdge('192.0.2.1');
      operation?.observedEdge('192.0.2.1');
      operation?.selectedNormalEdge('2001:db8:0:0:0:0:0:1');
      for (let index = 2; index <= 17; index += 1) operation?.observedEdge(`192.0.2.${index}`);
      operation?.correlationComplete(true);
      operation?.terminal('normal_response');
    });

    const snapshot = collector.seal();
    expect(snapshot).not.toBeInstanceOf(Promise);
    expect(snapshot).toMatchObject({
      applicability: 'remote',
      edge_ip_retention: 'enabled',
      normal_attempts: 1,
      correlation_complete: true,
      edge_ips_truncated: true,
      selected_normal_edge_ips: ['2001:db8::1'],
      terminal_reasons: { normal_response: 1 }
    });
    expect((snapshot as Exclude<typeof snapshot, Promise<unknown>>).observed_edge_ips).toHaveLength(16);
  });

  it('suppresses all IP slots outside the exact Cloud opt-in without losing counts', () => {
    const collector = remote(false);
    const operation = collector.beginOperation()!;
    operation.normalAttempt();
    operation.observedEdge('192.0.2.1');
    operation.selectedNormalEdge('192.0.2.1');
    const event = operation.beginFallback(4, 3, [{ ip: '192.0.2.2', prior: 'healthy' }]);
    event.attempted('192.0.2.2', 'failed');
    event.finish('exhausted');
    operation.terminal('fallback_exhausted');
    const snapshot = collector.seal() as Exclude<ReturnType<RciTransportCollector['seal']>, Promise<unknown>>;
    expect(snapshot).toMatchObject({
      edge_ip_retention: 'suppressed_by_config',
      normal_attempts: 1,
      fallback_attempts: 1,
      fallback_exhaustions: 1,
      observed_edge_ips: null,
      selected_normal_edge_ips: null,
      fallback_events: [{ candidates: [{ edge_ip: null, attempted: true, outcome: 'failed' }] }]
    });

    const unrecognized = remote(true, 'https://edge.example.test/rci/').seal();
    expect(unrecognized).toMatchObject({ edge_ip_retention: 'suppressed_unrecognized_endpoint' });
  });

  it('uses null measurements for LAN and holds a bounded shared-auth lease after the handler', async () => {
    const lan = new RciTransportCollector({
      connection: { mode: 'lan', endpoint: 'http://router.invalid/rci/' }
    });
    expect(lan.seal()).toMatchObject({ applicability: 'not_applicable', normal_attempts: null });

    const collector = remote();
    const operation = collector.beginOperation()!;
    const release = operation.acquireLease();
    const delayed = collector.seal();
    expect(delayed).toBeInstanceOf(Promise);
    release();
    await expect(delayed).resolves.toMatchObject({ finalized_after_handler: true });
  });

  it('caps fallback events and candidates without allowing telemetry input to throw', () => {
    const collector = remote();
    const operation = collector.beginOperation()!;
    expect(() => operation.observedEdge({ hostile: true } as unknown as string)).not.toThrow();
    for (let index = 0; index < 9; index += 1) {
      const event = operation.beginFallback(30, 30, [
        { ip: '192.0.2.1', prior: 'healthy' },
        { ip: '192.0.2.2', prior: 'unknown' },
        { ip: '192.0.2.3', prior: 'failed' }
      ]);
      event.finish('exhausted');
    }
    const snapshot = collector.seal() as Exclude<ReturnType<RciTransportCollector['seal']>, Promise<unknown>>;
    expect(snapshot.fallback_events).toHaveLength(8);
    expect(snapshot).toMatchObject({ fallback_events_total: 9, fallback_events_truncated: true });
    expect(snapshot.fallback_events?.[0]?.candidates).toHaveLength(2);
    expect(Buffer.byteLength(JSON.stringify(snapshot), 'utf8')).toBeLessThan(16_384);
  });

  it('never stores endpoint, credentials, headers, payloads, responses, config, or error text', () => {
    const collector = remote(true, 'https://edge.keenetic.pro/rci/secret-url-marker');
    const operation = collector.beginOperation()!;
    operation.normalAttempt();
    operation.terminal('transport_failure');
    const serialized = JSON.stringify(collector.seal());
    for (const marker of [
      'secret-url-marker', 'secret-password-marker', 'secret-authorization-marker',
      'secret-cookie-marker', 'secret-payload-marker', 'secret-raw-response-marker',
      'secret-configuration-marker', 'secret-error-marker'
    ]) expect(serialized).not.toContain(marker);
  });
});
