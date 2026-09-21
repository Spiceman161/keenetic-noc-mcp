import { describe, expect, it } from 'vitest';
import {
  RciTransportCollector,
  currentRciTransportCollector,
  runWithRciTransportCollector,
  type TerminalReason
} from '../../src/telemetry/rci-transport.js';

function remote(endpoint = 'https://edge.keenetic.pro/rci/'): RciTransportCollector {
  return new RciTransportCollector({
    connection: { mode: 'remote', endpoint }
  });
}

describe('RCI transport telemetry collector', () => {
  it('captures only bounded canonical, first-seen remote attempt evidence', () => {
    const collector = remote();
    runWithRciTransportCollector(collector, () => {
      const operation = currentRciTransportCollector()?.beginOperation();
      operation?.normalAttempt();
      operation?.observedEdge('8.8.8.1');
      operation?.observedEdge('8.8.8.1');
      operation?.selectedNormalEdge('2001:4860:0:0:0:0:0:8888');
      for (let index = 2; index <= 17; index += 1) operation?.observedEdge(`8.8.8.${index}`);
      operation?.correlationComplete(true);
      operation?.terminal('normal_response');
    });

    const snapshot = collector.seal();
    expect(snapshot).not.toBeInstanceOf(Promise);
    expect(snapshot).toMatchObject({
      applicability: 'remote',
      normal_attempts: 1,
      correlation_complete: true,
      edge_ips_truncated: true,
      selected_normal_edge_ips: ['2001:4860::8888'],
      terminal_reasons: { normal_response: 1 }
    });
    expect((snapshot as Exclude<typeof snapshot, Promise<unknown>>).observed_edge_ips).toHaveLength(16);
  });

  it('retains canonical special and private IP literals without endpoint gating', () => {
    const collector = remote('http://user:secret@edge.example.test/not-rci');
    const operation = collector.beginOperation()!;
    operation.normalAttempt();
    operation.observedEdge('10.0.0.1');
    operation.observedEdge('::1');
    operation.selectedNormalEdge('192.168.1.1');
    const event = operation.beginFallback(4, 3, [{ ip: 'fe80::1', prior: 'healthy' }]);
    event.attempted(0);
    event.outcome(0, 'failed');
    event.finish('exhausted');
    operation.terminal('fallback_exhausted');
    const snapshot = collector.seal() as Exclude<ReturnType<RciTransportCollector['seal']>, Promise<unknown>>;
    expect(snapshot).toMatchObject({
      normal_attempts: 1,
      fallback_attempts: 1,
      fallback_exhaustions: 1,
      observed_edge_ips: ['10.0.0.1', '::1'],
      selected_normal_edge_ips: ['192.168.1.1'],
      fallback_events: [{ candidates: [{ edge_ip: 'fe80::1', attempted: true, outcome: 'failed' }] }]
    });
  });

  it('retains canonical fallback candidate identity', () => {
    const collector = remote();
    const operation = collector.beginOperation()!;
    const event = operation.beginFallback(2, 2, [
      { ip: '8.8.8.1', prior: 'failed' }, { ip: '8.8.8.2', prior: 'unknown' }
    ]);
    event.attempted(0);
    event.outcome(0, 'failed');
    event.attempted(1);
    event.outcome(1, 'recovered');
    event.finish('recovered');
    const snapshot = collector.seal() as Exclude<ReturnType<RciTransportCollector['seal']>, Promise<unknown>>;
    expect(snapshot).toMatchObject({
      fallback_attempts: 2,
      fallback_events: [{ candidates: [
        { edge_ip: '8.8.8.1', attempted: true, outcome: 'failed' },
        { edge_ip: '8.8.8.2', attempted: true, outcome: 'recovered' }
      ] }]
    });
  });

  it('accounts for every non-recovery fallback terminal matrix without fabricating attempts', () => {
    const cases: Array<{ reason: TerminalReason }> = [
      { reason: 'fallback_replay_unsafe' }, { reason: 'fallback_correlation_incomplete' },
      { reason: 'cancelled' }, { reason: 'deadline_exceeded' }
    ];
    for (const { reason } of cases) {
      const collector = remote();
      const operation = collector.beginOperation()!;
      operation.normalAttempt();
      operation.terminal(reason);
      expect(collector.seal()).toMatchObject({ terminal_reasons: { [reason]: 1 } });
    }

    const noCandidates = remote();
    const noCandidateOperation = noCandidates.beginOperation()!;
    noCandidateOperation.normalAttempt();
    noCandidateOperation.fallbackConsidered();
    noCandidateOperation.beginFallback(0, 0, []).finish('no_candidates');
    noCandidateOperation.terminal('fallback_no_candidates');
    expect(noCandidates.seal()).toMatchObject({
      fallback_considered: 1, fallback_activations: 0, fallback_attempts: 0,
      terminal_reasons: { fallback_no_candidates: 1 }
    });

    const exhausted = remote();
    const exhaustionOperation = exhausted.beginOperation()!;
    exhaustionOperation.normalAttempt();
    const event = exhaustionOperation.beginFallback(2, 2, [
      { ip: '8.8.8.1', prior: 'unknown' }, { ip: '8.8.8.2', prior: 'failed' }
    ]);
    event.attempted(0);
    event.outcome(0, 'failed');
    event.attempted(1);
    event.outcome(1, 'failed');
    event.finish('exhausted');
    exhaustionOperation.terminal('fallback_exhausted');
    expect(exhausted.seal()).toMatchObject({
      fallback_activations: 1, fallback_attempts: 2, fallback_exhaustions: 1,
      terminal_reasons: { fallback_exhausted: 1 }
    });
  });

  it('uses null measurements for LAN and holds a bounded shared-auth lease after the handler', async () => {
    const lan = new RciTransportCollector({
      connection: { mode: 'lan', endpoint: 'http://router.invalid/rci/' }
    });
    expect(lan.seal()).toMatchObject({ applicability: 'not_applicable', normal_attempts: null });
    expect(new RciTransportCollector().seal()).toMatchObject({ applicability: 'unknown', normal_attempts: null });

    const noDispatch = remote();
    noDispatch.beginOperation()?.terminal('cancelled');
    expect(noDispatch.seal()).toMatchObject({ correlation_complete: null });

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
        { ip: '8.8.8.1', prior: 'healthy' },
        { ip: '8.8.8.2', prior: 'unknown' },
        { ip: '8.8.8.3', prior: 'failed' }
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
    const collector = remote('https://edge.keenetic.pro/rci/secret-url-marker');
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
