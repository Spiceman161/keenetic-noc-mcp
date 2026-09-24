import { describe, expect, it } from 'vitest';
import {
  activeDiagnosticReport,
  budgetActiveDiagnostic,
  budgetIperf3Report,
  iperf3Report,
  sanitizeDiagnosticLines
} from '../../src/shape/active-diagnostics.js';

describe('iPerf3 Stage A projection', () => {
  const input = { serverHost: 'example.test', serverPort: 5201, requestedDirection: 'reverse' as const,
    byteLimitBytes: 1_048_576, timeoutMs: 4_000, requestedSourceInterface: 'Wireguard0' };

  it('exposes no native free-form content, local IP, false speed or confirmed reverse claim', () => {
    const privateAddress = ['192', '168', '1', '2'].join('.');
    const peerAddress = ['10', '0', '0', '1'].join('.');
    const messages = [`[  5]  ${privateAddress}:456 to ${peerAddress}:5201 password=secret`,
      'one sender', 'one receiver', 'iperf Done!', '\u001b[31m hostile owner: admin'];
    const report = iperf3Report({ ...input, messages, termination: 'completed' });
    expect(report).toMatchObject({ status: 'completed', termination: 'completed',
      requestedDirection: 'reverse', throughput: 'unknown',
      observedNativeMarkers: ['sender', 'receiver', 'iperf Done!'] });
    const output = JSON.stringify(report);
    for (const secret of [privateAddress, peerAddress, 'secret', 'admin', 'Mbps', 'download']) {
      expect(output).not.toContain(secret);
    }
    expect(Buffer.byteLength(output)).toBeLessThan(1_000);
  });

  it('keeps absent-component and deadline outcomes separate from transfer success', () => {
    expect(iperf3Report(input)).toMatchObject({ status: 'unavailable',
      reason: 'component-not-installed', termination: 'not-started', throughput: 'unknown' });
    expect(iperf3Report({ ...input, termination: 'timeout', messages: ['sender'] }))
      .toMatchObject({ status: 'timeout', termination: 'timeout', throughput: 'unknown' });
  });

  it('keeps the typed absence envelope under the smallest configured output cap', () => {
    const longHost = [
      'abcde-'.repeat(10) + 'abc', 'fghij-'.repeat(10) + 'fgh',
      'klmno-'.repeat(10) + 'klm', 'pqrst-'.repeat(10) + 'p'
    ].join('.');
    const report = iperf3Report({ ...input, serverHost: longHost,
      requestedSourceInterface: 'W-'.repeat(63) + 'W0' });
    const bounded = budgetIperf3Report(report, 512);
    expect(bounded).toMatchObject({ operation: 'iperf3', schemaVersion: 1,
      status: 'unavailable', reason: 'component-not-installed',
      requestedDirection: 'reverse', limitsApplied: { byteLimitBytes: 1_048_576 },
      truncated: true });
    expect(JSON.stringify(bounded)).not.toContain(longHost);
    expect(Buffer.byteLength(JSON.stringify(bounded))).toBeLessThanOrEqual(512);
  });
});

describe('active diagnostic projection', () => {
  it('removes terminal controls and redacts secret-like text', () => {
    expect(sanitizeDiagnosticLines([
      '\u001b[31mhop\u001b[0m\u0007 password=hunter2',
      'prefix\npassword=hunter2',
      'safe\u202Etext',
      'visual\u2028break\u2029here',
      ''
    ])).toEqual(['hop password=[REDACTED]', 'prefix password=[REDACTED]', 'safetext',
      'visual break here']);
  });

  it('caps line count, individual lines, and serialized output', () => {
    const messages = Array.from({ length: 140 }, (_, index) => `${index} ${'x'.repeat(700)}`);
    const report = activeDiagnosticReport({ operation: 'traceroute', target: 'example.test',
      limitsApplied: { maxHops: 30 }, messages, termination: 'completed' });
    expect(report.lines).toHaveLength(100);
    expect(report.lines.every(line => Buffer.byteLength(line) <= 512)).toBe(true);
    const bounded = budgetActiveDiagnostic(report, 2_000);
    expect(bounded.truncated).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(bounded, null, 2))).toBeLessThanOrEqual(2_000);
  });

  it('reports truncation when one router line exceeds its byte ceiling', () => {
    const report = activeDiagnosticReport({ operation: 'ping', target: 'example.test',
      limitsApplied: {}, messages: ['word '.repeat(140)], termination: 'completed' });
    expect(report.lines[0]).toContain('[truncated]');
    expect(report.truncated).toBe(true);
  });

  it('keeps sourced output bounded and does not infer reachability from a completed job', () => {
    const sourceInterface = 'W-'.repeat(63) + 'W0';
    const limitsApplied = { family: 'ipv4', count: 2, timeoutMs: 4_000, sourceInterface };
    const messages = Array.from({ length: 130 }, () => 'hop '.repeat(150));
    const report = activeDiagnosticReport({ operation: 'ping', target: '192.0.2.1',
      limitsApplied, messages, termination: 'completed' });
    expect(report.status).toBe('completed');
    const bounded = budgetActiveDiagnostic(report, 2_000);
    expect(bounded.limitsApplied.sourceInterface).toBe(sourceInterface);
    expect(bounded.truncated).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(bounded, null, 2))).toBeLessThanOrEqual(2_000);
    expect(activeDiagnosticReport({ operation: 'ping', target: '192.0.2.1',
      limitsApplied, messages: ['0 packets transmitted, 100% packet loss'],
      termination: 'completed' })).toMatchObject({ status: 'unreachable',
      limitsApplied: { sourceInterface } });
  });

  it('classifies finite diagnostic outcomes and preserves timeout evidence', () => {
    expect(activeDiagnosticReport({ operation: 'ping', target: 'missing.example.test',
      limitsApplied: {}, messages: ['unknown host'], termination: 'completed' }).status).toBe('not-found');
    expect(activeDiagnosticReport({ operation: 'ping', target: 'missing.example.test',
      limitsApplied: {}, messages: ['failed to resolve missing.example.test'],
      termination: 'completed' }).status).toBe('not-found');
    expect(activeDiagnosticReport({ operation: 'ping', target: 'example.test',
      limitsApplied: {}, messages: ['resolve started', 'one probe failed'],
      termination: 'completed' }).status).toBe('completed');
    expect(activeDiagnosticReport({ operation: 'ping', target: 'example.test',
      limitsApplied: {}, messages: ['5 packets transmitted, 0 received, 100% packet loss'],
      termination: 'completed' }).status).toBe('unreachable');
    expect(activeDiagnosticReport({ operation: 'ping', target: 'example.test',
      limitsApplied: {}, messages: ['5 packets transmitted, 4 received, 20% packet loss'],
      termination: 'completed' }).status).toBe('partial');
    expect(activeDiagnosticReport({ operation: 'traceroute', target: 'example.test',
      limitsApplied: {}, messages: ['1  192.0.2.1'], termination: 'timeout' })).toMatchObject({
      status: 'partial', lines: ['1  192.0.2.1']
    });
    expect(activeDiagnosticReport({ operation: 'traceroute', target: 'example.test',
      limitsApplied: {}, messages: [], termination: 'timeout' }).status).toBe('timeout');
    expect(activeDiagnosticReport({ operation: 'traceroute', target: '203.0.113.8',
      limitsApplied: { maxHops: 1 }, messages: ['1  192.0.2.1'],
      termination: 'completed' }).status).toBe('partial');
    expect(activeDiagnosticReport({ operation: 'traceroute', target: '203.0.113.8',
      limitsApplied: { maxHops: 1 },
      messages: ['traceroute to 203.0.113.8', '1  192.0.2.1'],
      termination: 'completed' }).status).toBe('partial');
    expect(activeDiagnosticReport({ operation: 'traceroute', target: '203.0.113.8',
      limitsApplied: { maxHops: 1 }, messages: ['1  203.0.113.8'],
      termination: 'completed' }).status).toBe('completed');
  });
});
