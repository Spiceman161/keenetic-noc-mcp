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
  const uploadSender = '[  5]   0.00-2.00   sec  1.25 MBytes  5.24 Mbits/sec    1            sender';
  const uploadReceiver = '[  5]   0.00-2.82   sec   896 KBytes  2.60 Mbits/sec                  receiver';
  const reverseSender = '[  5]   0.00-2.20   sec  2.50 MBytes  9.52 Mbits/sec   79            sender';
  const reverseReceiver = '[  5]   0.00-2.00   sec  1.25 MBytes  5.24 Mbits/sec                  receiver';
  const bytesSender = '[  5]   0.00-2.00   sec  1.00 MBytes  4.19 Mbits/sec    1            sender';
  const bytesReceiver = '[  5]   0.00-2.20   sec  1.00 MBytes  3.81 Mbits/sec                  receiver';

  it('projects only observed final upload role rows, not interval rows', () => {
    const report = iperf3Report({ ...input, requestedDirection: 'upload', termination: 'completed',
      polls: 2, terminalShape: 'empty-object', messages: [
        '[  5]   0.00-1.00   sec   512 KBytes  4.19 Mbits/sec    1    113 KBytes',
        uploadSender, uploadReceiver, 'iperf Done.'
      ] });
    expect(report).toMatchObject({ status: 'completed', requestedDirection: 'upload',
      actualDirection: 'unknown', throughput: 'unknown', polls: 2,
      terminalShape: 'empty-object', nativeRoleObservations: [
        { role: 'sender', intervalStartSeconds: 0, intervalEndSeconds: 2,
          transferAmount: 1.25, transferUnit: 'MBytes', bitrateMbps: 5.24 },
        { role: 'receiver', intervalStartSeconds: 0, intervalEndSeconds: 2.82,
          transferAmount: 896, transferUnit: 'KBytes', bitrateMbps: 2.60 }
      ] });
    expect(JSON.stringify(report)).not.toContain('113 KBytes');
    const bounded = budgetIperf3Report(report, 512);
    expect(bounded).toMatchObject({ status: 'completed', throughput: 'unknown',
      actualDirection: 'unknown', truncated: true });
    expect(bounded).not.toHaveProperty('nativeRoleObservations');
    expect(Buffer.byteLength(JSON.stringify(bounded))).toBeLessThanOrEqual(512);
  });

  it('reports reverse only with the exact native marker and keeps roles separate', () => {
    const messages = ['Reverse mode, remote host example.test is sending', reverseSender,
      reverseReceiver, 'iperf Done.'];
    const report = iperf3Report({ ...input, messages, termination: 'completed' });
    expect(report.actualDirection).toBe('reverse');
    expect(report.throughput).toBe('unknown');
    expect(report.nativeRoleObservations).toEqual([
      { role: 'sender', intervalStartSeconds: 0, intervalEndSeconds: 2.2,
        transferAmount: 2.5, transferUnit: 'MBytes', bitrateMbps: 9.52 },
      { role: 'receiver', intervalStartSeconds: 0, intervalEndSeconds: 2,
        transferAmount: 1.25, transferUnit: 'MBytes', bitrateMbps: 5.24 }
    ]);
    expect(iperf3Report({ ...input, messages: messages.slice(1), termination: 'completed' })
      .actualDirection).toBe('unknown');
    expect(iperf3Report({ ...input, messages: ['Reverse mode, remote host other.test is sending',
      reverseSender], termination: 'completed' }).actualDirection).toBe('unknown');
    expect(iperf3Report({ ...input, requestedDirection: 'upload', messages,
      termination: 'completed' }).actualDirection).toBe('unknown');
  });

  it('projects the observed byte-bounded summary without inferring a singular Mbps', () => {
    const report = iperf3Report({ ...input, requestedDirection: 'upload', termination: 'completed',
      messages: [bytesSender, bytesReceiver] });
    expect(report.nativeRoleObservations).toMatchObject([
      { role: 'sender', transferAmount: 1, transferUnit: 'MBytes', bitrateMbps: 4.19 },
      { role: 'receiver', transferAmount: 1, transferUnit: 'MBytes', bitrateMbps: 3.81 }
    ]);
    expect(report.throughput).toBe('unknown');
  });

  it('drops unmatched lines, unobserved units, and ambiguous duplicate roles', () => {
    const privateAddress = ['192', '168', '1', '3'].join('.');
    const malformedSender = uploadSender.replace('Mbits/sec', 'Gbits/sec');
    const wrongUnit = uploadReceiver.replace('KBytes', 'Bytes');
    const report = iperf3Report({ ...input, termination: 'completed', messages: [
      `[  5] local ${privateAddress} port 55555 connected to example.test port 5201`,
      malformedSender, wrongUnit, `${uploadSender} secret=opaque`, uploadReceiver,
      uploadReceiver.replace('896 KBytes', '768 KBytes')
    ] });
    expect(report.nativeRoleObservations).toEqual([]);
    expect(report.actualDirection).toBe('unknown');
    expect(JSON.stringify(report)).not.toMatch(/192\.168|opaque|Gbits|768 KBytes/);
  });

  it('exposes no native free-form content, local IP, false speed or confirmed reverse claim', () => {
    const privateAddress = ['192', '168', '1', '2'].join('.');
    const peerAddress = ['10', '0', '0', '1'].join('.');
    const messages = [`[  5]  ${privateAddress}:456 to ${peerAddress}:5201 password=secret`,
      'one sender', 'one receiver', 'iperf Done!', '\u001b[31m hostile owner: admin'];
    const report = iperf3Report({ ...input, messages, termination: 'completed' });
    expect(report).toMatchObject({ status: 'completed', termination: 'completed',
      requestedDirection: 'reverse', throughput: 'unknown', actualDirection: 'unknown',
      nativeTransfer: 'unknown', nativeInterval: 'unknown', polls: null, terminalShape: 'unknown',
      observedNativeMarkers: ['iperf Done!'], nativeRoleObservations: [] });
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

  it('preserves only bounded poll and terminal facts from continued chunks', () => {
    const report = iperf3Report({ ...input, termination: 'completed', polls: 2,
      terminalShape: 'empty-object', messages: [
        `sender 1.62 MBytes 0.00-2.00 sec 6.81 Mbits/sec ${['192', '168', '1', '3'].join('.')}`,
        'receiver 1.25 MBytes 0.00-2.17 sec 4.84 Mbits/sec',
        'iperf Done!'
      ] });
    expect(report).toMatchObject({ polls: 2, terminalShape: 'empty-object',
      nativeTransfer: 'unknown', nativeInterval: 'unknown', actualDirection: 'unknown',
      throughput: 'unknown' });
    expect(JSON.stringify(report)).not.toMatch(/192\.168|MBytes|Mbits|6\.81|4\.84/);
    expect(budgetIperf3Report(report, 400)).toMatchObject({ status: 'completed',
      polls: 2, terminalShape: 'empty-object', nativeTransfer: 'unknown', truncated: true });
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
