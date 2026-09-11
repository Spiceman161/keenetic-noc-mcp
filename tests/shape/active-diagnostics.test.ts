import { describe, expect, it } from 'vitest';
import {
  activeDiagnosticReport,
  budgetActiveDiagnostic,
  sanitizeDiagnosticLines
} from '../../src/shape/active-diagnostics.js';

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
