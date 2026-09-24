import { capText } from './budget.js';
import { redact, redactText } from '../security/redact.js';
import type { Iperf3Direction } from '../router/active-diagnostics.js';

export interface Iperf3Report {
  schemaVersion: 1;
  operation: 'iperf3';
  serverHost: string;
  serverPort: number;
  requestedDirection: Iperf3Direction;
  requestedSourceInterface?: string;
  limitsApplied: { byteLimitBytes: number; timeoutMs: number };
  status: 'unavailable' | 'completed' | 'timeout';
  termination: 'not-started' | 'completed' | 'timeout';
  reason?: 'component-not-installed';
  throughput: 'unknown';
  observedNativeMarkers: Array<'sender' | 'receiver' | 'iperf Done!'>;
  untrustedRouterData: true;
}

export function iperf3Report(input: {
  serverHost: string;
  serverPort: number;
  requestedDirection: Iperf3Direction;
  requestedSourceInterface?: string;
  byteLimitBytes: number;
  timeoutMs: number;
  termination?: 'completed' | 'timeout';
  messages?: readonly string[];
}): Iperf3Report {
  const messages = input.messages ?? [];
  const observedNativeMarkers: Iperf3Report['observedNativeMarkers'] = [];
  if (messages.some(line => /\bsender\s*$/i.test(line))) observedNativeMarkers.push('sender');
  if (messages.some(line => /\breceiver\s*$/i.test(line))) observedNativeMarkers.push('receiver');
  if (messages.some(line => /^\s*iperf Done!\s*$/i.test(line))) observedNativeMarkers.push('iperf Done!');
  return {
    schemaVersion: 1,
    operation: 'iperf3',
    serverHost: input.serverHost,
    serverPort: input.serverPort,
    requestedDirection: input.requestedDirection,
    ...(input.requestedSourceInterface === undefined ? {} : {
      requestedSourceInterface: input.requestedSourceInterface
    }),
    limitsApplied: { byteLimitBytes: input.byteLimitBytes, timeoutMs: input.timeoutMs },
    status: input.termination ?? 'unavailable',
    termination: input.termination ?? 'not-started',
    ...(input.termination === undefined ? { reason: 'component-not-installed' as const } : {}),
    throughput: 'unknown',
    observedNativeMarkers,
    untrustedRouterData: true
  };
}

export function budgetIperf3Report(report: Iperf3Report, maxBytes: number): object {
  if (Buffer.byteLength(JSON.stringify(redact(report)), 'utf8') <= maxBytes) return report;
  return {
    schemaVersion: report.schemaVersion,
    operation: report.operation,
    status: report.status,
    termination: report.termination,
    ...(report.reason === undefined ? {} : { reason: report.reason }),
    requestedDirection: report.requestedDirection,
    limitsApplied: report.limitsApplied,
    throughput: report.throughput,
    untrustedRouterData: true,
    truncated: true
  };
}

export interface ActiveDiagnosticReport {
  schemaVersion: 1;
  operation: 'ping' | 'traceroute';
  target: string;
  status: 'completed' | 'partial' | 'timeout' | 'unreachable' | 'not-found';
  limitsApplied: Record<string, number | string>;
  lines: string[];
  shown: number;
  total: number;
  truncated: boolean;
  untrustedRouterData: true;
}

const ANSI = /[\u001b\u009b][[\]()#;?]*(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]+)*)?\u0007|(?:(?:\d{1,4}(?:[;:]\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
const FORMAT = /\p{Cf}/gu;
const LINE_SEPARATOR = /[\u2028\u2029]/g;

export function sanitizeDiagnosticLines(lines: readonly string[]): string[] {
  return lines.map(line => capText(redactText(
    line.replace(ANSI, '').replace(CONTROL, ' ').replace(FORMAT, '').replace(LINE_SEPARATOR, ' ')
  ), 512))
    .filter(line => line.length > 0)
    .slice(0, 100);
}

function bytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(redact(value), null, 2), 'utf8');
}

export function budgetActiveDiagnostic(report: ActiveDiagnosticReport, maxBytes: number): ActiveDiagnosticReport {
  while (report.lines.length > 0 && bytes(report) > maxBytes) {
    report.lines = report.lines.slice(0, Math.floor(report.lines.length / 2));
    report.shown = report.lines.length;
    report.truncated = true;
  }
  if (bytes(report) > maxBytes) report.truncated = true;
  return report;
}

export function activeDiagnosticReport(input: {
  operation: 'ping' | 'traceroute';
  target: string;
  limitsApplied: Record<string, number | string>;
  messages: readonly string[];
  termination: 'completed' | 'timeout';
}): ActiveDiagnosticReport {
  const lines = sanitizeDiagnosticLines(input.messages);
  const joined = lines.join('\n');
  let status: ActiveDiagnosticReport['status'];
  if (/unknown host|name or service not known|unable to resolve|(?:resolve[^\n]*failed|failed[^\n]*resolve)|bad address/i.test(joined)) {
    status = 'not-found';
  } else if (/100(?:\.0+)?%\s+packet loss|destination .*unreachable|network is unreachable|!H(?:\s|$)/i.test(joined)) {
    status = 'unreachable';
  } else if (input.termination === 'timeout') {
    status = lines.length > 0 ? 'partial' : 'timeout';
  } else if (input.operation === 'traceroute' &&
      typeof input.limitsApplied['maxHops'] === 'number' &&
      lines.some(line => new RegExp(`^\\s*${input.limitsApplied['maxHops']}\\s`).test(line)) &&
      !lines.some(line => /^\s*\d+\s/.test(line) && line.includes(input.target))) {
    status = 'partial';
  } else if (/(?:[1-9]\d?(?:\.\d+)?%|\*)\s*(?:packet loss)?/i.test(joined)) {
    status = 'partial';
  } else {
    status = 'completed';
  }
  return {
    schemaVersion: 1,
    operation: input.operation,
    target: input.target,
    status,
    limitsApplied: input.limitsApplied,
    lines,
    shown: lines.length,
    total: input.messages.filter(line => line.length > 0).length,
    truncated: lines.length < input.messages.filter(line => line.length > 0).length ||
      lines.some(line => line.endsWith('\n\n[truncated]')),
    untrustedRouterData: true
  };
}
