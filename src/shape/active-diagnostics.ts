import { capText } from './budget.js';
import { redact, redactText } from '../security/redact.js';

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
