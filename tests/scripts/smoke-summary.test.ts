import { describe, expect, it } from 'vitest';
import { createConfigSmokeSummary, createDnsShapeSummary, createLogSmokeSummary } from '../../scripts/smoke-summary.js';

describe('remote smoke summary', () => {
  it('retains only anonymous shapes and counts', () => {
    const privateLine = '192.0.2.5 private-device joined SecretInterface';
    const summary = createLogSmokeSummary([{
      timestamp: '2026-09-09T01:02:03Z', ident: 'Network', level: 'info',
      label: 'SecretInterface', line: privateLine
    }], {
      interface: { available: true, matched: 1 },
      timeRange: { available: true, matched: 1 },
      deviceAlias: { available: true, matched: 1 }
    });
    const text = JSON.stringify(summary);
    expect(summary).toMatchObject({ total: 1, timestampShape: { status: 'passed' } });
    expect(text).not.toContain(privateLine);
    expect(text).not.toContain('192.0.2.5');
    expect(text).not.toContain('SecretInterface');
  });

  it('marks filters skipped when no safe candidate exists', () => {
    const summary = createLogSmokeSummary([], {
      interface: { available: false, matched: null },
      timeRange: { available: false, matched: null },
      deviceAlias: { available: false, matched: null }
    });
    expect(summary).toMatchObject({
      timestampShape: { status: 'skipped' }, interfaceFilter: { status: 'skipped' }
    });
  });
});

describe('configuration smoke summary', () => {
  it('reports independent capabilities and whitelists metadata fields', () => {
    const privateLine = 'private configuration must not escape';
    const capabilities = {
      runningConfig: {
        available: true, transport: 'rci', httpStatus: 200, contentTypeClass: 'json',
        shape: 'object', items: 1, bytes: 345, payloadShape: 'array', payloadItems: 12,
        payloadItemShape: 'string', wrapperDepth: 2, reason: null,
        privateLine
      },
      startupConfig: {
        available: false, transport: 'rci', httpStatus: 403, contentTypeClass: 'unknown',
        shape: 'unknown', items: null, bytes: null, payloadShape: 'unknown', payloadItems: null,
        payloadItemShape: 'unknown', wrapperDepth: 0, reason: 'capability-denied',
        privateLine
      }
    } as const;
    const summary = createConfigSmokeSummary(capabilities);

    expect(summary).toMatchObject({
      runningConfig: {
        available: true, shape: 'object', payloadShape: 'array', payloadItems: 12,
        payloadItemShape: 'string', wrapperDepth: 2
      },
      startupConfig: { available: false, httpStatus: 403, reason: 'capability-denied' }
    });
    expect(JSON.stringify(summary)).not.toContain(privateLine);
  });
});

describe('DNS smoke summary', () => {
  it('retains allowlisted field shapes but no values or dynamic keys', () => {
    const summary = createDnsShapeSummary({ 'proxy-status': { server: {
      'resolver.example.private': { address: '192.0.2.53', sni: 'secret.example.private', status: 'up' }
    } } });
    const text = JSON.stringify(summary);
    expect(text).toContain('proxy-status.server.<dynamic>.address');
    expect(text).not.toContain('resolver.example.private');
    expect(text).not.toContain('secret.example.private');
    expect(text).not.toContain('192.0.2.53');
  });

  it('reports sampling and field-count truncation honestly', () => {
    const rows = [{ status: 'up' }, { status: 'up' }, { status: 'up' }, { protocol: 'DoT' }];
    expect(createDnsShapeSummary({ server: rows }).truncated).toBe(true);
    const many = Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`private-${index}`, { status: 'up' }]));
    expect(createDnsShapeSummary(many).truncated).toBe(true);
  });

  it('normalizes numeric object keys instead of retaining identifiers', () => {
    const summary = createDnsShapeSummary({ '1234567890123456': { status: 'up' } });
    const text = JSON.stringify(summary);
    expect(text).toContain('<index>.status');
    expect(text).not.toContain('1234567890123456');
  });

  it('aggregates heterogeneous normalized siblings and only retains safe enums', () => {
    const summary = createDnsShapeSummary({ server: {
      first: { status: 'up', protocol: 'DoT' },
      second: { status: { nested: true }, protocol: 'private-profile-name' }
    } });
    const fields = summary.fields as Array<{ path: string; shape: string; values?: string[] }>;
    expect(fields.find(field => field.path.endsWith('<dynamic>.status'))).toMatchObject({ shape: 'mixed', values: ['up'] });
    expect(fields.find(field => field.path.endsWith('<dynamic>.protocol'))?.values).toEqual(['dot']);
    expect(JSON.stringify(summary)).not.toContain('private-profile-name');
  });
});
