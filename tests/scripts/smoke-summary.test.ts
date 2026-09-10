import { describe, expect, it } from 'vitest';
import { createLogSmokeSummary } from '../../scripts/smoke-summary.js';

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
