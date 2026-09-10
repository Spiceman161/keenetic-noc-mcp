import { describe, expect, it } from 'vitest';
import { redactConfigLines } from '../../src/security/redact.js';
import {
  boundedConfigDiffEnvelope,
  diffConfigLines
} from '../../src/shape/config-diff.js';

function diff(startup: string[], running: string[], maxCells?: number) {
  return diffConfigLines(startup, running, redactConfigLines,
    maxCells === undefined ? {} : { maxCells });
}

describe('configuration diff', () => {
  it('reports identical configuration as saved', () => {
    expect(diff(['system', '    hostname router'], ['system', '    hostname router']))
      .toMatchObject({ comparable: true, unsavedChanges: false, changedSections: [],
        added: 0, removed: 0, redactedChanges: 0, operations: [] });
  });

  it('ignores only the measured generated checksum header', () => {
    const first = '! $$$ Md5 checksum: a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const second = '! $$$ Md5 checksum: 0f9e8d7c6b5a49382716f5e4d3c2b1a0';
    expect(diff([first, '! operator comment', 'system'], [second, '! operator comment', 'system']))
      .toMatchObject({ comparable: true, unsavedChanges: false });
    expect(diff([first, '! old comment', 'system'], [second, '! new comment', 'system']))
      .toMatchObject({ comparable: true, unsavedChanges: true, changedSections: ['other'],
        added: 1, removed: 1 });
    expect(diff(['! $ Md5 checksum: a1b2c3d4e5f60718293a4b5c6d7e8f90'],
      ['! $$$$ Md5 checksum: a1b2c3d4e5f60718293a4b5c6d7e8f90']))
      .toMatchObject({ comparable: true, unsavedChanges: true, added: 1, removed: 1 });
  });

  it('retains ordering and deterministic removal-before-addition ties', () => {
    const result = diff(['system', '    first', '    second'],
      ['system', '    second', '    first']);
    expect(result.comparable).toBe(true);
    if (!result.comparable) return;
    expect(result.operations.map(operation => [operation.kind, operation.text])).toEqual([
      ['removed', '    first'],
      ['added', '    first']
    ]);
  });

  it('attributes nested changes to specific block categories', () => {
    const startup = [
      'dns-proxy', '    cache-size 128',
      'interface WifiMaster0/AccessPoint0', '    ssid old',
      'interface Wireguard1', '    wireguard peer old'
    ];
    const running = [
      'dns-proxy', '    cache-size 256',
      'interface WifiMaster0/AccessPoint0', '    ssid new',
      'interface Wireguard1', '    wireguard peer new'
    ];
    expect(diff(startup, running)).toMatchObject({
      comparable: true,
      changedSections: ['dns', 'wifi', 'vpn'],
      added: 3,
      removed: 3
    });
  });

  it('detects secret-only changes but exposes only redacted text', () => {
    const result = diff(['user agent', '    password first-secret'],
      ['user agent', '    password second-secret']);
    expect(result.comparable).toBe(true);
    if (!result.comparable) return;
    expect(result).toMatchObject({ unsavedChanges: true, redactedChanges: 1,
      added: 1, removed: 1 });
    expect(JSON.stringify(result)).not.toMatch(/first-secret|second-secret/);
    expect(result.operations.map(operation => operation.text)).toEqual([
      '    password [REDACTED]', '    password [REDACTED]'
    ]);
  });

  it('does not expose changed Tweaked multiline private key material', () => {
    const startup = ['interface Wireguard1', '    -----BEGIN PRIVATE KEY-----',
      '    old-private-material', '    -----END PRIVATE KEY-----'];
    const running = ['interface Wireguard1', '    -----BEGIN PRIVATE KEY-----',
      '    new-private-material', '    -----END PRIVATE KEY-----'];
    const result = diff(startup, running);
    expect(result.comparable).toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/old-private|new-private/);
    if (result.comparable) expect(result.redactedChanges).toBe(1);
  });

  it('stops before allocating an excessive LCS matrix', () => {
    const startup = Array.from({ length: 100 }, (_, index) => `old ${index}`);
    const running = Array.from({ length: 100 }, (_, index) => `new ${index}`);
    expect(diff(startup, running, 5_000)).toEqual({
      comparable: false,
      reason: 'comparison-limit-exceeded',
      requiredCells: 10_201,
      maxCells: 5_000,
      inputLines: 100,
      maxLines: 10_000
    });
  });

  it('rejects newline-heavy inputs before invoking redaction', () => {
    const redact = () => { throw new Error('redaction should not run'); };
    expect(diffConfigLines(Array(101).fill(''), Array(101).fill(''), redact,
      { maxLines: 100 })).toMatchObject({ comparable: false,
      reason: 'comparison-limit-exceeded', requiredCells: null, inputLines: 101,
      maxLines: 100 });
  });

  it('counts adjacent secret replacements independently', () => {
    const result = diff(['user agent', '    password first', '    token second'],
      ['user agent', '    password third', '    token fourth']);
    expect(result).toMatchObject({ comparable: true, redactedChanges: 2,
      added: 2, removed: 2 });
  });

  it('does not count a literal redaction marker as a hidden change', () => {
    expect(diff(['system', '    description [REDACTED] old'],
      ['system', '    description [REDACTED] new']))
      .toMatchObject({ comparable: true, redactedChanges: 0 });
  });

  it('bounds whole diff lines and keeps visible counts accurate', () => {
    const result = diff(['system', ...Array.from({ length: 20 }, (_, i) => `    old ${i}`)],
      ['system', ...Array.from({ length: 20 }, (_, i) => `    new ${i}`)]);
    expect(result.comparable).toBe(true);
    if (!result.comparable) return;
    const envelope = boundedConfigDiffEnvelope({ comparable: true, added: result.added,
      removed: result.removed }, result.operations, 30, 500);
    expect(Buffer.byteLength(JSON.stringify(envelope, null, 2), 'utf8')).toBeLessThanOrEqual(500);
    expect((envelope['shownAdded'] as number) + (envelope['shownRemoved'] as number))
      .toBe(envelope['shown']);
    expect(envelope).toMatchObject({ total: 40, truncated: true });
  });

  it('keeps a complete diff when it fits without a truncation note', () => {
    const operations = [
      { kind: 'added', text: '', section: 'other', redacted: false, group: 1 },
      { kind: 'added', text: '', section: 'other', redacted: false, group: 1 }
    ] as const;
    const unbounded = boundedConfigDiffEnvelope({ comparable: true, added: 2, removed: 0 },
      operations, 2, 10_000);
    const exactBytes = Buffer.byteLength(JSON.stringify(unbounded, null, 2), 'utf8');
    expect(boundedConfigDiffEnvelope({ comparable: true, added: 2, removed: 0 },
      operations, 2, exactBytes)).toMatchObject({ shown: 2, total: 2, truncated: false });
  });
});
