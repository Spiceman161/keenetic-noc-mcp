import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createAuditWriter } from '../../src/security/audit.js';

describe('JSONL audit', () => {
  it('records an attempt and redacts secrets', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-audit-'));
    await createAuditWriter(dir, 'lab').write({ tool: 'test', success: false, password: 'never-write-this', nested: { psk: 'also-secret' } });
    const line = await readFile(join(dir, 'audit.jsonl'), 'utf8');
    expect(JSON.parse(line)).toMatchObject({ routerId: 'lab', tool: 'test', success: false, password: '[REDACTED]' });
    expect(line).not.toContain('never-write-this'); expect(line).not.toContain('also-secret');
  });
});
