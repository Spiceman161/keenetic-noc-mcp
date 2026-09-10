import { chmod, mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
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

  it('repairs permissive modes on an existing audit directory and file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-audit-'));
    const dir = join(root, 'state');
    await mkdir(dir, { mode: 0o755 });
    const path = join(dir, 'audit.jsonl');
    await writeFile(path, '', { mode: 0o644 });
    await chmod(dir, 0o755);
    await chmod(path, 0o644);
    await createAuditWriter(dir, 'lab').write({ tool: 'test' });
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });
});
