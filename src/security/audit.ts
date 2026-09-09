import { appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { redact } from './redact.js';

export interface AuditWriter { write(entry: Record<string, unknown>): Promise<void>; }
export function createAuditWriter(dir: string, routerId: string): AuditWriter {
  const path = join(dir, 'audit.jsonl');
  return { async write(entry) { await mkdir(dir, { recursive: true }); await appendFile(path,
    `${JSON.stringify(redact({ timestamp: new Date().toISOString(), routerId, ...entry }))}\n`, { encoding: 'utf8', mode: 0o600 }); } };
}
