import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open } from 'node:fs/promises';
import { join } from 'node:path';
import { redact } from './redact.js';

export interface AuditWriter { write(entry: Record<string, unknown>): Promise<void>; }

/** Outcome logging must never turn an already-applied router change into a retryable error. */
export async function writeAuditOutcome(
  writer: AuditWriter | undefined,
  entry: Record<string, unknown>
): Promise<boolean> {
  if (writer === undefined) return false;
  try {
    await writer.write(entry);
    return true;
  } catch {
    return false;
  }
}

const MAX_AUDIT_RECORD_BYTES = 64_000;

export function createAuditWriter(dir: string, routerId: string): AuditWriter {
  const path = join(dir, 'audit.jsonl');
  return { async write(entry) {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const directory = await lstat(dir);
    if (!directory.isDirectory() || directory.isSymbolicLink()) {
      throw new Error('Audit directory must be a real directory.');
    }
    if (process.geteuid !== undefined && directory.uid !== process.geteuid()) {
      throw new Error('Audit directory must be owned by the current user.');
    }
    await chmod(dir, 0o700);
    const line = `${JSON.stringify(redact({
      timestamp: new Date().toISOString(), routerId, ...entry
    }))}\n`;
    const bytes = Buffer.byteLength(line, 'utf8');
    if (bytes > MAX_AUDIT_RECORD_BYTES) throw new Error('Audit record exceeds its safety limit.');
    if (constants.O_NOFOLLOW === undefined || constants.O_NOFOLLOW === 0) {
      throw new Error('Audit is unavailable: this platform cannot safely refuse symbolic links.');
    }

    // Open the final target without following links, then validate the opened
    // descriptor. Path-only checks leave a race between inspection and append.
    const flags = constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY |
      constants.O_NOFOLLOW;
    const handle = await open(path, flags, 0o600);
    try {
      const info = await handle.stat();
      if (!info.isFile()) throw new Error('Audit target must be a regular file.');
      if (info.nlink !== 1) throw new Error('Audit target must not have hard links.');
      if (process.geteuid !== undefined && info.uid !== process.geteuid()) {
        throw new Error('Audit target must be owned by the current user.');
      }
      await handle.chmod(0o600);
      const written = await handle.write(line, null, 'utf8');
      if (written.bytesWritten !== bytes) throw new Error('Audit record was not written completely.');
    } finally {
      await handle.close();
    }
  } };
}
