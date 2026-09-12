import { constants } from 'node:fs';
import { lstat, mkdir, open, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { TelemetryRecord } from './record.js';

export interface TelemetryWriter {
  write(record: TelemetryRecord): Promise<void>;
}

const MAX_RECORD_BYTES = 16_384;
const MAX_PENDING_RECORDS = 64;
const LOCK_ATTEMPTS = 100;
const LOCK_RETRY_MS = 10;

type OpenFile = (path: string, flags: number, mode: number) => Promise<FileHandle>;

export interface TelemetryWriterOptions {
  maxPendingRecords?: number;
  openFile?: OpenFile;
}

async function inspectTarget(path: string): Promise<void> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error('Telemetry target must be a regular file.');
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

async function acquireAppendLock(path: string): Promise<() => Promise<void>> {
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      const handle = await open(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0),
        0o600
      );
      return async () => {
        try {
          await handle.close();
        } finally {
          await unlink(path).catch(() => undefined);
        }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_MS));
    }
  }
  throw new Error('Telemetry append lock is busy.');
}

export function createQueuedTelemetryWriter(
  append: (record: TelemetryRecord) => Promise<void>,
  maxPendingRecords = MAX_PENDING_RECORDS
): TelemetryWriter {
  let queue = Promise.resolve();
  let pending = 0;

  return {
    write(record): Promise<void> {
      if (pending >= maxPendingRecords) {
        return Promise.reject(new Error('Telemetry pending-record limit reached.'));
      }
      pending += 1;
      const task = queue.then(() => append(record));
      queue = task.then(
        () => { pending -= 1; },
        () => { pending -= 1; }
      );
      return task;
    }
  };
}

export function createTelemetryWriter(
  path: string,
  options: TelemetryWriterOptions = {}
): TelemetryWriter {
  const openFile = options.openFile ?? open;

  async function append(record: TelemetryRecord): Promise<void> {
    const parent = dirname(path);
    await mkdir(parent, { recursive: true, mode: 0o700 });
    const release = await acquireAppendLock(`${path}.lock`);
    try {
      await inspectTarget(path);

      const line = `${JSON.stringify(record)}\n`;
      const size = Buffer.byteLength(line, 'utf8');
      if (size > MAX_RECORD_BYTES) throw new Error('Telemetry record exceeds its safety limit.');

      const flags = constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY |
        (constants.O_NOFOLLOW ?? 0);
      const handle = await openFile(path, flags, 0o600);
      try {
        const info = await handle.stat();
        if (!info.isFile()) throw new Error('Telemetry target must be a regular file.');
        if (info.nlink !== 1) throw new Error('Telemetry target must not have hard links.');
        if (process.geteuid !== undefined && info.uid !== process.geteuid()) {
          throw new Error('Telemetry target must be owned by the current user.');
        }
        await handle.chmod(0o600);
        try {
          const written = await handle.write(line, null, 'utf8');
          if (written.bytesWritten !== size) {
            await handle.truncate(info.size);
            throw new Error('Telemetry record was not written completely.');
          }
        } catch (error) {
          const after = await handle.stat().catch(() => null);
          if (after !== null && after.size > info.size && after.size < info.size + size) {
            await handle.truncate(info.size).catch(() => undefined);
          }
          throw error;
        }
      } finally {
        await handle.close();
      }
    } finally {
      await release();
    }
  }

  return createQueuedTelemetryWriter(append, options.maxPendingRecords);
}
