import { chmod, link, lstat, mkdtemp, open, readFile, rm, symlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createQueuedTelemetryWriter,
  createTelemetryWriter,
  type TelemetryWriterOptions
} from '../../src/telemetry/writer.js';
import type { TelemetryRecord } from '../../src/telemetry/record.js';
import type { RciTransportSnapshot } from '../../src/telemetry/rci-transport.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(path => rm(path, { recursive: true, force: true })));
});

function record(index: number): TelemetryRecord {
  return {
    schema_version: 1,
    timestamp: '2026-09-12T00:00:00.000Z',
    finished_at: '2026-09-12T00:00:00.001Z',
    call_id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    router_profile: 'test',
    tool: 'get_system_info',
    tool_attributes: { read_only: true },
    duration_ms: 1,
    status: 'success',
    error_code: null,
    args_summary: { fields: {}, total_fields: 0, truncated: false },
    result_size_bytes: 20,
    output_truncated: false,
    server_version: '0.0.0-dev'
  };
}

function maximumTransport(): RciTransportSnapshot {
  const terminal_reasons = {
    normal_response: 99, fallback_recovered: 99, fallback_exhausted: 99,
    fallback_no_candidates: 99, fallback_replay_unsafe: 99,
    fallback_correlation_incomplete: 99, cancelled: 99, deadline_exceeded: 99,
    transport_failure: 99
  };
  return {
    applicability: 'remote', edge_ip_retention: 'enabled', remote_requests: 99,
    shared_auth_waits: 99, normal_attempts: 99, fallback_considered: 99,
    fallback_activations: 99, fallback_attempts: 99, fallback_recoveries: 99,
    fallback_exhaustions: 99, correlation_complete: true, finalized_after_handler: true,
    observed_edge_ips: Array.from({ length: 16 }, (_, index) => `8.8.8.${index + 1}`),
    selected_normal_edge_ips: Array.from({ length: 16 }, (_, index) => `2001:4860::${index + 1}`),
    edge_ips_truncated: true, terminal_reasons,
    fallback_events: Array.from({ length: 8 }, () => ({
      pool_size: 99, total_candidates: 99, outcome: 'exhausted' as const,
      candidates: [
        { edge_ip: '8.8.8.1', prior: 'healthy' as const, attempted: true, outcome: 'failed' as const },
        { edge_ip: '2001:4860::1', prior: 'failed' as const, attempted: true, outcome: 'failed' as const }
      ]
    })),
    fallback_events_total: 99, fallback_events_truncated: true
  };
}

describe('JSONL telemetry writer', () => {
  it('serializes concurrent writes into complete JSON lines', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const path = join(root, 'state', 'mcp-calls.jsonl');
    const writer = createTelemetryWriter(path);
    await Promise.all(Array.from({ length: 40 }, (_, index) => writer.write(record(index))));

    const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
    expect(lines).toHaveLength(40);
    const parsed = lines.map(line => JSON.parse(line) as TelemetryRecord);
    expect(new Set(parsed.map(item => item.call_id)).size).toBe(40);
  });

  it('writes a maximum-shape transport record below the 16 KiB ceiling', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const path = join(root, 'state', 'mcp-calls.jsonl');
    const maximum = record(1);
    maximum.args_summary = {
      fields: Object.fromEntries(Array.from({ length: 32 }, (_, index) => [
        `field_${index}`, { type: 'string' as const, length: 65_535 }
      ])), total_fields: 32, truncated: true
    };
    maximum.rci_transport = maximumTransport();
    await createTelemetryWriter(path).write(maximum);
    const line = (await readFile(path, 'utf8')).trimEnd();
    expect(Buffer.byteLength(`${line}\n`, 'utf8')).toBeLessThan(16_384);
    expect(JSON.parse(line)).toMatchObject({ rci_transport: { fallback_events: { length: 8 } } });
  });

  it('creates owner-only state and file modes on POSIX', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const parent = join(root, 'state');
    const path = join(parent, 'mcp-calls.jsonl');
    await createTelemetryWriter(path).write(record(1));
    if (process.platform !== 'win32') {
      expect((await lstat(parent)).mode & 0o777).toBe(0o700);
      expect((await lstat(path)).mode & 0o777).toBe(0o600);
    }
  });

  it('refuses a symbolic-link target', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const target = join(root, 'target.jsonl');
    const path = join(root, 'mcp-calls.jsonl');
    await symlink(target, path);
    await expect(createTelemetryWriter(path).write(record(1))).rejects.toThrow(/regular file/);
  });

  it('refuses a hard-linked target', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const path = join(root, 'mcp-calls.jsonl');
    const alias = join(root, 'alias.jsonl');
    const writer = createTelemetryWriter(path);
    await writer.write(record(1));
    await link(path, alias);
    await expect(writer.write(record(2))).rejects.toThrow(/hard links/);
  });

  it('bounds records retained behind a stalled append', async () => {
    const stalled = new Promise<void>(() => undefined);
    const writer = createQueuedTelemetryWriter(async () => stalled, 2);
    void writer.write(record(1));
    void writer.write(record(2));
    await expect(writer.write(record(3))).rejects.toThrow(/pending-record limit/);
  });

  it('rolls back a short append before writing the next record', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const path = join(root, 'mcp-calls.jsonl');
    let first = true;
    const openFile: NonNullable<TelemetryWriterOptions['openFile']> = async (
      target,
      flags,
      mode
    ) => {
      const handle = await open(target, flags, mode);
      if (!first) return handle;
      first = false;
      return {
        stat: handle.stat.bind(handle),
        chmod: handle.chmod.bind(handle),
        truncate: handle.truncate.bind(handle),
        close: handle.close.bind(handle),
        write: async (value: string) => handle.write(value.slice(0, 10), null, 'utf8')
      } as unknown as FileHandle;
    };
    const writer = createTelemetryWriter(path, { openFile });
    await expect(writer.write(record(1))).rejects.toThrow(/not written completely/);
    await writer.write(record(2));
    const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]!) as TelemetryRecord).call_id).toBe(record(2).call_id);
  });

  it('does not roll back another writer during a short append', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    const path = join(root, 'mcp-calls.jsonl');
    let partialReady!: () => void;
    let releasePartial!: () => void;
    const ready = new Promise<void>(resolve => { partialReady = resolve; });
    const release = new Promise<void>(resolve => { releasePartial = resolve; });
    let first = true;
    const openFile: NonNullable<TelemetryWriterOptions['openFile']> = async (
      target,
      flags,
      mode
    ) => {
      const handle = await open(target, flags, mode);
      if (!first) return handle;
      first = false;
      return {
        stat: handle.stat.bind(handle),
        chmod: handle.chmod.bind(handle),
        truncate: handle.truncate.bind(handle),
        close: handle.close.bind(handle),
        write: async (value: string) => {
          const result = await handle.write(value.slice(0, 10), null, 'utf8');
          partialReady();
          await release;
          return result;
        }
      } as unknown as FileHandle;
    };
    const firstWriter = createTelemetryWriter(path, { openFile });
    const secondWriter = createTelemetryWriter(path);
    const firstWrite = firstWriter.write(record(1));
    await ready;
    let secondSettled = false;
    const secondWrite = secondWriter.write(record(2)).then(() => { secondSettled = true; });
    await new Promise(resolve => setTimeout(resolve, 30));
    expect(secondSettled).toBe(false);
    releasePartial();
    await expect(firstWrite).rejects.toThrow(/not written completely/);
    await secondWrite;
    const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]!) as TelemetryRecord).call_id).toBe(record(2).call_id);
  });

  it('does not change an existing custom parent directory mode', async () => {
    const root = await mkdtemp(join(tmpdir(), 'keenetic-telemetry-'));
    roots.push(root);
    if (process.platform === 'win32') return;
    await chmod(root, 0o755);
    await createTelemetryWriter(join(root, 'mcp-calls.jsonl')).write(record(1));
    expect((await lstat(root)).mode & 0o777).toBe(0o755);
  });
});
