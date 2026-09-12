import { chmod, link, lstat, mkdir, mkdtemp, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  canonicalSnapshot,
  createSnapshotStore,
  snapshotRouterComponent,
  type SnapshotStoreLimits
} from '../../src/router/snapshot-store.js';
import type { RouterSnapshotV1 } from '../../src/shape/router-snapshot.js';

const limits: SnapshotStoreLimits = { maxCount: 2, maxAgeMs: 1_000, maxTotalBytes: 32_000,
  maxFileBytes: 16_000, maxDirectoryEntries: 32 };

function snapshot(at: string): RouterSnapshotV1 {
  const unavailable = { status: 'unavailable' as const, reason: 'not-supported' as const, data: null };
  return { schemaVersion: 1, at, complete: false, sources: {
    system: unavailable, configuration: unavailable, interfaces: unavailable, routes: unavailable,
    dns: unavailable, vpn: unavailable, wifi: unavailable, devices: unavailable
  } };
}

describe('snapshot store', () => {
  it('uses collision-resistant confined router components', () => {
    expect(snapshotRouterComponent('home')).toBe('home');
    expect(snapshotRouterComponent('../../escape')).not.toContain('/');
    expect(snapshotRouterComponent('a/b')).not.toBe(snapshotRouterComponent('a?b'));
    expect(snapshotRouterComponent('home!')).not.toBe(snapshotRouterComponent(snapshotRouterComponent('home!')));
  });

  it('writes atomically with owner-only permissions and reads v1 records', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    await chmod(root, 0o755);
    const store = createSnapshotStore(root, 'home', limits);
    const result = await store.write(snapshot('2026-09-11T10:00:00.000Z'),
      new Date('2026-09-11T10:00:00.000Z'));
    expect(result.bytes).toBeGreaterThan(0);
    expect((await stat(root)).mode & 0o777).toBe(0o700);
    expect((await stat(result.path)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(result.path, 'utf8')).schemaVersion).toBe(1);
    expect((await store.list()).snapshots).toHaveLength(1);
  });

  it('strips unexpected properties before persistence', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const value = snapshot('2026-09-11T10:00:00.000Z') as RouterSnapshotV1 & {
      password: string; sources: RouterSnapshotV1['sources'] & { logs: string[] }
    };
    value.password = 'do-not-store';
    value.sources.logs = ['private log line'];
    const result = await createSnapshotStore(root, 'home', limits).write(value);
    const text = await readFile(result.path, 'utf8');
    expect(text).not.toMatch(/do-not-store|private log line|password|logs/);
  });

  it('canonicalizes nested data and rejects invalid enums and reasons', () => {
    const value = snapshot('2026-09-11T10:00:00.000Z') as unknown as Record<string, unknown>;
    (value['sources'] as Record<string, unknown>)['system'] = {
      status: 'available', reason: null,
      data: { firmware: '5.1.4', uptimeSeconds: 1, cpuLoad: 2, memoryFreeKb: 3,
        rawConfig: 'private' }
    };
    const canonical = canonicalSnapshot(value);
    expect(canonical?.sources.system.data).not.toHaveProperty('rawConfig');
    (value['sources'] as Record<string, unknown>)['system'] = {
      status: 'unavailable', reason: 'password=secret', data: null
    };
    expect(canonicalSnapshot(value)).toBeNull();
  });

  it('rejects contradictory configuration state', () => {
    const value = snapshot('2026-09-11T10:00:00.000Z') as unknown as Record<string, unknown>;
    (value['sources'] as Record<string, unknown>)['configuration'] = {
      status: 'available', reason: null, data: { runningChecksum: 'a'.repeat(32),
        savedChecksum: 'a'.repeat(32), unsavedChanges: true, savedState: 'available', savedReason: null }
    };
    expect(canonicalSnapshot(value)).toBeNull();
  });

  it('skips malformed v1 files and does not mutate storage during list', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    await mkdir(store.directory, { recursive: true, mode: 0o700 });
    await writeFile(join(store.directory, 'bad.json'), JSON.stringify({ schemaVersion: 1,
      at: '2026-09-11T10:00:00.000Z', complete: false, sources: Object.fromEntries(
        ['system', 'configuration', 'interfaces', 'routes', 'dns', 'vpn', 'wifi', 'devices']
          .map(key => [key, { status: 'available', reason: null, data: 'malformed' }])) }), { mode: 0o600 });
    expect(await store.list()).toEqual({ snapshots: [], skipped: 1 });
  });

  it('does not expose permissive pre-existing files through read-only list', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    await mkdir(store.directory, { recursive: true, mode: 0o700 });
    const path = join(store.directory, 'permissive.json');
    await writeFile(path, JSON.stringify(snapshot('2026-09-11T10:00:00.000Z')), { mode: 0o644 });
    expect(await store.list()).toEqual({ snapshots: [], skipped: 1 });
    expect((await stat(path)).mode & 0o777).toBe(0o644);
    await store.write(snapshot('2026-09-11T10:00:00.500Z'), new Date('2026-09-11T10:00:00.500Z'));
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it('rejects a write when the profile disappears while waiting for the store lock', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    await expect(store.write(snapshot('2026-09-11T10:00:00.000Z'), new Date(), async () => {
      throw new Error('profile removed');
    })).rejects.toThrow('profile removed');
    expect((await store.list()).snapshots).toHaveLength(0);
  });

  it('serializes first write with removal when the router directory starts absent', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    let release!: () => void;
    let entered!: () => void;
    const atGate = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const writing = store.write(snapshot('2026-09-11T10:00:00.000Z'), new Date(), async () => {
      entered();
      await gate;
    });
    await atGate;
    let finalized = false;
    const removing = store.removeAll(async () => { finalized = true; });
    release();
    await writing;
    await removing;
    expect(finalized).toBe(true);
    expect((await store.list()).snapshots).toHaveLength(0);
  });

  it('prunes by age and count while skipping corrupt and unknown schemas', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    await store.write(snapshot('2026-09-11T09:59:58.000Z'), new Date('2026-09-11T09:59:58.000Z'));
    await store.write(snapshot('2026-09-11T10:00:00.000Z'), new Date('2026-09-11T10:00:00.000Z'));
    await store.write(snapshot('2026-09-11T10:00:00.500Z'), new Date('2026-09-11T10:00:00.500Z'));
    const listed = await store.list();
    expect(listed.snapshots.map(item => item.at)).toEqual([
      '2026-09-11T10:00:00.000Z', '2026-09-11T10:00:00.500Z'
    ]);
    await writeFile(join(store.directory, 'corrupt.json'), '{', { mode: 0o600 });
    await writeFile(join(store.directory, 'invalid-version.json'), '{"schemaVersion":0}',
      { mode: 0o600 });
    await writeFile(join(store.directory, 'negative-version.json'), '{"schemaVersion":-1}',
      { mode: 0o600 });
    await writeFile(join(store.directory, 'future.json'), '{"schemaVersion":2}', { mode: 0o600 });
    expect(await store.list()).toMatchObject({ skipped: 4, unsupportedVersions: 1 });
  });

  it('serializes concurrent writers under the count limit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    const now = new Date('2026-09-11T10:00:03.000Z');
    await Promise.all([
      store.write(snapshot('2026-09-11T10:00:00.000Z'), now),
      store.write(snapshot('2026-09-11T10:00:01.000Z'), now),
      store.write(snapshot('2026-09-11T10:00:02.000Z'), now)
    ]);
    expect((await store.list()).snapshots).toHaveLength(2);
  });

  it('unlinks a router-directory symlink without following it', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const outside = await mkdtemp(join(tmpdir(), 'kn-snapshot-outside-'));
    await writeFile(join(outside, 'keep'), 'safe');
    await mkdir(root, { recursive: true });
    await symlink(outside, join(root, 'home'));
    await createSnapshotStore(root, 'home', limits).removeAll();
    await expect(readFile(join(outside, 'keep'), 'utf8')).resolves.toBe('safe');
  });

  it('does not read through a router-directory symlink', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const outside = await mkdtemp(join(tmpdir(), 'kn-snapshot-outside-'));
    const outsideStore = createSnapshotStore(outside, 'outside', limits);
    const saved = await outsideStore.write(snapshot('2026-09-11T10:00:00.000Z'));
    await mkdir(join(outside, 'snapshots'), { mode: 0o700 });
    await writeFile(join(outside, 'snapshots', 'outside.json'), await readFile(saved.path), { mode: 0o600 });
    await symlink(outside, join(root, 'home'));
    expect(await createSnapshotStore(root, 'home', limits).list()).toEqual({ snapshots: [], skipped: 1 });
  });

  it('does not mutate through a symlinked state root during removal', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'kn-snapshot-parent-'));
    const outside = await mkdtemp(join(tmpdir(), 'kn-snapshot-outside-'));
    const target = await mkdtemp(join(tmpdir(), 'kn-snapshot-target-'));
    await symlink(target, join(outside, 'home'));
    const root = join(parent, 'state');
    await symlink(outside, root);
    await expect(createSnapshotStore(root, 'home', limits).removeAll()).rejects.toThrow('state root');
    expect((await lstat(join(outside, 'home'))).isSymbolicLink()).toBe(true);
  });

  it('fails closed when a linked JSON file prevents retention accounting', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kn-snapshot-'));
    const store = createSnapshotStore(root, 'home', limits);
    await mkdir(store.directory, { recursive: true, mode: 0o700 });
    const outside = join(root, 'large.json');
    await writeFile(outside, 'x'.repeat(40_000), { mode: 0o600 });
    await link(outside, join(store.directory, 'linked.json'));
    await expect(store.write(snapshot('2026-09-11T10:00:00.000Z'))).rejects.toThrow(/linked JSON/);
    expect((await stat(join(store.directory, 'linked.json'))).size).toBe(40_000);
  });
});
