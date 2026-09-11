import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmod, lstat, mkdir, open, readdir, readFile, rename, rm, unlink, utimes
} from 'node:fs/promises';
import { join } from 'node:path';
import type {
  ConfigurationSnapshot, DeviceSnapshot, DnsSnapshot, InterfaceKind, InterfaceSnapshot,
  RouteSnapshot, RouterSnapshotV1, SnapshotSource, StateCounts, SystemSnapshot,
  VpnSnapshot, WifiSnapshot
} from '../shape/router-snapshot.js';
import type { SafeReason } from '../shape/internet-diagnostic.js';

export interface SnapshotStoreLimits {
  maxCount: number;
  maxAgeMs: number;
  maxTotalBytes: number;
  maxFileBytes: number;
  maxDirectoryEntries: number;
}

export const DEFAULT_SNAPSHOT_LIMITS: SnapshotStoreLimits = {
  maxCount: 96, maxAgeMs: 30 * 24 * 60 * 60 * 1_000,
  maxTotalBytes: 1024 * 1024, maxFileBytes: 16 * 1024, maxDirectoryEntries: 1024
};

export interface SnapshotWriteResult { path: string; bytes: number; pruned: number }
export interface SnapshotListResult { snapshots: RouterSnapshotV1[]; skipped: number }
export interface SnapshotStore {
  readonly directory: string;
  write(snapshot: RouterSnapshotV1, now?: Date, validate?: () => Promise<void>): Promise<SnapshotWriteResult>;
  list(): Promise<SnapshotListResult>;
  removeAll(finalize?: () => Promise<void>): Promise<void>;
}

const PROFILE_ID = /^[a-z][a-z0-9_-]{0,63}$/;
const KINDS: readonly InterfaceKind[] = ['wan', 'lan', 'wifi', 'vpn', 'bridge', 'other'];
const SAFE_REASONS = new Set<SafeReason>([
  'not-supported', 'rci-error', 'transport-error', 'authentication-error',
  'response-too-large', 'unexpected-response'
]);
const SAVED_REASONS = new Set([...SAFE_REASONS, 'not-probed', 'denied', 'not-found', 'http-error']);

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function nonNegative(value: unknown, integer = false): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 &&
    value <= Number.MAX_SAFE_INTEGER && (!integer || Number.isInteger(value)) ? value : null;
}

function nullableNonNegative(value: unknown, integer = false): number | null | undefined {
  if (value === null) return null;
  const parsed = nonNegative(value, integer);
  return parsed === null ? undefined : parsed;
}

function nullableBoolean(value: unknown): boolean | null | undefined {
  return value === null || typeof value === 'boolean' ? value : undefined;
}

function nullableChecksum(value: unknown): string | null | undefined {
  return value === null ? null
    : typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) ? value : undefined;
}

function counts(value: unknown): StateCounts | null {
  const item = record(value);
  if (item === null) return null;
  const total = nonNegative(item['total'], true);
  const up = nonNegative(item['up'], true);
  const down = nonNegative(item['down'], true);
  const unknown = nonNegative(item['unknown'], true);
  if ([total, up, down, unknown].some(part => part === null) || total !== up! + down! + unknown!) return null;
  return { total: total!, up: up!, down: down!, unknown: unknown! };
}

function canonicalSource<T>(value: unknown, project: (data: unknown) => T | null): SnapshotSource<T> | null {
  const source = record(value);
  if (source === null) return null;
  if (source['status'] === 'unavailable' && source['data'] === null &&
      typeof source['reason'] === 'string' && SAFE_REASONS.has(source['reason'] as SafeReason)) {
    return { status: 'unavailable', reason: source['reason'] as SafeReason, data: null };
  }
  if (source['status'] !== 'available' || source['reason'] !== null) return null;
  const data = project(source['data']);
  return data === null ? null : { status: 'available', reason: null, data };
}

function systemData(value: unknown): SystemSnapshot | null {
  const data = record(value);
  if (data === null) return null;
  const firmware = data['firmware'];
  const uptimeSeconds = nullableNonNegative(data['uptimeSeconds']);
  const cpuLoad = nullableNonNegative(data['cpuLoad']);
  const memoryFreeKb = nullableNonNegative(data['memoryFreeKb']);
  if (!(firmware === null || typeof firmware === 'string' && /^\d\.\d{1,3}(?:\.\d{1,3}){0,2}$/.test(firmware)) ||
      uptimeSeconds === undefined || cpuLoad === undefined || memoryFreeKb === undefined) return null;
  return { firmware, uptimeSeconds, cpuLoad, memoryFreeKb };
}

function configurationData(value: unknown): ConfigurationSnapshot | null {
  const data = record(value);
  if (data === null) return null;
  const runningChecksum = nullableChecksum(data['runningChecksum']);
  const savedChecksum = nullableChecksum(data['savedChecksum']);
  const unsavedChanges = nullableBoolean(data['unsavedChanges']);
  const savedState = data['savedState'];
  const savedReason = data['savedReason'];
  if (runningChecksum === undefined || savedChecksum === undefined || unsavedChanges === undefined ||
      !['available', 'unavailable', 'unknown'].includes(String(savedState)) ||
      !(savedReason === null || typeof savedReason === 'string' && SAVED_REASONS.has(savedReason))) return null;
  if (savedState === 'available' && (savedChecksum === null || savedReason !== null)) return null;
  if (savedState !== 'available' && (savedChecksum !== null || savedReason === null)) return null;
  const expectedUnsaved = runningChecksum === null || savedChecksum === null
    ? null : runningChecksum !== savedChecksum;
  if (unsavedChanges !== expectedUnsaved) return null;
  return { runningChecksum, savedChecksum, unsavedChanges,
    savedState: savedState as ConfigurationSnapshot['savedState'], savedReason };
}

function interfaceData(value: unknown): InterfaceSnapshot | null {
  const data = record(value);
  const rawKinds = record(data?.['byKind']);
  if (data === null || rawKinds === null) return null;
  const byKind = {} as Record<InterfaceKind, StateCounts>;
  for (const kind of KINDS) {
    const item = counts(rawKinds[kind]);
    if (item === null) return null;
    byKind[kind] = item;
  }
  const total = nonNegative(data['total'], true);
  if (total === null || total !== KINDS.reduce((sum, kind) => sum + byKind[kind].total, 0)) return null;
  return { total, byKind };
}

function routeData(value: unknown): RouteSnapshot | null {
  const data = record(value);
  if (data === null) return null;
  const total = nonNegative(data['total'], true);
  const usable = nonNegative(data['usable'], true);
  const rejecting = nonNegative(data['rejecting'], true);
  const activePath = data['activePath'];
  if (total === null || usable === null || rejecting === null || usable + rejecting !== total ||
      !['physical', 'vpn', 'ambiguous', 'none', 'unknown'].includes(String(activePath))) return null;
  return { total, usable, rejecting, activePath: activePath as RouteSnapshot['activePath'] };
}

function dnsData(value: unknown): DnsSnapshot | null {
  const data = record(value);
  if (data === null) return null;
  const enabled = nullableBoolean(data['enabled']);
  const state = data['state'];
  const upstreamsTotal = nonNegative(data['upstreamsTotal'], true);
  const upstreamsHealthy = nonNegative(data['upstreamsHealthy'], true);
  const upstreamsUnhealthy = nonNegative(data['upstreamsUnhealthy'], true);
  const upstreamsUnknown = nonNegative(data['upstreamsUnknown'], true);
  const staticHostsCount = nonNegative(data['staticHostsCount'], true);
  const errorCount = nonNegative(data['errorCount'], true);
  if (enabled === undefined || !['healthy', 'unhealthy', 'unknown'].includes(String(state)) ||
      [upstreamsTotal, upstreamsHealthy, upstreamsUnhealthy, upstreamsUnknown,
        staticHostsCount, errorCount].some(part => part === null) ||
      upstreamsTotal !== upstreamsHealthy! + upstreamsUnhealthy! + upstreamsUnknown!) return null;
  return { enabled, state: state as DnsSnapshot['state'], upstreamsTotal: upstreamsTotal!,
    upstreamsHealthy: upstreamsHealthy!, upstreamsUnhealthy: upstreamsUnhealthy!,
    upstreamsUnknown: upstreamsUnknown!, staticHostsCount: staticHostsCount!, errorCount: errorCount! };
}

function vpnData(value: unknown): VpnSnapshot | null {
  const base = counts(value);
  const data = record(value);
  if (base === null || data === null) return null;
  const peersTotal = nonNegative(data['peersTotal'], true);
  const peersOnline = nonNegative(data['peersOnline'], true);
  const peersUnknown = nonNegative(data['peersUnknown'], true);
  if (peersTotal === null || peersOnline === null || peersUnknown === null ||
      peersOnline + peersUnknown > peersTotal) return null;
  return { ...base, peersTotal, peersOnline, peersUnknown };
}

function wifiData(value: unknown): WifiSnapshot | null {
  const count = nonNegative(record(value)?.['clientCount'], true);
  return count === null ? null : { clientCount: count };
}

function deviceData(value: unknown): DeviceSnapshot | null {
  const data = record(value);
  if (data === null) return null;
  const deviceCount = nonNegative(data['deviceCount'], true);
  const activeCount = nonNegative(data['activeCount'], true);
  return deviceCount === null || activeCount === null || activeCount > deviceCount
    ? null : { deviceCount, activeCount };
}

export function canonicalSnapshot(value: unknown): RouterSnapshotV1 | null {
  const snapshot = record(value);
  const sources = record(snapshot?.['sources']);
  const at = snapshot?.['at'];
  if (snapshot === null || sources === null || snapshot['schemaVersion'] !== 1 ||
      typeof at !== 'string' || !Number.isFinite(Date.parse(at)) || new Date(Date.parse(at)).toISOString() !== at ||
      typeof snapshot['complete'] !== 'boolean') return null;
  const system = canonicalSource(sources['system'], systemData);
  const configuration = canonicalSource(sources['configuration'], configurationData);
  const interfaces = canonicalSource(sources['interfaces'], interfaceData);
  const routes = canonicalSource(sources['routes'], routeData);
  const dns = canonicalSource(sources['dns'], dnsData);
  const vpn = canonicalSource(sources['vpn'], vpnData);
  const wifi = canonicalSource(sources['wifi'], wifiData);
  const devices = canonicalSource(sources['devices'], deviceData);
  if ([system, configuration, interfaces, routes, dns, vpn, wifi, devices].some(item => item === null)) return null;
  const canonicalSources = { system: system!, configuration: configuration!, interfaces: interfaces!,
    routes: routes!, dns: dns!, vpn: vpn!, wifi: wifi!, devices: devices! };
  const computedComplete = Object.values(canonicalSources).every(source => source.status === 'available') &&
    canonicalSources.configuration.data?.runningChecksum !== null &&
    canonicalSources.configuration.data?.savedState === 'available';
  if (snapshot['complete'] !== computedComplete) return null;
  return { schemaVersion: 1, at, complete: computedComplete, sources: canonicalSources };
}

export function snapshotRouterComponent(routerId: string): string {
  if (PROFILE_ID.test(routerId)) return routerId;
  const digest = createHash('sha256').update(routerId).digest('hex');
  return `X${digest}`;
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Snapshot path must be a real directory.');
  await chmod(path, 0o700);
}

function wait(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

interface LockOwner { pid: number; token: string }

async function readOwner(path: string): Promise<LockOwner | null> {
  try {
    const value: unknown = JSON.parse((await readFile(path, 'utf8')).slice(0, 1024));
    const owner = record(value);
    return owner !== null && Number.isInteger(owner['pid']) && typeof owner['token'] === 'string'
      ? { pid: owner['pid'] as number, token: owner['token'] } : null;
  } catch { return null; }
}

async function releaseOwnedLock(path: string, token: string): Promise<void> {
  if ((await readOwner(path))?.token === token) await unlink(path).catch(() => undefined);
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code === 'EPERM'; }
}

async function withLock<T>(routerDirectory: string, operation: () => Promise<T>): Promise<T> {
  const lock = join(routerDirectory, '.snapshot.lock');
  const token = randomUUID();
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const handle = await open(lock, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify({ pid: process.pid, token }), { encoding: 'utf8' });
        await handle.sync();
      } catch (error) {
        // This descriptor exclusively created the pathname and acquisition has
        // not completed, so no legitimate owner can have replaced it yet.
        await unlink(lock).catch(() => undefined);
        await handle.close().catch(() => undefined);
        throw error;
      }
      await handle.close();
      try { return await operation(); } finally { await releaseOwnedLock(lock, token); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const owner = await readOwner(lock);
      if (owner === null) throw new Error('Snapshot lock is corrupt; remove it only after confirming no snapshot command is running.');
      if (!processAlive(owner.pid)) {
        throw new Error('Snapshot lock belongs to a stopped process; remove it only after confirming no snapshot command is running.');
      }
      await wait(100);
    }
  }
  throw new Error('Snapshot store is busy; retry the command.');
}

interface StoredFile { name: string; path: string; bytes: number; mtimeMs: number }

export function createSnapshotStore(
  stateRoot: string,
  routerId: string,
  limits: SnapshotStoreLimits = DEFAULT_SNAPSHOT_LIMITS
): SnapshotStore {
  const routerDirectory = join(stateRoot, snapshotRouterComponent(routerId));
  const directory = join(routerDirectory, 'snapshots');

  async function prepare(): Promise<void> {
    await ensurePrivateDirectory(stateRoot);
    await ensurePrivateDirectory(routerDirectory);
    await ensurePrivateDirectory(directory);
  }

  async function files(repairPermissions: boolean): Promise<StoredFile[]> {
    const entries = await readdir(directory, { withFileTypes: true });
    if (entries.length > limits.maxDirectoryEntries) {
      throw new Error('Snapshot directory entry limit exceeded; clean it before capturing another snapshot.');
    }
    const result: StoredFile[] = [];
    for (const entry of entries) {
      if (!entry.name.endsWith('.json')) continue;
      if (!entry.isFile()) {
        if (repairPermissions) throw new Error('Snapshot retention cannot inspect an unsafe JSON entry.');
        continue;
      }
      const path = join(directory, entry.name);
      let handle;
      try {
        handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
        const info = await handle.stat();
        if (!info.isFile() || info.nlink !== 1) {
          if (repairPermissions) throw new Error('Snapshot retention cannot own a linked JSON entry.');
          continue;
        }
        if (repairPermissions) await handle.chmod(0o600);
        else if ((info.mode & 0o077) !== 0) continue;
        result.push({ name: entry.name, path, bytes: info.size, mtimeMs: info.mtimeMs });
      } catch (error) {
        if (repairPermissions) throw error;
      }
      finally { await handle?.close().catch(() => undefined); }
    }
    return result.sort((a, b) => a.mtimeMs - b.mtimeMs || a.name.localeCompare(b.name));
  }

  async function write(
    snapshot: RouterSnapshotV1,
    now = new Date(),
    validate?: () => Promise<void>
  ): Promise<SnapshotWriteResult> {
    await prepare();
    const persisted = canonicalSnapshot(snapshot);
    if (persisted === null) throw new Error('Refusing to store an invalid router snapshot.');
    const text = `${JSON.stringify(persisted, null, 2)}\n`;
    const bytes = Buffer.byteLength(text, 'utf8');
    if (bytes > limits.maxFileBytes || bytes > limits.maxTotalBytes) {
      throw new Error('Router snapshot exceeds the configured storage ceiling.');
    }
    return withLock(routerDirectory, async () => {
      await validate?.();
      let pruned = 0;
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (entry.isFile() && entry.name.includes('.tmp')) await unlink(join(directory, entry.name)).catch(() => undefined);
      }
      let current = await files(true);
      const cutoff = now.getTime() - limits.maxAgeMs;
      for (const file of current.filter(item => item.mtimeMs < cutoff)) {
        await unlink(file.path);
        pruned += 1;
      }
      current = await files(true);
      let totalBytes = current.reduce((total, item) => total + item.bytes, 0);
      while (current.length >= limits.maxCount || totalBytes + bytes > limits.maxTotalBytes) {
        const oldest = current.shift();
        if (!oldest) throw new Error('Snapshot retention cannot make room for the new record.');
        await unlink(oldest.path);
        totalBytes -= oldest.bytes;
        pruned += 1;
      }
      const stamp = persisted.at.replace(/[:.]/g, '-');
      const finalPath = join(directory, `${stamp}-${randomUUID()}.json`);
      const temporary = `${finalPath}.${process.pid}.tmp`;
      const handle = await open(temporary, 'wx', 0o600);
      try {
        await handle.writeFile(text, { encoding: 'utf8' });
        await handle.sync();
      } finally { await handle.close(); }
      await chmod(temporary, 0o600);
      await rename(temporary, finalPath);
      await chmod(finalPath, 0o600);
      await utimes(finalPath, now, now);
      return { path: finalPath, bytes, pruned };
    });
  }

  async function list(): Promise<SnapshotListResult> {
    const rootInfo = await lstat(stateRoot).catch(() => null);
    if (rootInfo === null) return { snapshots: [], skipped: 0 };
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) return { snapshots: [], skipped: 1 };
    const routerInfo = await lstat(routerDirectory).catch(() => null);
    if (routerInfo === null) return { snapshots: [], skipped: 0 };
    if (!routerInfo.isDirectory() || routerInfo.isSymbolicLink()) return { snapshots: [], skipped: 1 };
    const info = await lstat(directory).catch(() => null);
    if (info === null) return { snapshots: [], skipped: 0 };
    if (!info.isDirectory() || info.isSymbolicLink()) return { snapshots: [], skipped: 1 };
    const snapshots: RouterSnapshotV1[] = [];
    let skipped = 0;
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { snapshots: [], skipped: 0 };
      throw error;
    }
    if (entries.length > limits.maxDirectoryEntries) return { snapshots: [], skipped: entries.length };
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      let handle;
      try {
        handle = await open(join(directory, entry.name), constants.O_RDONLY | constants.O_NOFOLLOW);
        const current = await handle.stat();
        if (!current.isFile() || current.nlink !== 1 || current.size > limits.maxFileBytes ||
            (current.mode & 0o077) !== 0) { skipped += 1; continue; }
        const canonical = canonicalSnapshot(JSON.parse(await handle.readFile('utf8')));
        if (canonical === null) { skipped += 1; continue; }
        snapshots.push(canonical);
      } catch { skipped += 1; }
      finally { await handle?.close().catch(() => undefined); }
    }
    snapshots.sort((a, b) => a.at.localeCompare(b.at));
    return { snapshots, skipped };
  }

  async function removeAll(finalize?: () => Promise<void>): Promise<void> {
    const rootInfo = await lstat(stateRoot).catch(() => null);
    if (rootInfo !== null && (!rootInfo.isDirectory() || rootInfo.isSymbolicLink())) {
      throw new Error('Snapshot state root must be a real directory.');
    }
    const info = await lstat(routerDirectory).catch(() => null);
    if (info?.isSymbolicLink()) await unlink(routerDirectory);
    else if (info !== null && !info.isDirectory()) throw new Error('Snapshot router path is not a directory.');
    await ensurePrivateDirectory(stateRoot);
    await ensurePrivateDirectory(routerDirectory);
    await withLock(routerDirectory, async () => {
      await rm(directory, { recursive: true, force: true });
      await finalize?.();
    });
  }

  return { directory, write, list, removeAll };
}
