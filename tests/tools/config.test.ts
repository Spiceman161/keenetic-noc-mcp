import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { registerConfigTools } from '../../src/tools/config.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

const RUNNING_CHECKSUM = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const STALE_CHECKSUM = '0f9e8d7c6b5a49382716f5e4d3c2b1a0';

/** Startup config as the router serves it: the saved checksum is in the header. */
const configText = (checksum: string) =>
  `! $$$ Md5 checksum: ${checksum}\n! $$$ Model: Keenetic Model\nip hotspot\n`;

const CONFIG = configText(STALE_CHECKSUM);

/**
 * `unsavedAfter` models a save that never completes: the command is accepted
 * but the checksum in flash never catches up with the running one.
 *
 * `fail-safe.unsaved` is deliberately pinned to false throughout, because that
 * is what a real 5.1.1 router reports even while a change sits unsaved. A save
 * check that believes that flag passes this harness while doing nothing.
 */
function harness(opts: { unsavedAfter?: boolean; readOnly?: boolean; startupAvailable?: boolean;
  runningAvailable?: boolean; maxResponseBytes?: number; configLines?: string[];
  runningLines?: string[]; startupLines?: string[]; changeDuringDiff?: boolean } = {}) {
  const posts: unknown[] = [];
  const events: string[] = [];
  let savedChecksum = STALE_CHECKSUM;
  let lastChangedAt = 'Fri, 7 Aug 2026 01:20:36 GMT';

  let lastChangeReads = 0;
  const get = vi.fn(async () => {
    lastChangeReads += 1;
    const moved = opts.changeDuringDiff === true && lastChangeReads > 1;
    return {
      date: moved ? 'Fri, 7 Aug 2026 01:20:40 GMT' : lastChangedAt,
      user: 'admin',
      checksum: moved ? STALE_CHECKSUM : RUNNING_CHECKSUM,
      'fail-safe': { unsaved: false, rollback: false, 'time-left': 0 }
    };
  });
  const getText = vi.fn(async () => configText(savedChecksum));
  const configLines = opts.configLines ?? [
    'system',
    '    hostname safe-router',
    'user agent',
    '    password do-not-leak',
    'dns-proxy',
    '    enabled',
    'interface WifiMaster0/AccessPoint0',
    '    ssid Example',
    'interface Wireguard1',
    '    wireguard private-key private-material'
  ];
  const runningLines = opts.runningLines ?? configLines;
  const startupLines = opts.startupLines ?? configLines;
  const getConfig = vi.fn(async (path: string) => ({
    value: path === '' ? { system: { hostname: 'safe-router' } } :
      path === 'system' ? { hostname: 'safe-router' } :
        { result: path === 'more?filename=startup-config' ? startupLines : runningLines },
    bytes: 100
  }));
  const post = vi.fn(async (body: unknown) => {
    events.push('post');
    posts.push(body);
    // The router records the save either way; whether flash caught up is what
    // separates a real save from one that never landed.
    lastChangedAt = 'Fri, 7 Aug 2026 01:20:40 GMT';
    if (opts.unsavedAfter !== true) savedChecksum = RUNNING_CHECKSUM;
    return {};
  });

  const client = {
    rci: { get, post, getText, getConfig },
    capabilities: vi.fn(),
    probedCapabilities: vi.fn(async () => ({ config: {
      runningCli: opts.runningAvailable === false
        ? { state: 'unavailable', method: null, reason: 'not-found' }
        : { state: 'available', method: 'rci-show', reason: null },
      runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
      startup: opts.startupAvailable === false
        ? { state: 'unavailable', method: null, reason: 'not-found' }
        : { state: 'available', method: 'rci-more', reason: null },
      backup: { state: 'available', method: 'ci-file', reason: null }
    } })),
    markRunningStructured: vi.fn()
  } as unknown as KeeneticClient;

  const backup = stubBackup();
  const ensure = backup.ensure;
  backup.ensure = vi.fn(async () => { events.push('backup'); return ensure(); });
  const ctx: ToolContext = {
    client,
    maxResponseBytes: opts.maxResponseBytes ?? 25_000,
    readOnly: opts.readOnly === true,
    backup,
    audit: { write: vi.fn(async () => undefined) }
  };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const registrations: Record<string, any> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((
    name: string,
    config: unknown,
    handler: Handler
  ) => {
    handlers[name] = handler;
    registrations[name] = config;
    return {} as never;
  }) as never);

  registerConfigTools(server, ctx);
  return { handlers, registrations, posts, get, getText, getConfig, backup, events,
    audit: ctx.audit! };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(p => p.text).join(''));
}

describe('configuration read tools', () => {
  it('registers all reads in read-only mode and redacts before returning CLI lines', async () => {
    const { handlers } = harness({ readOnly: true });
    expect(Object.keys(handlers)).toEqual(expect.arrayContaining([
      'get_running_config', 'get_startup_config', 'search_config', 'get_config_diff'
    ]));
    const out = payload(await handlers['get_running_config']!({ section: 'users' }));
    expect(JSON.stringify(out)).not.toContain('do-not-leak');
    expect(out.lines).toEqual(['user agent', '    password [REDACTED]']);
  });

  it('requires an explicit high limit for all without reading configuration', async () => {
    const { handlers, getConfig } = harness();
    const result = await handlers['get_running_config']!({ section: 'all' });
    expect(result.isError).toBe(true);
    expect(getConfig).not.toHaveBeenCalled();
  });

  it('uses the measured startup RCI source and never substitutes running', async () => {
    const { handlers, getConfig } = harness();
    const out = payload(await handlers['get_startup_config']!({ section: 'system' }));
    expect(out.source).toBe('startup');
    expect(out.method).toBe('rci-more');
    expect(getConfig).toHaveBeenCalledWith('more?filename=startup-config', 256_000);
  });

  it('returns a normal capability envelope when startup is unavailable', async () => {
    const { handlers, getConfig, getText } = harness({ startupAvailable: false });
    const out = payload(await handlers['get_startup_config']!({ section: 'system' }));
    expect(out).toMatchObject({ available: false, state: 'unavailable', reason: 'not-found' });
    expect(getConfig).not.toHaveBeenCalled();
    expect(getText).not.toHaveBeenCalled();
  });

  it('supports structured allowlist reads and rejects heuristic sections', async () => {
    const { handlers, getConfig } = harness();
    const out = payload(await handlers['get_running_config']!({ section: 'system', format: 'structured' }));
    expect(out.method).toBe('rci-branch');
    expect(out.data.system).toEqual({ hostname: 'safe-router' });
    expect(getConfig).toHaveBeenCalledWith('system', 256_000);
    const rejected = await handlers['get_running_config']!({ section: 'vpn', format: 'structured' });
    expect(rejected.isError).toBe(true);
  });

  it('searches normalized text without echoing the query', async () => {
    const { handlers } = harness();
    const out = payload(await handlers['search_config']!({ source: 'running', query: 'SAFE-ROUTER',
      section: 'all', limit: 50, context: 2 }));
    expect(out.totalMatches).toBe(1);
    expect(JSON.stringify(out)).not.toContain('SAFE-ROUTER');
  });

  it('applies normalized CLI filters and reports limit counts', async () => {
    const { handlers } = harness({ configLines: ['system', '    description Café  Router',
      '    hostname Café Router'] });
    const out = payload(await handlers['get_running_config']!({ section: 'system',
      filter: 'CAFE\u0301 ROUTER', limit: 1 }));
    expect(out).toMatchObject({ shown: 1, total: 2, truncated: true });
  });

  it('does not write configuration reads to the mutation audit', async () => {
    const { handlers, audit } = harness();
    await handlers['get_running_config']!({ section: 'system' });
    await handlers['get_startup_config']!({ section: 'system' });
    await handlers['search_config']!({ source: 'running', query: 'system', section: 'all',
      limit: 50, context: 2 });
    expect(audit.write).not.toHaveBeenCalled();
  });

  it('reports only matches present after response-byte truncation', async () => {
    const lines = Array.from({ length: 30 }, (_, index) => `match-${index} ${'x'.repeat(100)}`);
    const { handlers } = harness({ maxResponseBytes: 500, configLines: lines });
    const out = payload(await handlers['search_config']!({ source: 'running', query: 'match',
      section: 'all', limit: 30, context: 0 }));
    const actuallyShown = out.groups.flatMap((group: any) => group.lines)
      .filter((line: any) => line.match).length;
    expect(out.shownMatches).toBe(actuallyShown);
    expect(out.totalMatches).toBe(30);
    expect(out.truncated).toBe(true);
  });

  it('summarizes configuration changes without returning diff lines by default', async () => {
    const { handlers } = harness({
      startupLines: ['! $$$ Md5 checksum: 0f9e8d7c6b5a49382716f5e4d3c2b1a0',
        'dns-proxy', '    cache-size 128'],
      runningLines: ['! $$$ Md5 checksum: a1b2c3d4e5f60718293a4b5c6d7e8f90',
        'dns-proxy', '    cache-size 256']
    });
    const out = payload(await handlers['get_config_diff']!({ include_diff: false, limit: 200 }));
    expect(out).toMatchObject({ comparable: true, unsavedChanges: true,
      runningMethod: 'rci-show', startupMethod: 'rci-more', changedSections: ['dns'],
      added: 1, removed: 1, diffIncluded: false,
      lastChange: { at: 'Fri, 7 Aug 2026 01:20:36 GMT', by: 'admin', via: null } });
    expect(out.diff).toBeUndefined();
  });

  it('returns a bounded redacted textual diff only when requested', async () => {
    const { handlers } = harness({ maxResponseBytes: 700,
      startupLines: ['user agent', '    password first-secret',
        ...Array.from({ length: 20 }, (_, index) => `    description old-${index}`)],
      runningLines: ['user agent', '    password second-secret',
        ...Array.from({ length: 20 }, (_, index) => `    description new-${index}`)] });
    const out = payload(await handlers['get_config_diff']!({ include_diff: true, limit: 20 }));
    expect(out).toMatchObject({ comparable: true, diffIncluded: true, total: 42,
      truncated: true, redactedChanges: 1 });
    expect(out.shownAdded + out.shownRemoved).toBe(out.shown);
    expect(JSON.stringify(out)).not.toMatch(/first-secret|second-secret/);
  });

  it('returns a capability result without reading either config when startup is unavailable', async () => {
    const { handlers, getConfig, get } = harness({ startupAvailable: false });
    const out = payload(await handlers['get_config_diff']!({ include_diff: false, limit: 200 }));
    expect(out).toEqual({ comparable: false, unsavedChanges: null,
      reason: { source: 'startup', state: 'unavailable', reason: 'not-found' },
      diffIncluded: false });
    expect(getConfig).not.toHaveBeenCalled();
    expect(get).not.toHaveBeenCalled();
  });

  it('keeps the diff tool read-only and out of mutation audit', async () => {
    const { handlers, registrations, audit } = harness();
    await handlers['get_config_diff']!({ include_diff: false, limit: 200 });
    expect(registrations['get_config_diff'].annotations.readOnlyHint).toBe(true);
    expect(audit.write).not.toHaveBeenCalled();
  });

  it('refuses a diff when configuration changes between the bracketing reads', async () => {
    const { handlers, get } = harness({ changeDuringDiff: true,
      startupLines: ['system', '    hostname old'],
      runningLines: ['system', '    hostname new'] });
    const out = payload(await handlers['get_config_diff']!({ include_diff: true, limit: 200 }));
    expect(out).toEqual({ comparable: false, unsavedChanges: null,
      reason: 'configuration-changed-during-read', diffIncluded: false });
    expect(out.diff).toBeUndefined();
    expect(get).toHaveBeenCalledTimes(2);
  });
});

describe('save_config', () => {
  it('sends the save command and confirms afterwards', async () => {
    const { handlers, posts, backup, events } = harness();
    const out = payload(await handlers['save_config']!({ dry_run: false, confirm: true }));
    expect(events.slice(0, 2)).toEqual(['backup', 'post']);
    expect(backup.ensure).toHaveBeenCalledOnce();
    expect(posts).toContainEqual({ system: { configuration: { save: {} } } });
    expect(out.saved).toBe(true);
    expect(out.backup).toBeTruthy();
  });

  it('fails when the router still reports unsaved changes', async () => {
    const { handlers } = harness({ unsavedAfter: true });
    const result = await handlers['save_config']!({ dry_run: false, confirm: true });
    expect(result.isError).toBe(true);
    expect(result.content.map(p => p.text).join('')).toMatch(/still reports unsaved/i);
  }, 10_000);

  // The startup config is ~17 KB. Polling the confirmation rather than the
  // cheap endpoint turned one save into roughly 100 KB of traffic.
  it('reads the startup config once, however many times it polls', async () => {
    const { handlers, get, getText } = harness();
    await handlers['save_config']!({ dry_run: false, confirm: true });
    expect(getText).toHaveBeenCalledTimes(1);
    expect(get.mock.calls.length).toBeGreaterThan(1);
  });

  it('reads it once on the failing path too', async () => {
    const { handlers, getText } = harness({ unsavedAfter: true });
    await handlers['save_config']!({ dry_run: false, confirm: true });
    expect(getText).toHaveBeenCalledTimes(1);
  }, 10_000);

  it('is not registered in read-only mode', () => {
    const { handlers } = harness({ readOnly: true });
    expect(handlers['save_config']).toBeUndefined();
  });
});

describe('backup_config', () => {
  it('defaults to a zero-write preview', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-'));
    const target = join(dir, 'out.txt');
    const { handlers, getText } = harness();
    const out = payload(await handlers['backup_config']!({ path: target }));
    expect(out.dryRun).toBe(true);
    expect(getText).not.toHaveBeenCalled();
    await expect(readFile(target, 'utf8')).rejects.toThrow();
  });

  it('writes the startup config to the requested path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-'));
    const target = join(dir, 'out.txt');
    const { handlers } = harness();
    const out = payload(await handlers['backup_config']!({ path: target, dry_run: false, confirm: true }));

    expect(out.path).toBe(target);
    expect(out.bytes).toBe(CONFIG.length);
    await expect(readFile(target, 'utf8')).resolves.toBe(CONFIG);
    expect((await stat(target)).mode & 0o777).toBe(0o600);
  });

  it('refuses to overwrite an existing file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-'));
    const target = join(dir, 'out.txt');
    await writeFile(target, 'keep me');
    const { handlers } = harness();
    const result = await handlers['backup_config']!({ path: target, dry_run: false, confirm: true });
    expect(result.isError).toBe(true);
    await expect(readFile(target, 'utf8')).resolves.toBe('keep me');
  });

  it('reports a usable error when the directory does not exist', async () => {
    const { handlers } = harness();
    const result = await handlers['backup_config']!({ path: '/nope/missing/out.txt', dry_run: false, confirm: true });
    expect(result.isError).toBe(true);
    expect(result.content.map(p => p.text).join('')).toMatch(/absolute path/i);
  });

  it('is absent in read-only mode because it writes the local filesystem', () => {
    const { handlers } = harness({ readOnly: true });
    expect(handlers['backup_config']).toBeUndefined();
  });
});
