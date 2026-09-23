import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { RciError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { filterLogEntries, logEntries, registerLogTools } from '../../src/tools/logs.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

function harness(options: { logs?: unknown; error?: Error; maxResponseBytes?: number; hosts?: unknown } = {}) {
  const get = vi.fn(async () => ({ host: [
    { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'iPhosha 13' }
  ] }));
  if (options.hosts !== undefined) get.mockResolvedValue(options.hosts as never);
  const post = options.error
    ? vi.fn(async () => { throw options.error; })
    : vi.fn(async () => options.logs ?? { show: { log: { log: {
      '1': { timestamp: '00:01', ident: 'System', message: { level: 'info', label: 'Boot', message: 'ready' } },
      '2': { timestamp: '00:02', ident: 'Hotspot', message: { level: 'info', label: 'Host', message: '192.0.2.5 joined' } }
    } } } });
  const client = {
    rci: { get, post, getText: vi.fn() },
    capabilities: vi.fn()
  } as unknown as KeeneticClient;
  const ctx: ToolContext = {
    client,
    maxResponseBytes: options.maxResponseBytes ?? 25_000,
    readOnly: true,
    backup: stubBackup()
  };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((
    name: string,
    _config: unknown,
    handler: Handler
  ) => {
    handlers[name] = handler;
    return {} as never;
  }) as never);
  registerLogTools(server, ctx);
  return { handlers, get, post };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

function sampleLogs(count: number, message: (index: number) => string): unknown {
  return { show: { log: { log: Object.fromEntries(Array.from({ length: count }, (_, index) => [
    String(index), { timestamp: `00:${String(index).padStart(3, '0')}`, ident: 'Network', message: {
      message: message(index)
    } }
  ])) } } };
}

describe('log tools', () => {
  it('uses the read-only show command dispatcher and unwraps its response', async () => {
    const { handlers, post } = harness();
    const out = payload(await handlers['get_logs']!({ lines: 1 }));
    expect(out.lines).toEqual(['00:02 Hotspot info Host 192.0.2.5 joined']);
    expect(out.entries).toEqual([{
      timestamp: '00:02', ident: 'Hotspot', level: 'info', label: 'Host',
      line: '00:02 Hotspot info Host 192.0.2.5 joined'
    }]);
    expect(post).toHaveBeenCalledWith({ show: { log: {} } }, 2_000_000);
    expect(out.matched).toBe(1);
    expect(out.truncated).toBeUndefined();
  });

  it.each(['get_logs', 'get_logs_by_device'])('preserves the newest selected paired entries under a 25 KB cap for %s', async tool => {
    const logs = sampleLogs(51, index => `${index === 0 ? 'older-sentinel' : `event-${index}`} 192.0.2.5 password=test-value ${'a"\\é'.repeat(110)}`);
    const setup = harness({ logs });
    const args = tool === 'get_logs' ? { filter: 'event-', lines: 50 } : { device: 'iPhosha13', filter: 'event-', lines: 50 };
    const result = await setup.handlers[tool]!(args);
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(25_000);
    expect(out).toMatchObject({ total: 51, matched: 50, filters: { filter: 'event-' }, untrusted: true, truncated: true });
    expect(out.lines.length).toBeGreaterThan(0);
    expect(out.lines.length).toBeLessThan(50);
    expect(out.entries.map((entry: { line: string }) => entry.line)).toEqual(out.lines);
    expect(out.lines.at(-1)).toContain('event-50');
    expect(out.lines[0]).toContain(`event-${51 - out.lines.length}`);
    expect(result.content[0]!.text).not.toContain('older-sentinel');
    expect(result.content[0]!.text).not.toContain('test-value');
    expect(out.lines.at(-1)).toContain('password=[REDACTED]');
    if (tool === 'get_logs_by_device') expect(out.aliases).toContain('192.0.2.5');
  });

  it('keeps the normal dual-array default tail and does not treat the lines limit as budget truncation', async () => {
    const setup = harness({ logs: sampleLogs(3, index => `entry-${index}`) });
    const out = payload(await setup.handlers['get_logs']!({ lines: 2 }));
    expect(out).toMatchObject({ total: 3, matched: 2, untrusted: true, filters: {} });
    expect(out.lines).toHaveLength(2);
    expect(out.entries.map((entry: { line: string }) => entry.line)).toEqual(out.lines);
    expect(out.truncated).toBeUndefined();
  });

  it('keeps a bounded unfiltered default tail rather than losing all evidence', async () => {
    const setup = harness({ logs: sampleLogs(120, index => `event-${index} ${'payload-word '.repeat(40)}`) });
    const result = await setup.handlers['get_logs']!({});
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(25_000);
    expect(out).toMatchObject({ total: 120, matched: 100, filters: {}, truncated: true });
    expect(out.lines.length).toBeGreaterThan(0);
    expect(out.lines.at(-1)).toContain('event-119');
    expect(out.entries.map((entry: { line: string }) => entry.line)).toEqual(out.lines);
    expect(result.content[0]!.text).not.toContain('event-0 ');
  });

  it('distinguishes no matches from a single oversized selected entry under a tight ceiling', async () => {
    const setup = harness({ logs: sampleLogs(1, () => `event ${'é"\\'.repeat(600)}`), maxResponseBytes: 512 });
    const empty = payload(await setup.handlers['get_logs']!({ filter: 'absent' }));
    expect(empty).toMatchObject({ total: 1, matched: 0, filters: { filter: 'absent' }, lines: [], entries: [] });
    expect(empty.truncated).toBeUndefined();
    const result = await setup.handlers['get_logs']!({ filter: 'event' });
    const out = payload(result);
    expect(Buffer.byteLength(result.content[0]!.text, 'utf8')).toBeLessThanOrEqual(512);
    expect(out).toMatchObject({ total: 1, matched: 1, filters: { filter: 'event' }, lines: [], entries: [], truncated: true });
    expect(out.note).toMatch(/filter|lines/i);
  });

  it('fails closed when exact selector or alias metadata cannot fit a 512-byte response', async () => {
    const huge = 'zxy '.repeat(200);
    const selector = harness({ maxResponseBytes: 512 });
    const selectorOut = payload(await selector.handlers['get_logs']!({ filter: huge }));
    expect(selectorOut).toHaveProperty('originalBytes');
    expect(selectorOut).not.toHaveProperty('filters');
    const alias = harness({ maxResponseBytes: 512, hosts: { host: [
      { name: 'Target', hostname: huge, ip: '192.0.2.5' }
    ] } });
    const aliasOut = payload(await alias.handlers['get_logs_by_device']!({ device: 'Target' }));
    expect(aliasOut).toHaveProperty('originalBytes');
    expect(aliasOut).not.toHaveProperty('aliases');
  });

  it('keeps the generic get_logs line contract separate from diagnose_internet omission', async () => {
    const { handlers } = harness({ logs: { show: { log: { log: {
      '1': { timestamp: '00:01', ident: 'Network', message: { message: 'gateway generic-log-sentinel' } }
    } } } } });
    const out = payload(await handlers['get_logs']!({}));
    expect(out.entries[0]).toMatchObject({ line: '00:01 Network gateway generic-log-sentinel' });
  });

  it('resolves normalized device names to log aliases', async () => {
    const { handlers } = harness();
    const out = payload(await handlers['get_logs_by_device']!({ device: 'Iphosha13' }));
    expect(out.aliases).toContain('192.0.2.5');
    expect(out.lines).toEqual(['00:02 Hotspot info Host 192.0.2.5 joined']);
  });

  it('rejects ambiguous normalized device names without listing devices', async () => {
    const setup = harness();
    setup.get.mockResolvedValue({ host: [
      { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'Kitchen Phone' },
      { mac: '02:00:00:00:00:02', ip: '192.0.2.6', name: 'kitchenphone' }
    ] });
    const result = await setup.handlers['get_logs_by_device']!({ device: 'Kitchen Phone' });
    expect(result.isError).toBe(true);
    const text = result.content.map(part => part.text).join('');
    expect(text).toMatch(/ambiguous/i);
    expect(text).not.toContain('02:00:00:00:00:01');
    expect(text).not.toContain('192.0.2.5');
    expect(text).not.toContain('kitchenphone');
  });

  it('rejects a blank device selector before reading the log dispatcher', async () => {
    const setup = harness();
    const result = await setup.handlers['get_logs_by_device']!({ device: '   ' });
    expect(result.isError).toBe(true);
    expect(setup.post).not.toHaveBeenCalled();
  });

  it('combines device, interface, text and time filters without inspecting message text as a timestamp', () => {
    const entries = logEntries({ log: {
      '1': { timestamp: '2026-09-09T01:00:00Z', ident: 'Network', message: { message: 'Bridge0 linked 192.0.2.5' } },
      '2': { timestamp: '2026-09-09T01:01:00Z', ident: 'Network', message: { message: 'Bridge1 linked 192.0.2.5' } },
      '3': { timestamp: '2026-09-09T01:02:00Z', ident: 'Network', message: { message: 'Bridge0 linked 192.0.2.6' } }
    } });
    expect(filterLogEntries(entries, {
      aliases: ['192.0.2.5'], interface: 'Bridge0', filter: 'linked',
      since: '2026-09-09T00:59:00Z', until: '2026-09-09T01:01:00Z'
    }).map(entry => entry.line)).toEqual(['2026-09-09T01:00:00Z Network Bridge0 linked 192.0.2.5']);
  });

  it('matches an interface from structured metadata and falls back for text logs', () => {
    const structured = logEntries({ timestamp: '00:01', ident: 'Network', message: {
      label: 'Bridge0', message: 'linked'
    } });
    const legacy = logEntries('00:02 Bridge1 linked');
    expect(filterLogEntries(structured, { interface: 'bridge0' })).toHaveLength(1);
    expect(filterLogEntries(legacy, { interface: 'bridge1' })).toHaveLength(1);
  });

  it('uses null metadata for legacy string responses', () => {
    expect(logEntries('00:01 ready')[0]).toEqual({
      timestamp: '00:01', ident: null, level: null, label: null, line: '00:01 ready'
    });
  });

  it('walks deeply nested responses without overflowing the stack', () => {
    let raw: unknown = { timestamp: '00:01', message: 'ready' };
    for (let depth = 0; depth < 7_000; depth += 1) raw = { log: raw };
    expect(logEntries(raw).map(entry => entry.line)).toEqual(['00:01 ready']);
  });

  it('accepts the combined filters through the device-specific MCP tool', async () => {
    const { handlers } = harness({ logs: { show: { log: { log: {
      '1': { timestamp: '2026-09-09T01:00:00Z', ident: 'Hotspot', message: { message: 'Bridge0 192.0.2.5 joined' } }
    } } } } });
    const out = payload(await handlers['get_logs_by_device']!({
      device: 'iPhosha13', interface: 'Bridge0', since: '2026-09-09T00:59:00Z', until: '2026-09-09T01:01:00Z'
    }));
    expect(out.lines).toEqual(['2026-09-09T01:00:00Z Hotspot Bridge0 192.0.2.5 joined']);
    expect(out.filters).toMatchObject({ interface: 'Bridge0', since: '2026-09-09T00:59:00Z' });
  });

  it('accepts a device selector together with the general log filters', async () => {
    const { handlers } = harness({ logs: { show: { log: { log: {
      '1': { timestamp: '2026-09-09T01:00:00Z', ident: 'Hotspot', message: { message: 'Bridge0 192.0.2.5 joined' } }
    } } } } });
    const out = payload(await handlers['get_logs']!({
      device: 'iPhosha13', interface: 'Bridge0', filter: 'joined',
      since: '2026-09-09T00:59:00Z', until: '2026-09-09T01:01:00Z'
    }));
    expect(out.lines).toEqual(['2026-09-09T01:00:00Z Hotspot Bridge0 192.0.2.5 joined']);
    expect(out.filters).toMatchObject({ device: 'iPhosha13', filter: 'joined' });
  });

  it('reports an unavailable log command as a capability limitation', async () => {
    const error = new RciError('missing', { path: 'POST /rci/', code: '404', ident: 'http' });
    const result = await harness({ error }).handlers['get_logs']!({});
    expect(result.isError).toBe(true);
    const text = result.content.map(part => part.text).join('');
    expect(text).toMatch(/not exposed/i);
    expect(text).toMatch(/firmware or connection mode/i);
  });

  it('does not misclassify an oversized log response as unsupported', async () => {
    const error = new RciError('response exceeds safety limit', {
      path: 'response', code: 'response-too-large', ident: 'rci'
    });
    const result = await harness({ error }).handlers['get_logs']!({});
    expect(result.isError).toBe(true);
    const text = result.content.map(part => part.text).join('');
    expect(text).toMatch(/response-too-large/);
    expect(text).not.toMatch(/not exposed/i);
  });
});
