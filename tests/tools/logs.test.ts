import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { RciError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { filterLogEntries, logEntries, registerLogTools } from '../../src/tools/logs.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

function harness(options: { logs?: unknown; error?: Error } = {}) {
  const get = vi.fn(async () => ({ host: [
    { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'iPhosha 13' }
  ] }));
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
    maxResponseBytes: 25_000,
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

describe('log tools', () => {
  it('uses the read-only show command dispatcher and unwraps its response', async () => {
    const { handlers, post } = harness();
    const out = payload(await handlers['get_logs']!({ lines: 1 }));
    expect(out.lines).toEqual(['00:02 Hotspot info Host 192.0.2.5 joined']);
    expect(out.entries).toEqual([{
      timestamp: '00:02', ident: 'Hotspot', level: 'info', label: 'Host',
      line: '00:02 Hotspot info Host 192.0.2.5 joined'
    }]);
    expect(post).toHaveBeenCalledWith({ show: { log: {} } });
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
