import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import { guard, ok, type ToolResult } from '../../src/tools/registry.js';
import { instrumentToolRegistration } from '../../src/telemetry/instrumentation.js';
import type { TelemetryRecord } from '../../src/telemetry/record.js';

type Callback = (args: unknown, context: ServerContext) => Promise<ToolResult>;

async function capture(
  name: string,
  args: unknown,
  result: unknown,
  inputFields: readonly string[] = []
): Promise<string> {
  let callback: Callback | undefined;
  const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
    unknown as McpServer;
  const records: TelemetryRecord[] = [];
  const registrar = instrumentToolRegistration(server, {
    writer: { write: async record => { records.push(record); } },
    routerProfile: 'aunt',
    serverVersion: '0.0.0-dev'
  });
  const register = registrar.registerTool as unknown as (
    tool: string,
    config: Record<string, unknown>,
    handler: Callback
  ) => unknown;
  register(name, {
    inputSchema: Object.fromEntries(inputFields.map(field => [field, {}]))
  }, guard(async () => ok(result)));
  await callback!(args, { mcpReq: { id: 'safe-id' } } as unknown as ServerContext);
  return JSON.stringify(records[0]);
}

describe('telemetry privacy boundary', () => {
  it('stores only shapes for raw RCI arguments and never stores result content', async () => {
    const serialized = await capture('rci_call', {
      method: 'POST',
      path: 'secret-path-marker',
      body: { password: 'secret-body-marker', nested: { privateKey: 'secret-key-marker' } },
      confirm: true
    }, { configuration: 'secret-result-marker' }, ['method', 'path', 'body', 'confirm']);
    expect(serialized).not.toContain('secret-path-marker');
    expect(serialized).not.toContain('secret-body-marker');
    expect(serialized).not.toContain('secret-key-marker');
    expect(serialized).not.toContain('secret-result-marker');
    expect(JSON.parse(serialized).args_summary.fields).toEqual({
      method: { type: 'string', length: 4 },
      path: { type: 'string', length: 18 },
      body: { type: 'object', fields: 2 },
      confirm: { type: 'boolean' }
    });
  });

  it('does not retain configuration queries, filters, paths, or returned lines', async () => {
    const serialized = await capture('search_config', {
      query: 'secret-query-marker',
      filter: 'secret-filter-marker',
      path: '/secret/local/path-marker'
    }, { lines: ['secret-config-line-marker'] }, ['query', 'filter', 'path']);
    for (const marker of [
      'secret-query-marker',
      'secret-filter-marker',
      '/secret/local/path-marker',
      'secret-config-line-marker'
    ]) expect(serialized).not.toContain(marker);
  });

  it('bounds and anonymizes unusual argument field names', async () => {
    const args = Object.fromEntries(Array.from({ length: 40 }, (_, index) => [
      index === 0 ? 'bad\nsecret-field-marker' : `field_${index}`,
      'secret-value-marker'
    ]));
    const serialized = await capture('future_tool', args, { ok: true });
    expect(serialized).not.toContain('secret-field-marker');
    expect(serialized).not.toContain('secret-value-marker');
    expect(JSON.parse(serialized).args_summary).toMatchObject({ total_fields: 40, truncated: true });
  });

  it('does not persist exception text even when it contains credential-like data', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const records: TelemetryRecord[] = [];
    const registrar = instrumentToolRegistration(server, {
      writer: { write: async record => { records.push(record); } },
      routerProfile: 'aunt',
      serverVersion: '0.0.0-dev'
    });
    const register = registrar.registerTool as unknown as (
      tool: string,
      config: Record<string, unknown>,
      handler: Callback
    ) => unknown;
    register('get_startup_config', { inputSchema: {} }, guard(async () => {
      throw new Error('authorization: secret-exception-marker');
    }));
    await callback!({}, { mcpReq: { id: 1 } } as unknown as ServerContext);
    const serialized = JSON.stringify(records[0]);
    expect(serialized).not.toContain('secret-exception-marker');
    expect(records[0]).toMatchObject({ status: 'error', error_code: 'internal' });
  });

  it('does not persist client-controlled string request IDs', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const records: TelemetryRecord[] = [];
    const registrar = instrumentToolRegistration(server, {
      writer: { write: async record => { records.push(record); } },
      routerProfile: 'aunt',
      serverVersion: '0.0.0-dev'
    });
    const register = registrar.registerTool as unknown as (
      tool: string,
      config: Record<string, unknown>,
      handler: Callback
    ) => unknown;
    register('get_system_info', { inputSchema: {} }, guard(async () => ok({ healthy: true })));
    await callback!({}, {
      mcpReq: { id: 'secret-client-id-marker' }
    } as unknown as ServerContext);
    expect(JSON.stringify(records[0])).not.toContain('secret-client-id-marker');
    expect(records[0]).not.toHaveProperty('mcp_request_id');
  });
});
