import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import {
  ActiveDiagnosticUncertainError,
  ResourceError,
  ValidationError
} from '../../src/router/errors.js';
import { fail, guard, ok, type ToolResult } from '../../src/tools/registry.js';
import { instrumentToolRegistration } from '../../src/telemetry/instrumentation.js';
import type { TelemetryRecord } from '../../src/telemetry/record.js';
import { normalizeErrorCode } from '../../src/telemetry/record.js';
import type { TelemetryWriter } from '../../src/telemetry/writer.js';

type Callback = (args: unknown, context: ServerContext) => Promise<ToolResult>;

function setup(options?: { rejectWrite?: boolean; times?: number[] }) {
  let callback: Callback | undefined;
  const server = {
    registerTool: vi.fn((_name: string, _config: unknown, handler: Callback) => {
      callback = handler;
      return {};
    })
  } as unknown as McpServer;
  const records: TelemetryRecord[] = [];
  const writer: TelemetryWriter = {
    write: vi.fn(async record => {
      if (options?.rejectWrite) throw new Error('unavailable');
      records.push(record);
    })
  };
  const monotonic = options?.times ?? [10, 448];
  let timeIndex = 0;
  const registrar = instrumentToolRegistration(server, {
    writer,
    routerProfile: 'tupik',
    serverVersion: '0.0.0-dev',
    now: () => new Date(timeIndex === 0 ? '2026-09-12T00:00:00.000Z' : '2026-09-12T00:00:00.438Z'),
    monotonicNow: () => monotonic[timeIndex++] ?? monotonic.at(-1) ?? 0
  });
  const request = { mcpReq: { id: 17 } } as unknown as ServerContext;
  return { registrar, records, writer, request, callback: () => callback! };
}

function register(
  fixture: Pick<ReturnType<typeof setup>, 'registrar'>,
  handler: Callback
): void {
  const call = fixture.registrar.registerTool as unknown as (
    name: string,
    config: Record<string, unknown>,
    callback: Callback
  ) => unknown;
  call('diagnose_dns', {
    inputSchema: { query: {} },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
  }, handler);
}

describe('tool-call instrumentation', () => {
  it('records success, duration, profile, size, truncation, and call metadata', async () => {
    const fixture = setup();
    register(fixture, guard(async () => ok({ truncated: true, value: 'safe' })));
    const result = await fixture.callback()({ query: 'do-not-store' }, fixture.request);

    expect(fixture.records).toHaveLength(1);
    expect(fixture.records[0]).toMatchObject({
      router_profile: 'tupik',
      tool: 'diagnose_dns',
      duration_ms: 438,
      status: 'success',
      error_code: null,
      output_truncated: true,
      mcp_request_id: 17,
      args_summary: {
        fields: { query: { type: 'string', length: 12 } },
        total_fields: 1,
        truncated: false
      }
    });
    expect(fixture.records[0]!.result_size_bytes).toBe(Buffer.byteLength(JSON.stringify(result)));
    const meta = result['_meta'] as Record<string, unknown>;
    expect(meta['io.github.spiceman161/telemetry'])
      .toEqual({ call_id: fixture.records[0]!.call_id });
  });

  it('records normalized returned and thrown failures', async () => {
    const returned = setup();
    register(returned, guard(async () => {
      throw new ValidationError('bad input');
    }));
    const returnedResult = await returned.callback()({}, returned.request);
    expect(returnedResult.isError).toBe(true);
    expect(returned.records[0]).toMatchObject({ status: 'error', error_code: 'validation' });

    const thrown = setup();
    register(thrown, async () => {
      throw new ResourceError('busy', 'active_diagnostic_busy');
    });
    await expect(thrown.callback()({}, thrown.request)).rejects.toThrow(/busy/);
    expect(thrown.records[0]).toMatchObject({
      status: 'error', error_code: 'active_diagnostic_busy', result_size_bytes: 0
    });
  });

  it('generates a unique call ID for every invocation', async () => {
    const fixture = setup({ times: [0, 1, 2, 3] });
    register(fixture, async () => ok({ done: true }));
    await fixture.callback()({}, fixture.request);
    await fixture.callback()({}, fixture.request);
    expect(new Set(fixture.records.map(record => record.call_id)).size).toBe(2);
  });

  it('does not let telemetry write failure alter the tool result', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const registrar = instrumentToolRegistration(server, {
      writer: { write: async () => { throw new Error('unavailable'); } },
      routerProfile: 'tupik',
      serverVersion: '0.0.0-dev',
      onWriteError: () => { throw new Error('warning failed'); }
    });
    register({ registrar }, async () => fail(new Error('tool failed')));
    const result = await callback!({}, { mcpReq: { id: 1 } } as unknown as ServerContext);
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('tool failed');
  });

  it('does not wait for a stalled telemetry writer', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const registrar = instrumentToolRegistration(server, {
      writer: { write: () => new Promise(() => undefined) },
      routerProfile: 'tupik',
      serverVersion: '0.0.0-dev'
    });
    register({ registrar }, async () => ok({ done: true }));
    const outcome = await Promise.race([
      callback!({}, { mcpReq: { id: 1 } } as unknown as ServerContext).then(() => 'done'),
      new Promise<string>(resolve => setTimeout(() => resolve('timed-out'), 100))
    ]);
    expect(outcome).toBe('done');
  });

  it('does not let record-construction failures replace a successful result', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const writer = { write: vi.fn(async () => undefined) };
    const onWriteError = vi.fn();
    const registrar = instrumentToolRegistration(server, {
      writer,
      routerProfile: 'tupik',
      serverVersion: '0.0.0-dev',
      onWriteError
    });
    const original = {
      content: [{ type: 'text' as const, text: '{}' }],
      _meta: { unsupported: 1n }
    };
    register({ registrar }, async () => original);
    const returned = await callback!({}, { mcpReq: { id: 1 } } as unknown as ServerContext);
    expect(returned).toBe(original);
    expect(writer.write).not.toHaveBeenCalled();
    expect(onWriteError).toHaveBeenCalledOnce();
  });

  it('delivers the handler result when args or context cannot be summarized', async () => {
    let callback: Callback | undefined;
    const server = { registerTool: vi.fn((_name, _config, handler) => { callback = handler; }) } as
      unknown as McpServer;
    const onWriteError = vi.fn();
    const registrar = instrumentToolRegistration(server, {
      writer: { write: vi.fn(async () => undefined) },
      routerProfile: 'tupik',
      serverVersion: '0.0.0-dev',
      onWriteError
    });
    const original = ok({ done: true });
    register({ registrar }, async () => original);
    const hostileArgs = new Proxy({}, { ownKeys: () => { throw new Error('hostile'); } });
    const returned = await callback!(hostileArgs, {} as ServerContext);
    expect(returned).toBe(original);
    expect(onWriteError).toHaveBeenCalledOnce();
  });

  it('distinguishes active diagnostic resource failures', () => {
    expect(normalizeErrorCode(new ResourceError('busy', 'active_diagnostic_busy')))
      .toBe('active_diagnostic_busy');
    expect(normalizeErrorCode(new ResourceError('limited', 'active_diagnostic_rate_limited')))
      .toBe('active_diagnostic_rate_limited');
    expect(normalizeErrorCode(new ActiveDiagnosticUncertainError()))
      .toBe('active_diagnostic_uncertain');
  });
});
