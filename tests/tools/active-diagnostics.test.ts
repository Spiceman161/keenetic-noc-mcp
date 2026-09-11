import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerActiveDiagnosticTools } from '../../src/tools/active-diagnostics.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>, context: unknown) => Promise<ToolResult>;

function setup() {
  const runContinued = vi.fn(async () => ({
    messages: ['1 packets transmitted, 1 packets received, 0% packet loss'], bytes: 64, polls: 1,
    termination: 'completed' as const, effectiveTimeoutMs: 4_000
  }));
  const client = { rci: { runContinued } } as unknown as KeeneticClient;
  const backup = stubBackup();
  const audit = { write: vi.fn(async () => undefined) };
  const ctx: ToolContext = { client, maxResponseBytes: 25_000, readOnly: true, backup, audit };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, any> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, config: unknown, handler: Handler) => {
    handlers[name] = handler;
    configs[name] = config;
    return {} as never;
  }) as never);
  registerActiveDiagnosticTools(server, ctx);
  const controller = new AbortController();
  const request = { mcpReq: { signal: controller.signal } };
  return { handlers, configs, runContinued, backup, audit, request, controller };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(item => item.text).join(''));
}

describe('active diagnostic tools', () => {
  it('runs a bounded ping, forwards cancellation, and never invokes mutation services', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['ping']!({ target: 'example.test', family: 'ipv4',
      count: 3, timeout_ms: 5_000 }, fixture.request));
    expect(out).toMatchObject({ schemaVersion: 1, operation: 'ping', status: 'completed',
      limitsApplied: { timeoutMs: 4_000 }, untrustedRouterData: true });
    expect(fixture.runContinued).toHaveBeenCalledWith('tools/ping',
      { host: 'example.test', packetsize: 84, count: 3 }, 64_000,
      { signal: fixture.controller.signal, timeoutMs: 5_000 });
    expect(fixture.backup.ensure).not.toHaveBeenCalled();
    expect(fixture.audit.write).not.toHaveBeenCalled();
  });

  it('validates before making a router request', async () => {
    const fixture = setup();
    const result = await fixture.handlers['ping']!({ target: 'example.test;bad', family: 'ipv4',
      count: 3, timeout_ms: 5_000 }, fixture.request);
    expect(result.isError).toBe(true);
    expect(fixture.runContinued).not.toHaveBeenCalled();
  });

  it('does not charge invalid targets against the active start rate', async () => {
    const fixture = setup();
    for (let index = 0; index < 11; index += 1) {
      const result = await fixture.handlers['ping']!({ target: `bad;${index}`, family: 'ipv4',
        count: 3, timeout_ms: 5_000 }, fixture.request);
      expect(result.isError).toBe(true);
    }
    const valid = await fixture.handlers['ping']!({ target: 'example.test', family: 'ipv4',
      count: 3, timeout_ms: 5_000 }, fixture.request);
    expect(valid.isError).not.toBe(true);
    expect(fixture.runContinued).toHaveBeenCalledOnce();
  });

  it('advertises active, open-world, non-destructive contracts', () => {
    const fixture = setup();
    for (const name of ['ping', 'traceroute']) {
      expect(fixture.configs[name].annotations).toEqual({ readOnlyHint: true,
        destructiveHint: false, idempotentHint: false, openWorldHint: true });
    }
    expect(fixture.configs.ping.inputSchema.count._def.type).toBe('default');
  });
});
