import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import type { KeeneticClient } from '../../src/router/client.js';
import { RciError } from '../../src/router/errors.js';
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
      limitsApplied: { family: 'ipv4', count: 3, timeoutMs: 4_000 }, untrustedRouterData: true });
    expect(out.limitsApplied).toEqual({ family: 'ipv4', count: 3, timeoutMs: 4_000 });
    expect(out.limitsApplied).not.toHaveProperty('sourceInterface');
    expect(fixture.runContinued).toHaveBeenCalledWith('tools/ping',
      { host: 'example.test', packetsize: 84, count: 3 }, 64_000,
      { signal: fixture.controller.signal, timeoutMs: 5_000 });
    expect(fixture.backup.ensure).not.toHaveBeenCalled();
    expect(fixture.audit.write).not.toHaveBeenCalled();
  });

  it('preserves the unbound IPv6 request and report contract', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['ping']!({ target: '2001:db8::1', family: 'ipv6',
      count: 2, timeout_ms: 5_000 }, fixture.request));
    expect(fixture.runContinued).toHaveBeenCalledOnce();
    expect(fixture.runContinued).toHaveBeenCalledWith('tools/ping6',
      { host: '2001:db8::1', packetsize: 84, count: 2 }, 64_000,
      { signal: fixture.controller.signal, timeoutMs: 5_000 });
    expect(out.limitsApplied).toEqual({ family: 'ipv6', count: 2, timeoutMs: 4_000 });
    expect(out.limitsApplied).not.toHaveProperty('sourceInterface');
  });

  it('runs sourced IPv4 through the existing bounded job and reports only the requested source', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['ping']!({ target: '192.0.2.1', family: 'ipv4',
      source_interface: 'Wireguard0', count: 2, timeout_ms: 5_000 }, fixture.request));
    expect(fixture.runContinued).toHaveBeenCalledOnce();
    expect(fixture.runContinued).toHaveBeenCalledWith('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 2, 'source-interface': 'Wireguard0' }, 64_000,
      { signal: fixture.controller.signal, timeoutMs: 5_000 });
    expect(out).toMatchObject({ schemaVersion: 1, operation: 'ping', target: '192.0.2.1',
      status: 'completed', limitsApplied: { family: 'ipv4', count: 2, timeoutMs: 4_000,
        sourceInterface: 'Wireguard0' },
      untrustedRouterData: true });
    expect(fixture.backup.ensure).not.toHaveBeenCalled();
    expect(fixture.audit.write).not.toHaveBeenCalled();
  });

  it('rejects invalid source or IPv6 binding locally without charging a start', async () => {
    const fixture = setup();
    for (let index = 0; index < 11; index += 1) {
      const result = await fixture.handlers['ping']!({ target: 'example.test', family: 'ipv4',
        source_interface: `Wireguard0;${index}`, count: 2, timeout_ms: 5_000 }, fixture.request);
      expect(result.isError).toBe(true);
    }
    const ipv6 = await fixture.handlers['ping']!({ target: '2001:db8::1', family: 'ipv6',
      source_interface: 'Wireguard0', count: 2, timeout_ms: 5_000 }, fixture.request);
    expect(ipv6.isError).toBe(true);
    expect(fixture.runContinued).not.toHaveBeenCalled();
    const valid = await fixture.handlers['ping']!({ target: 'example.test', family: 'ipv4',
      source_interface: 'Wireguard0', count: 2, timeout_ms: 5_000 }, fixture.request);
    expect(valid.isError).not.toBe(true);
    expect(fixture.runContinued).toHaveBeenCalledOnce();
  });

  it('propagates router selector rejection without retrying unbound', async () => {
    const fixture = setup();
    fixture.runContinued.mockRejectedValueOnce(new RciError('unknown interface', {
      path: 'tools/ping', code: '6553609', ident: 'Network::Interface::Ip'
    }));
    const rejected = await fixture.handlers['ping']!({ target: 'example.test', family: 'ipv4',
      source_interface: 'WireguardUnknown', count: 2, timeout_ms: 5_000 }, fixture.request);
    expect(rejected.isError).toBe(true);
    expect(rejected.content[0]?.text).toContain('6553609');
    expect(fixture.runContinued).toHaveBeenCalledOnce();
    expect(fixture.runContinued).toHaveBeenCalledWith('tools/ping',
      { host: 'example.test', packetsize: 84, count: 2, 'source-interface': 'WireguardUnknown' },
      64_000, { signal: fixture.controller.signal, timeoutMs: 5_000 });
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
