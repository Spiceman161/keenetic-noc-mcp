import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { createServer } from '../src/index.js';
import type { ToolContext } from '../src/tools/registry.js';
import type { KeeneticClient } from '../src/router/client.js';
import { stubBackup } from './helpers/backup.js';

// Local filesystem writes count as writes even when the router is unchanged.
const READ_TOOLS = [
  'rci_call',
  'diagnose_internet',
  'diagnose_dns',
  'diagnose_device',
  'diagnose_wifi',
  'get_wifi_client_health',
  'ping',
  'traceroute',
  'get_config_state',
  'get_connection_status',
  'get_device',
  'get_interface',
  'get_internet_status',
  'get_dns_status',
  'list_dns_upstreams',
  'get_logs',
  'get_logs_by_device',
  'get_config_diff',
  'get_running_config',
  'get_startup_config',
  'search_config',
  'get_system_info',
  'get_wifi_status',
  'get_vpn',
  'list_devices',
  'list_interfaces',
  'list_policies',
  'list_routes', 'list_vpn',
  'list_segments'
];

const WRITE_TOOLS = [
  'backup_config',
  'set_interface_state',
  'restart_interface',
  'save_config',
];

function context(readOnly: boolean): ToolContext {
  const client = {
    rci: { get: vi.fn(async () => ({})), post: vi.fn(), getText: vi.fn() },
    capabilities: vi.fn(async () => ({
      model: 'Keenetic Model (KN-0000)',
      hwId: 'KN-0000',
      firmware: '5.1.3',
      components: new Set<string>(),
      features: new Set<string>()
    }))
  } as unknown as KeeneticClient;
  return { client, maxResponseBytes: 25_000, readOnly, backup: stubBackup() };
}

/** Speaks real MCP to the assembled server over a linked in-memory transport. */
async function connectedClient(readOnly = false): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer(context(readOnly));
  await server.connect(serverTransport);

  const client = new Client({ name: 'protocol-test', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

describe('assembled server over MCP', () => {
  it('advertises every read tool', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    for (const name of READ_TOOLS) {
      expect(tools.map(t => t.name)).toContain(name);
    }
  });

  it('gives every tool a description a model can select on', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    for (const tool of tools) {
      expect(tool.description, `${tool.name} has no description`).toBeTruthy();
      expect(tool.description!.length, `${tool.name} description is too short`).toBeGreaterThan(60);
    }
  });

  it('returns a tool result through a real tools/call round trip', async () => {
    const client = await connectedClient();
    const result = await client.callTool({ name: 'get_system_info', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    const payload = JSON.parse(content.map(part => part.text).join(''));
    expect(payload.model).toBe('Keenetic Model (KN-0000)');
  });

  /**
   * `z.unknown()` emits a property with no `type` and no `anyOf`. A client with
   * nothing to go on may then serialise the argument to a string, and every
   * POST silently became a no-op. The advertised schema has to describe the
   * shape, so this asserts on the manifest rather than on the handler.
   */
  it('advertises a typed schema for the rci_call body', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    const body = (tools.find(t => t.name === 'rci_call')?.inputSchema.properties as
      | Record<string, Record<string, unknown>>
      | undefined)?.['body'];

    expect(body, 'rci_call must advertise a body property').toBeDefined();
    expect(
      body!['type'] ?? body!['anyOf'] ?? body!['oneOf'],
      'body must carry type information, or a client cannot tell what to send'
    ).toBeDefined();
  });

  it('advertises narrow configuration schemas', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    const running = tools.find(tool => tool.name === 'get_running_config')?.inputSchema;
    const startup = tools.find(tool => tool.name === 'get_startup_config')?.inputSchema;
    const search = tools.find(tool => tool.name === 'search_config')?.inputSchema;
    const diff = tools.find(tool => tool.name === 'get_config_diff')?.inputSchema;
    expect(running?.required).toContain('section');
    expect((running?.properties as any)?.format?.default).toBe('cli');
    expect((startup?.properties as any)?.format?.const).toBe('cli');
    expect(search?.required).toEqual(expect.arrayContaining(['source', 'query']));
    expect((diff?.properties as any)?.include_diff?.default).toBe(false);
    expect((diff?.properties as any)?.limit).toMatchObject({ default: 200, minimum: 1,
      maximum: 1000 });
  });

  it('advertises and calls the zero-argument internet diagnostic over MCP', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const tool = tools.find(item => item.name === 'diagnose_internet');
    expect(tool?.inputSchema).toMatchObject({ type: 'object', properties: {} });
    expect(tool?.annotations?.readOnlyHint).toBe(true);

    const result = await client.callTool({ name: 'diagnose_internet', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content.map(part => part.text).join(''))).toMatchObject({ schemaVersion: 1 });
  });

  it('advertises the DNS diagnostic contracts as read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const diagnostic = tools.find(item => item.name === 'diagnose_dns');
    const list = tools.find(item => item.name === 'list_dns_upstreams');
    expect(diagnostic?.inputSchema).toMatchObject({ type: 'object', properties: {} });
    expect(diagnostic?.annotations?.readOnlyHint).toBe(true);
    expect((list?.inputSchema.properties as any)?.limit).toMatchObject({ default: 50, minimum: 1, maximum: 100 });
    expect(list?.annotations?.readOnlyHint).toBe(true);
  });

  it('advertises the device diagnostic contract as read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const diagnostic = tools.find(item => item.name === 'diagnose_device');
    const alternatives = (diagnostic?.inputSchema.anyOf ?? diagnostic?.inputSchema.oneOf) as
      | Array<{ required?: string[] }>
      | undefined;
    expect(alternatives?.map(value => value.required?.[0]).sort()).toEqual(['ip', 'mac', 'name']);
    expect(diagnostic?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
  });

  it('advertises the Wi-Fi diagnostic contracts as read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const aggregate = tools.find(item => item.name === 'diagnose_wifi');
    const selected = tools.find(item => item.name === 'get_wifi_client_health');
    expect(aggregate?.inputSchema).toMatchObject({ type: 'object', properties: {} });
    const alternatives = (selected?.inputSchema.anyOf ?? selected?.inputSchema.oneOf) as
      | Array<{ required?: string[] }> | undefined;
    expect(alternatives?.map(value => value.required?.[0]).sort()).toEqual(['ip', 'mac', 'name']);
    for (const tool of [aggregate, selected]) {
      expect(tool?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    }
  });

  it('enforces the device selector alternatives over MCP', async () => {
    const client = await connectedClient(true);
    const empty = await client.callTool({ name: 'diagnose_device', arguments: {} });
    const multiple = await client.callTool({ name: 'diagnose_device', arguments: {
      mac: '02:00:00:00:00:01', ip: '192.0.2.5'
    } });
    const one = await client.callTool({ name: 'diagnose_device', arguments: { name: 'device-1' } });
    expect(empty.isError).toBe(true);
    expect(multiple.isError).toBe(true);
    expect(one.isError).toBe(true);
    const text = (result: typeof one): string => JSON.stringify(result.content);
    expect(text(empty)).toMatch(/invalid.*argument/i);
    expect(text(multiple)).toMatch(/invalid.*argument/i);
    expect(text(one)).not.toMatch(/invalid.*argument/i);
  });

  it('enforces the Wi-Fi client selector alternatives over MCP', async () => {
    const client = await connectedClient(true);
    const empty = await client.callTool({ name: 'get_wifi_client_health', arguments: {} });
    const multiple = await client.callTool({ name: 'get_wifi_client_health', arguments: {
      mac: '02:00:00:00:00:01', ip: '192.0.2.5'
    } });
    const one = await client.callTool({ name: 'get_wifi_client_health', arguments: { name: 'device-1' } });
    expect(empty.isError).toBe(true);
    expect(multiple.isError).toBe(true);
    expect(one.isError).toBe(true);
    const text = (result: typeof one): string => JSON.stringify(result.content);
    expect(text(empty)).toMatch(/invalid.*argument/i);
    expect(text(multiple)).toMatch(/invalid.*argument/i);
    expect(text(one)).not.toMatch(/invalid.*argument/i);
  });

  it('advertises narrow active diagnostic contracts', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const ping = tools.find(item => item.name === 'ping');
    const trace = tools.find(item => item.name === 'traceroute');
    expect(ping?.inputSchema.required).toContain('target');
    expect((ping?.inputSchema.properties as any)?.count).toMatchObject({ default: 3,
      minimum: 1, maximum: 5 });
    expect((trace?.inputSchema.properties as any)?.max_hops).toMatchObject({ default: 15,
      minimum: 1, maximum: 30 });
    for (const tool of [ping, trace]) {
      expect(tool?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false,
        idempotentHint: false, openWorldHint: true });
    }
  });
});

describe('read-only mode', () => {
  it('advertises exactly the read tools and nothing else', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual([...READ_TOOLS].sort());
  });

  it('marks every advertised tool read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint, `${tool.name} must be read-only`).toBe(true);
    }
  });
});

describe('write mode', () => {
  it('advertises the write tools', async () => {
    const client = await connectedClient(false);
    const { tools } = await client.listTools();
    for (const name of WRITE_TOOLS) {
      expect(tools.map(t => t.name)).toContain(name);
    }
  });

  it('advertises exactly the documented read and write tools', async () => {
    const client = await connectedClient(false);
    const { tools } = await client.listTools();
    expect(tools.map(tool => tool.name).sort()).toEqual([...READ_TOOLS, ...WRITE_TOOLS].sort());
  });

  it('marks every write tool destructive rather than read-only', async () => {
    const client = await connectedClient(false);
    const { tools } = await client.listTools();
    for (const name of WRITE_TOOLS) {
      const tool = tools.find(t => t.name === name);
      expect(tool?.annotations?.readOnlyHint, `${name} must not be read-only`).toBe(false);
      expect(tool?.annotations?.destructiveHint, `${name} must be destructive`).toBe(true);
    }
  });

  it('keeps configuration readers annotated read-only in write mode', async () => {
    const client = await connectedClient(false);
    const { tools } = await client.listTools();
    for (const name of ['get_running_config', 'get_startup_config', 'search_config',
      'get_config_diff']) {
      expect(tools.find(tool => tool.name === name)?.annotations?.readOnlyHint).toBe(true);
    }
  });
});
