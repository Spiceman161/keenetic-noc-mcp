import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { createServer } from '../src/index.js';
import type { ToolContext } from '../src/tools/registry.js';
import type { KeeneticClient } from '../src/router/client.js';
import { stubBackup } from './helpers/backup.js';
import type { TelemetryRecord } from '../src/telemetry/record.js';
import { AuthError, RciError, TransportError } from '../src/router/errors.js';

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
  'compare_router_state',
  'get_recent_changes',
  'get_running_config',
  'get_startup_config',
  'search_config',
  'get_system_info',
  'get_wifi_status',
  'get_vpn',
  'get_wireguard_status',
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

function context(
  readOnly: boolean,
  interfaceResponse: unknown = {},
  options: { interfaceError?: unknown; maxResponseBytes?: number } = {}
): ToolContext {
  const client = {
    rci: { get: vi.fn(async (path: string) => path === 'show/version'
      ? { title: '5.1.3', model: 'Keenetic Model (KN-0000)', hw_id: 'KN-0000' }
      : path === 'show/interface'
        ? (() => {
          if (options.interfaceError !== undefined) throw options.interfaceError;
          return interfaceResponse;
        })()
        : {}), post: vi.fn(), getText: vi.fn() },
    capabilities: vi.fn(async () => ({
      model: 'Keenetic Model (KN-0000)',
      hwId: 'KN-0000',
      firmware: '5.1.3',
      components: new Set<string>(),
      features: new Set<string>()
    }))
  } as unknown as KeeneticClient;
  return {
    client,
    maxResponseBytes: options.maxResponseBytes ?? 25_000,
    readOnly,
    backup: stubBackup(),
    allowRawWrite: false
  };
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

async function connectedTelemetryClient(
  options: {
    routerId?: string;
    readOnly?: boolean;
    interfaceResponse?: unknown;
    interfaceError?: unknown;
    maxResponseBytes?: number;
  } = { routerId: 'tupik' }
): Promise<{ client: Client; records: TelemetryRecord[] }> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const records: TelemetryRecord[] = [];
  const ctx = context(options.readOnly ?? true, options.interfaceResponse, {
    ...(options.interfaceError === undefined ? {} : { interfaceError: options.interfaceError }),
    ...(options.maxResponseBytes === undefined ? {} : { maxResponseBytes: options.maxResponseBytes })
  });
  if (options.routerId !== undefined) ctx.routerId = options.routerId;
  const server = createServer(ctx, { writer: { write: async record => { records.push(record); } } });
  await server.connect(serverTransport);
  const client = new Client({ name: 'telemetry-protocol-test', version: '0.0.0' });
  await client.connect(clientTransport);
  return { client, records };
}

describe('assembled server over MCP', () => {
  it('does not add call metadata or records when telemetry is disabled', async () => {
    const client = await connectedClient(true);
    const result = await client.callTool({ name: 'get_system_info', arguments: {} });
    expect(result._meta).toBeUndefined();
  });

  it('records a successful real MCP round trip and exposes its call ID as metadata', async () => {
    const { client, records } = await connectedTelemetryClient();
    const result = await client.callTool({ name: 'get_system_info', arguments: {} });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      router_profile: 'tupik', tool: 'get_system_info', status: 'success'
    });
    expect((result._meta?.['io.github.spiceman161/telemetry'] as { call_id: string }).call_id)
      .toBe(records[0]!.call_id);
  });

  it('does not invent a profile when an embedded context omits routerId', async () => {
    const { client, records } = await connectedTelemetryClient({});
    await client.callTool({ name: 'get_system_info', arguments: {} });
    expect(records[0]?.router_profile).toBe('unknown');
  });

  it('records handler validation failures but not SDK schema rejections', async () => {
    const { client, records } = await connectedTelemetryClient();
    const handlerFailure = await client.callTool({
      name: 'ping',
      arguments: { target: 'invalid;target', family: 'ipv4', count: 3, timeout_ms: 5_000 }
    });
    expect(handlerFailure.isError).toBe(true);
    expect(records[0]).toMatchObject({ status: 'error', error_code: 'validation' });

    const schemaFailure = await client.callTool({
      name: 'ping',
      arguments: { target: 'example.test', count: 'three' }
    });
    expect(schemaFailure.isError).toBe(true);
    expect(records).toHaveLength(1);
  });

  it('classifies representative caller and policy failures without internal errors', async () => {
    const { client, records } = await connectedTelemetryClient({
      routerId: 'tupik', readOnly: false
    });
    const calls = [
      client.callTool({ name: 'rci_call', arguments: { method: 'GET' } }),
      client.callTool({ name: 'get_device', arguments: {} }),
      client.callTool({
        name: 'backup_config',
        arguments: { path: 'relative.txt', dry_run: false, confirm: true }
      }),
      client.callTool({ name: 'rci_call', arguments: { method: 'POST', body: {} } })
    ];
    const results = await Promise.all(calls);
    expect(results.every(result => result.isError === true)).toBe(true);
    expect(records.map(record => record.error_code)).toEqual(expect.arrayContaining([
      'validation', 'validation', 'validation', 'guard_refusal'
    ]));
    expect(records.some(record => record.error_code === 'internal')).toBe(false);
  });

  it('records concurrent real MCP calls as distinct calls', async () => {
    const { client, records } = await connectedTelemetryClient();
    await Promise.all(Array.from({ length: 8 }, () => client.callTool({
      name: 'get_system_info', arguments: {}
    })));
    expect(records).toHaveLength(8);
    expect(new Set(records.map(record => record.call_id)).size).toBe(8);
  });

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

  it('advertises bounded local state-comparison contracts as read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const compare = tools.find(tool => tool.name === 'compare_router_state');
    const recent = tools.find(tool => tool.name === 'get_recent_changes');
    expect((compare?.inputSchema.properties as any)?.from_at?.format).toBe('date-time');
    expect((compare?.inputSchema.properties as any)?.domains?.maxItems).toBe(8);
    expect((recent?.inputSchema.properties as any)?.limit).toMatchObject({
      default: 10, minimum: 1, maximum: 50
    });
    for (const tool of [compare, recent]) {
      expect(tool?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    }

    const result = await client.callTool({ name: 'compare_router_state', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content.map(part => part.text).join(''))).toMatchObject({
      schemaVersion: 1, status: 'indeterminate', correlationOnly: true,
      uncertainty: ['history-unavailable']
    });
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

  it('advertises the zero-argument WireGuard runtime evidence contract as read-only', async () => {
    const client = await connectedClient(true);
    const { tools } = await client.listTools();
    const tool = tools.find(item => item.name === 'get_wireguard_status');
    expect(tool?.inputSchema).toMatchObject({ type: 'object', properties: {} });
    expect(tool?.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    expect(tool?.description).toContain('authoritative handshake-age seconds');
    expect(tool?.description).toContain('declared endpoint');
    expect(tool?.description).toContain('nullable enabled/online observations');

    const result = await client.callTool({ name: 'get_wireguard_status', arguments: {} });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content.map(part => part.text).join(''))).toMatchObject({
      schemaVersion: 1, evidenceStatus: 'unavailable', evidenceReason: 'unexpected-response'
    });
  });

  it('keeps WireGuard sentinels out of real MCP telemetry for every status, error, and truncation path', async () => {
    const sentinels = [
      'SYNTHETIC_PRIVATE_KEY', 'SYNTHETIC_PSK', 'SYNTHETIC_PUBLIC_KEY', 'SYNTHETIC_PEER_ID',
      'SYNTHETIC_COLLECTION_KEY', 'SYNTHETIC_ENDPOINT', 'SYNTHETIC_ALLOWED_RANGE',
      'SYNTHETIC_RAW_PEER_OBJECT', 'SYNTHETIC_STABLE_ID', 'SYNTHETIC_HASH', 'SYNTHETIC_FINGERPRINT'
    ];
    const peer = () => ({
      'preshared-key': sentinels[1], 'public-key': sentinels[2], id: sentinels[3],
      endpoint: sentinels[5], 'allowed-ips': [sentinels[6]], raw: sentinels[7],
      stable: sentinels[8], hash: sentinels[9], fingerprint: sentinels[10],
      'last-handshake': 1, rxbytes: 0, txbytes: 1
    });
    const source = (peerCount = 1) => ({
      Wireguard0: {
        type: 'Wireguard', wireguard: {
          'private-key': sentinels[0],
          peer: Object.fromEntries(Array.from({ length: peerCount }, (_, index) => [
            `${sentinels[4]}_${index}`, peer()
          ]))
        }
      }
    });
    const errorText = `private-key=${sentinels.join(':')}`;
    const cases: Array<[
      string,
      Parameters<typeof connectedTelemetryClient>[0],
      { isError?: true; errorCode: string | null; outputTruncated?: boolean; peersTruncated?: boolean }
    ]> = [
      ['complete', { interfaceResponse: source() }, { errorCode: null }],
      ['partial', { interfaceResponse: { Wireguard0: { type: 'Wireguard', wireguard: { 'private-key': sentinels[0], peer: [peer(), true] } } } }, { errorCode: null }],
      ['unavailable', { interfaceResponse: [source()] }, { errorCode: null }],
      ['malformed', { interfaceResponse: { Wireguard0: { type: 'Wireguard', wireguard: [sentinels], peer: [peer()] } } }, { errorCode: null }],
      ['rci', { interfaceError: new RciError(errorText, { path: 'show/interface', code: '404', ident: 'rci' }) }, { errorCode: null }],
      ['auth', { interfaceError: new AuthError(errorText) }, { isError: true, errorCode: 'authentication' }],
      ['transport', { interfaceError: new TransportError(errorText) }, { isError: true, errorCode: 'transport' }],
      ['peer truncation', { interfaceResponse: source(101) }, { errorCode: null, peersTruncated: true }],
      ['interface truncation', { interfaceResponse: Object.fromEntries(Array.from({ length: 101 }, (_, index) => [
        `Wireguard${index}`, source().Wireguard0
      ])) }, { errorCode: null, outputTruncated: true }],
      ['512-byte budget', { interfaceResponse: source(101), maxResponseBytes: 512 }, { errorCode: null, outputTruncated: true }]
    ];

    for (const [_label, options, expected] of cases) {
      const { client, records } = await connectedTelemetryClient(options);
      const result = await client.callTool({ name: 'get_wireguard_status', arguments: {} });
      const publicText = (result.content as Array<{ type: string; text: string }>)
        .map(part => part.text).join('');
      expect(result.isError).toBe(expected.isError ?? undefined);
      expect(records).toHaveLength(1);
      expect(records[0]).toMatchObject({
        tool: 'get_wireguard_status', status: expected.isError ? 'error' : 'success',
        error_code: expected.errorCode,
        tool_attributes: { read_only: true, open_world: false },
        args_summary: { fields: {}, total_fields: 0, truncated: false }
      });
      if (expected.outputTruncated !== undefined) {
        expect(records[0]?.output_truncated).toBe(expected.outputTruncated);
      }
      if (expected.peersTruncated === true) {
        expect(publicText).toContain('"peersTruncated":true');
      }
      expect(publicText).toContain(expected.isError ? 'router' : 'peersObserved');
      for (const sentinel of sentinels) {
        expect(publicText).not.toContain(sentinel);
        expect(JSON.stringify(records)).not.toContain(sentinel);
      }
    }
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
      'get_config_diff', 'compare_router_state', 'get_recent_changes']) {
      expect(tools.find(tool => tool.name === name)?.annotations?.readOnlyHint).toBe(true);
    }
  });

  it('advertises and passively calls WireGuard evidence in write mode', async () => {
    const source = { Wireguard0: { type: 'Wireguard', wireguard: { peer: [{ 'last-handshake': 1 }] } } };
    const ctx = context(false, source);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer(ctx);
    await server.connect(serverTransport);
    const client = new Client({ name: 'wireguard-write-mode-test', version: '0.0.0' });
    await client.connect(clientTransport);

    const { tools } = await client.listTools();
    const tool = tools.find(item => item.name === 'get_wireguard_status');
    expect(tool?.annotations).toEqual({ readOnlyHint: true, openWorldHint: false });
    const result = await client.callTool({ name: 'get_wireguard_status', arguments: {} });
    expect(JSON.stringify(result)).toContain('peersObserved');
    const rci = ctx.client.rci as unknown as { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
    expect(rci.get.mock.calls).toEqual([['show/interface', 256_000]]);
    expect(rci.post).not.toHaveBeenCalled();
    expect((ctx.backup.ensure as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled();
  });
});
