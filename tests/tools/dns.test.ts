import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerDnsTools } from '../../src/tools/dns.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: any) => Promise<ToolResult>;

function setup() {
  const get = vi.fn(async () => ({ 'proxy-status': { enabled: true, status: 'up',
    server: [{ address: '192.0.2.53', protocol: 'DoT', status: 'up' }] } }));
  const getConfig = vi.fn(async (path: string) => ({ value: path === 'dns-proxy'
    ? { server: [{ url: 'https://resolver.example.test/dns-query?token=secret', protocol: 'DoH' }] }
    : { server: ['198.51.100.53'] }, bytes: 100 }));
  const client = { rci: { get, getConfig } } as unknown as KeeneticClient;
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, _config: never, handler: Handler) => {
    handlers[name] = handler;
    return {} as never;
  }) as never);
  registerDnsTools(server, { client, maxResponseBytes: 25_000, readOnly: true, backup: stubBackup() });
  return { handlers, get, getConfig };
}

const payload = (result: ToolResult): any => JSON.parse(result.content.map(part => part.text).join(''));

describe('DNS tools', () => {
  it('keeps get_dns_status compatible and applies an input bound', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['get_dns_status']!({}));
    expect(out).toMatchObject({ enabled: true, upstreamResolvers: [{ address: '192.0.2.53', protocol: 'DoT' }] });
    expect(fixture.get).toHaveBeenCalledWith('show/dns-proxy', 128_000);
  });

  it('lists separate runtime and configured observations and cleans endpoint secrets', async () => {
    const fixture = setup();
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.schemaVersion).toBe(1);
    expect(out.upstreams.map((item: any) => item.source)).toEqual([
      'runtime', 'dns-proxy-config', 'name-server-config'
    ]);
    expect(out.upstreams[1].endpoint).toBe('https://resolver.example.test/dns-query');
    expect(JSON.stringify(out)).not.toContain('token=secret');
    expect(fixture.getConfig.mock.calls).toEqual([['dns-proxy', 128_000], ['ip/name-server', 128_000]]);
  });

  it('preserves a successful source when another config branch is unavailable', async () => {
    const fixture = setup();
    fixture.getConfig.mockRejectedValueOnce(new RciError('missing', {
      path: 'dns-proxy', code: '404', ident: 'http'
    })).mockResolvedValueOnce({ value: { server: ['198.51.100.53'] }, bytes: 100 });
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.sources['dns-proxy-config'].status).toBe('unavailable');
    expect(out.sources['name-server-config'].status).toBe('available');
    expect(out.upstreams.map((item: any) => item.source)).toContain('name-server-config');
  });

  it.each([new AuthError('rejected'), new TransportError('offline')])(
    'stops immediately after a session-level config failure', async error => {
      const fixture = setup();
      fixture.getConfig.mockRejectedValueOnce(error);
      const result = await fixture.handlers['list_dns_upstreams']!({ limit: 50 });
      expect(result.isError).toBe(true);
      expect(fixture.getConfig).toHaveBeenCalledTimes(1);
    }
  );

  it('marks an unknown configuration shape unavailable', async () => {
    const fixture = setup();
    fixture.get.mockResolvedValue({ unexpected: true } as never);
    fixture.getConfig.mockResolvedValue({ value: { unexpected: true } as never, bytes: 10 });
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.sources['dns-proxy-config'].reason).toBe('unexpected-response');
    expect(out.sources['name-server-config'].reason).toBe('unexpected-response');
    expect(out.sources.runtime.reason).toBe('unexpected-response');
  });

  it('reports successfully read empty upstream arrays as available', async () => {
    const fixture = setup();
    fixture.get.mockResolvedValue({ 'proxy-status': [{ 'proxy-name': 'System',
      'proxy-tls': { 'server-tls': [] }, 'proxy-https': { 'server-https': [] } }] } as never);
    fixture.getConfig.mockImplementation(async (path: string): Promise<any> => ({ value: path === 'dns-proxy'
      ? { tls: { upstream: [] }, https: { upstream: [] } }
      : [], bytes: 2 }));
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.sources).toEqual({
      runtime: { status: 'available', reason: null },
      'dns-proxy-config': { status: 'available', reason: null },
      'name-server-config': { status: 'available', reason: null }
    });
    expect(out.upstreams).toEqual([]);
  });

  it('rejects a mixed keyed resolver map instead of dropping its malformed child', async () => {
    const fixture = setup();
    fixture.getConfig.mockResolvedValue({ value: { server: {
      good: { address: '192.0.2.53' }, bad: { unexpected: 'not-a-resolver' }
    } } as never, bytes: 100 });
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.sources['dns-proxy-config'].reason).toBe('unexpected-response');
    expect(out.sources['name-server-config'].reason).toBe('unexpected-response');
    expect(out.upstreams).toHaveLength(1);
  });

  it.each([
    { server: { one: { address: [] } } },
    { server: { one: { status: [] } } },
    { server: [53] },
    { enabled: [] },
    { status: [] }
  ])('rejects wrong resolver and proxy field types %#', async malformed => {
    const fixture = setup();
    fixture.getConfig.mockResolvedValue({ value: malformed as never, bytes: 20 });
    const out = payload(await fixture.handlers['list_dns_upstreams']!({ limit: 50 }));
    expect(out.sources['dns-proxy-config'].reason).toBe('unexpected-response');
    expect(out.sources['name-server-config'].reason).toBe('unexpected-response');
  });
});
