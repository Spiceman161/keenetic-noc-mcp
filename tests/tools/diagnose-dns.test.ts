import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { registerDnsDiagnosticTool } from '../../src/tools/diagnose-dns.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, never>) => Promise<ToolResult>;

const VALUES: Record<string, unknown> = {
  'show/version': { model: 'Keenetic Test', title: '5.1.4' },
  'show/internet/status': { checked: true, enabled: true, reliable: true,
    'gateway-accessible': true, 'dns-accessible': true, internet: true },
  'show/dns-proxy': { 'proxy-status': { enabled: true, status: 'up',
    server: [{ address: '192.0.2.53', protocol: 'DoT', status: 'up' }] } },
  'show/ip/route': [{ destination: '0.0.0.0/0', interface: 'GigabitEthernet1' }],
  'show/interface': { GigabitEthernet1: { link: 'up', state: 'up' } }
};

function setup(options: { failures?: Record<string, Error>; configFailures?: Record<string, Error> } = {}) {
  const order: string[] = [];
  const get = vi.fn(async (path: string, _maxBytes?: number) => {
    order.push(path);
    const failure = options.failures?.[path];
    if (failure) throw failure;
    return VALUES[path];
  });
  const getConfig = vi.fn(async (path: string, _maxBytes?: number) => {
    order.push(path);
    const failure = options.configFailures?.[path];
    if (failure) throw failure;
    return { value: path === 'dns-proxy' ? { server: [{ url: 'https://resolver.example.test/dns-query',
      protocol: 'DoH' }] } : { server: ['198.51.100.53'] }, bytes: 100 };
  });
  const post = vi.fn(async () => {
    order.push('show/log');
    return { show: { log: { log: { '1': { ident: 'dns-proxy', message: { message: 'upstream ready' } } } } } };
  });
  const client = { rci: { get, getConfig, post } } as unknown as KeeneticClient;
  const ctx: ToolContext = { client, maxResponseBytes: 25_000, readOnly: true, backup: stubBackup() };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  let handler: Handler | undefined;
  let config: { annotations?: { readOnlyHint?: boolean } } | undefined;
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, value: never, callback: Handler) => {
    if (name === 'diagnose_dns') { handler = callback; config = value; }
    return {} as never;
  }) as never);
  registerDnsDiagnosticTool(server, ctx);
  return { handler: handler!, config: config!, get, getConfig, post, order };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

describe('diagnose_dns', () => {
  it('returns a stable report using bounded sequential reads with logs last', async () => {
    const fixture = setup();
    const out = payload(await fixture.handler({}));
    expect(out).toMatchObject({ schemaVersion: 1, status: 'healthy', complete: true,
      untrustedRouterData: true, truncated: false });
    expect(out.checks.find((item: any) => item.id === 'routing').status).toBe('unknown');
    expect(out.checks.map((item: any) => item.id)).toEqual([
      'proxy-runtime', 'internet-dns-reachability', 'upstream-configuration',
      'encryption', 'routing', 'recent-logs'
    ]);
    expect(fixture.order).toEqual(['show/version', 'show/internet/status', 'show/dns-proxy',
      'dns-proxy', 'ip/name-server', 'show/ip/route', 'show/interface', 'show/log']);
    for (const call of fixture.get.mock.calls) expect(call[1]).toEqual(expect.any(Number));
    expect(fixture.getConfig.mock.calls).toEqual([['dns-proxy', 128_000], ['ip/name-server', 128_000]]);
    expect(fixture.post).toHaveBeenCalledWith({ show: { log: {} } }, 2_000_000);
    expect(fixture.config.annotations?.readOnlyHint).toBe(true);
  });

  it('preserves one configuration branch after an RCI failure in its sibling', async () => {
    const fixture = setup({ configFailures: { 'ip/name-server': new RciError('missing', {
      path: 'ip/name-server', code: '404', ident: 'http' }) } });
    const out = payload(await fixture.handler({}));
    expect(out.evidence.dnsProxyConfig.status).toBe('available');
    expect(out.evidence.nameServerConfig).toMatchObject({ status: 'unavailable', reason: 'rci-error' });
    expect(out.evidence.dnsProxyConfig.data.items[0].endpoint).toBe('https://resolver.example.test/dns-query');
  });

  it('latches a transport failure and makes no later router requests', async () => {
    const fixture = setup({ failures: { 'show/dns-proxy': new TransportError('offline') } });
    const out = payload(await fixture.handler({}));
    expect(fixture.order).toEqual(['show/version', 'show/internet/status', 'show/dns-proxy']);
    expect(out.evidence.proxyRuntime.reason).toBe('transport-error');
    expect(out.evidence.logs.reason).toBe('transport-error');
  });

  it('treats authentication loss as a fatal guarded error', async () => {
    const fixture = setup({ configFailures: { 'dns-proxy': new AuthError('password=bad') } });
    const result = await fixture.handler({});
    expect(result.isError).toBe(true);
    expect(fixture.order).toEqual(['show/version', 'show/internet/status', 'show/dns-proxy', 'dns-proxy']);
    expect(result.content[0]?.text).not.toContain('password=bad');
  });

  it('classifies oversized runtime evidence without discarding siblings', async () => {
    const fixture = setup({ failures: { 'show/dns-proxy': new RciError('too large', {
      path: 'show/dns-proxy', code: 'response-too-large', ident: 'rci' }) } });
    const out = payload(await fixture.handler({}));
    expect(out.evidence.proxyRuntime.reason).toBe('response-too-large');
    expect(out.evidence.internetReachability.status).toBe('available');
    expect(out.evidence.dnsProxyConfig.status).toBe('available');
  });

  it('rejects unknown runtime and configuration shapes instead of reporting them available', async () => {
    const fixture = setup();
    fixture.get.mockImplementation(async (path: string): Promise<any> => path === 'show/dns-proxy'
      ? { unexpected: true } : VALUES[path]);
    fixture.getConfig.mockResolvedValue({ value: { unexpected: true } as never, bytes: 10 });
    const out = payload(await fixture.handler({}));
    expect(out.evidence.proxyRuntime.reason).toBe('unexpected-response');
    expect(out.evidence.dnsProxyConfig.reason).toBe('unexpected-response');
    expect(out.evidence.nameServerConfig.reason).toBe('unexpected-response');
    expect(out.complete).toBe(false);
  });

  it('keeps explicitly empty upstream arrays available and complete', async () => {
    const fixture = setup();
    fixture.get.mockImplementation(async (path: string) => path === 'show/dns-proxy'
      ? { 'proxy-status': [{ 'proxy-name': 'System', 'proxy-tls': { 'server-tls': [] },
        'proxy-https': { 'server-https': [] } }] }
      : VALUES[path]);
    fixture.getConfig.mockImplementation(async (path: string): Promise<any> => ({ value: path === 'dns-proxy'
      ? { tls: { upstream: [] }, https: { upstream: [] } }
      : [], bytes: 2 }));
    const out = payload(await fixture.handler({}));
    expect(out.complete).toBe(true);
    expect(out.evidence.proxyRuntime.status).toBe('available');
    expect(out.evidence.dnsProxyConfig.status).toBe('available');
    expect(out.evidence.nameServerConfig.status).toBe('available');
  });

  it('rejects malformed internet, route and interface shapes', async () => {
    const fixture = setup();
    fixture.get.mockImplementation(async (path: string) => {
      if (path === 'show/internet/status') return { checked: [] };
      if (path === 'show/ip/route') return [{ destination: 42 }];
      if (path === 'show/interface') return {};
      return VALUES[path];
    });
    const out = payload(await fixture.handler({}));
    expect(out.evidence.internetReachability.reason).toBe('unexpected-response');
    expect(out.evidence.routing.reason).toBe('unexpected-response');
  });

  it('rejects wrong runtime resolver field types', async () => {
    const fixture = setup();
    fixture.get.mockImplementation(async (path: string) => path === 'show/dns-proxy'
      ? { 'proxy-status': { server: { one: { address: [] } } } } : VALUES[path]);
    const out = payload(await fixture.handler({}));
    expect(out.evidence.proxyRuntime.reason).toBe('unexpected-response');
    expect(out.complete).toBe(false);
  });
});
