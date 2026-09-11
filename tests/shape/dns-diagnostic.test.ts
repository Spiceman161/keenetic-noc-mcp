import { describe, expect, it } from 'vitest';
import { available, unavailable } from '../../src/shape/internet-diagnostic.js';
import {
  budgetDnsDiagnostic,
  buildDnsDiagnostic,
  cleanDnsEndpoint,
  isDnsConfigShape,
  isDnsRuntimeShape,
  projectDnsInternet,
  projectDnsLogs,
  projectDnsProxy,
  projectDnsRoutes,
  projectDnsUpstreams,
  type DnsDiagnosticEvidence
} from '../../src/shape/dns-diagnostic.js';

function evidence(overrides: Partial<DnsDiagnosticEvidence> = {}): DnsDiagnosticEvidence {
  return {
    proxyRuntime: available(projectDnsProxy({ 'proxy-status': {
      enabled: true, status: 'up', server: [{ address: '192.0.2.53', protocol: 'DoT', status: 'up' }]
    } })),
    internetReachability: available(projectDnsInternet({
      checked: true, enabled: true, reliable: true, 'gateway-accessible': true, 'dns-accessible': true, internet: true
    })),
    dnsProxyConfig: available({ items: [], shown: 0, total: 0, truncated: false }),
    nameServerConfig: available({ items: [{ source: 'name-server-config', scope: null, protocol: 'dot', status: null,
      address: '192.0.2.53', port: 853, endpoint: null, tlsServerName: 'resolver.example.test', interface: null, domain: null }],
    shown: 1, total: 1, truncated: false }),
    routing: available({ items: [{ address: '192.0.2.53', endpoint: null, interface: 'GigabitEthernet1',
      destination: '0.0.0.0/0', state: 'available' }], shown: 1, total: 1, truncated: false }),
    logs: available({ items: [], shown: 0, total: 0, truncated: false, scanned: 0, matched: 0, untrusted: true }),
    ...overrides
  };
}

describe('DNS diagnostic projections', () => {
  it('projects the measured KeeneticOS 5.1.3 runtime and config shapes', () => {
    const runtime = { 'proxy-status': [{
      'proxy-name': 'System',
      'proxy-tls': { 'server-tls': [{ address: '9.9.9.9', port: 853, sni: '', interface: '', domain: '' }] },
      'proxy-https': { 'server-https': [{
        uri: 'https://resolver.example.test/private-profile/dns-query', interface: 'GigabitEthernet0/Vlan2', domain: ''
      }] }
    }] };
    expect(projectDnsProxy(runtime).upstreams.items).toEqual([
      expect.objectContaining({ source: 'runtime', scope: 'System', protocol: 'dot',
        address: '9.9.9.9', port: 853 }),
      expect.objectContaining({ source: 'runtime', scope: 'System', protocol: 'doh', address: null,
        endpoint: 'https://resolver.example.test/dns-query', interface: 'GigabitEthernet0/Vlan2' })
    ]);
    const config = { tls: { upstream: [{ address: '9.9.9.9', port: 853 }] },
      https: { upstream: [{ url: 'https://resolver.example.test/private-profile/dns-query' }] } };
    expect(projectDnsUpstreams(config, 'dns-proxy-config')).toEqual([
      expect.objectContaining({ protocol: 'dot', address: '9.9.9.9', port: 853 }),
      expect.objectContaining({ protocol: 'doh', endpoint: 'https://resolver.example.test/dns-query' })
    ]);
  });

  it('rejects malformed measured branches even when a sibling is valid', () => {
    expect(isDnsRuntimeShape({ 'proxy-status': [{ 'proxy-name': 'System', 'proxy-tls': 42 }] })).toBe(false);
    expect(isDnsConfigShape({ tls: { upstream: [{ address: '9.9.9.9' }] },
      https: { upstream: 42 } }, 'dns-proxy-config')).toBe(false);
    expect(isDnsConfigShape({ tls: { upstream: [{ address: '9.9.9.9' }] },
      https: { upstream: [{ url: [] }] } }, 'dns-proxy-config')).toBe(false);
    expect(isDnsConfigShape({ tls: { upstream: [{ address: '9.9.9.9' }] },
      https: { upstream: [{ url: 'customer-profile-123' }] } }, 'dns-proxy-config')).toBe(false);
    expect(isDnsRuntimeShape({ 'proxy-status': [{ 'proxy-name': 'System',
      'proxy-https': { 'server-https': [{ uri: '/profiles/customer-123/dns-query' }] } }] })).toBe(false);
  });

  it('accepts explicitly empty upstream arrays without accepting empty objects', () => {
    expect(isDnsConfigShape([], 'name-server-config')).toBe(true);
    expect(isDnsConfigShape({ tls: { upstream: [] }, https: { upstream: [] } }, 'dns-proxy-config')).toBe(true);
    expect(isDnsRuntimeShape({ 'proxy-status': [{ 'proxy-name': 'System',
      'proxy-tls': { 'server-tls': [] }, 'proxy-https': { 'server-https': [] } }] })).toBe(true);
    expect(isDnsConfigShape({}, 'name-server-config')).toBe(false);
  });

  it('requires HTTPS endpoints in measured DoH branches', () => {
    expect(isDnsConfigShape({ https: { upstream: [{ url: 'http://resolver.example.test/dns-query' }] } },
      'dns-proxy-config')).toBe(false);
    expect(isDnsRuntimeShape({ 'proxy-status': [{ 'proxy-name': 'System',
      'proxy-https': { 'server-https': [{ uri: 'ftp://resolver.example.test/dns-query' }] } }] })).toBe(false);
    expect(isDnsConfigShape({ https: { upstream: [{ url: 'https://resolver.example.test/dns-query' }] } },
      'dns-proxy-config')).toBe(true);
  });

  it('projects exact runtime and configured identifiers without merging observations', () => {
    expect(projectDnsProxy({ 'proxy-status': { server: [{ address: '192.0.2.53', protocol: 'DoT',
      sni: 'resolver.example.test', status: 'up' }] } }).upstreams.items[0]).toMatchObject({
      source: 'runtime', protocol: 'dot', address: '192.0.2.53', tlsServerName: 'resolver.example.test'
    });
    expect(projectDnsUpstreams({ server: ['198.51.100.53'] }, 'name-server-config')).toEqual([
      expect.objectContaining({ source: 'name-server-config', address: '198.51.100.53', protocol: 'plain' })
    ]);
  });

  it('removes endpoint credentials, query and fragment', () => {
    expect(cleanDnsEndpoint('https://user:password@resolver.example.test/dns-query?token=secret#x'))
      .toBe('https://resolver.example.test/dns-query');
    expect(projectDnsUpstreams({ server: ['https://user:password@resolver.example.test/dns-query?token=secret'] },
      'dns-proxy-config')[0]).toMatchObject({ protocol: 'doh', address: null,
      endpoint: 'https://resolver.example.test/dns-query' });
    expect(cleanDnsEndpoint('https://user:password@[invalid?token=secret')).toBeNull();
    expect(cleanDnsEndpoint('ftp://user:password@resolver.example.test/file?token=secret#x'))
      .toBe('ftp://resolver.example.test/file');
    expect(cleanDnsEndpoint('https://resolver.example.test/private-profile/dns-query'))
      .toBe('https://resolver.example.test/dns-query');
    expect(cleanDnsEndpoint('/profiles/customer-123/dns-query')).toBeNull();
    expect(cleanDnsEndpoint('customer-profile-123')).toBeNull();
    const providerToken = 'QWxhZGRpbjpvcGVuIHNlc2FtZV9wcm9maWxlX3Rva2VuMTIzNDU2Nzg5MA';
    const endpoint = cleanDnsEndpoint(`https://resolver.example.test/${providerToken}/dns-query`);
    expect(endpoint).toBe('https://resolver.example.test/dns-query');
    expect(endpoint).not.toContain(providerToken);
  });

  it('uses longest-prefix IPv4 routing and detects an unavailable interface', () => {
    const upstreams = projectDnsUpstreams({ server: ['192.0.2.53'] }, 'name-server-config');
    const routes = projectDnsRoutes(upstreams, [
      { destination: '0.0.0.0/0', interface: 'GigabitEthernet1' },
      { destination: '192.0.2.0/24', interface: 'Wireguard0' }
    ], { GigabitEthernet1: { link: 'up' }, Wireguard0: { state: 'down' } });
    expect(routes.items).toEqual([{ address: '192.0.2.53', endpoint: null, interface: 'Wireguard0',
      destination: '192.0.2.0/24', state: 'unavailable' }]);
  });

  it('keeps unknown hostname routing and supports bare host routes', () => {
    const upstreams = [
      ...projectDnsUpstreams({ server: ['https://resolver.example.test/dns-query'] }, 'dns-proxy-config'),
      ...projectDnsUpstreams({ server: ['192.0.2.53'] }, 'name-server-config')
    ];
    const routes = projectDnsRoutes(upstreams, [
      { destination: '0.0.0.0/0', interface: 'GigabitEthernet1' },
      { destination: '192.0.2.53', interface: 'Wireguard0' }
    ], { GigabitEthernet1: { link: 'up' }, Wireguard0: { link: 'up' } });
    expect(routes.items[0]).toMatchObject({ endpoint: 'https://resolver.example.test/dns-query',
      state: 'not-exposed' });
    expect(routes.items[1]).toMatchObject({ destination: '192.0.2.53', interface: 'Wireguard0',
      state: 'available' });
  });

  it('does not call a missing or explicitly offline interface available', () => {
    const upstreams = projectDnsUpstreams({ server: ['192.0.2.53'] }, 'name-server-config');
    expect(projectDnsRoutes(upstreams, [{ destination: '0.0.0.0/0', interface: 'Missing0' }], {}).items[0]?.state)
      .toBe('not-exposed');
    expect(projectDnsRoutes(upstreams, [{ destination: '0.0.0.0/0', interface: 'Wan0' }],
      { Wan0: { connected: false, state: 'up' } }).items[0]?.state).toBe('unavailable');
  });

  it('honors a rejecting host route before an available default route', () => {
    const upstreams = projectDnsUpstreams({ server: ['192.0.2.53'] }, 'name-server-config');
    const routes = projectDnsRoutes(upstreams, [
      { destination: '0.0.0.0/0', interface: 'Wan0' },
      { destination: '192.0.2.53', interface: 'Reject0', rejecting: true }
    ], { Wan0: { link: 'up' }, Reject0: { link: 'up' } });
    expect(routes.items[0]).toMatchObject({ destination: '192.0.2.53', state: 'unavailable' });
  });

  it('does not treat an explicit interface binding as a proven route', () => {
    const upstream = [{ source: 'dns-proxy-config' as const, scope: null, protocol: 'plain' as const,
      status: null, address: '192.0.2.53', port: null, endpoint: null, tlsServerName: null,
      interface: 'Wan0', domain: null }];
    expect(projectDnsRoutes(upstream, [], { Wan0: { link: 'up' } }).items[0]).toMatchObject({
      interface: 'Wan0', destination: null, state: 'not-exposed'
    });
    expect(projectDnsRoutes(upstream, [{ destination: '192.0.2.53', interface: 'Wan0', rejecting: true }],
      { Wan0: { link: 'up' } }).items[0]?.state).toBe('unavailable');
  });

  it('caps route correlation work and reports omitted upstream evidence', () => {
    const upstreams = Array.from({ length: 10_000 }, (_, index) => ({
      source: 'runtime' as const, scope: null, protocol: 'plain' as const, status: 'up',
      address: `192.0.2.${index % 255}`, port: null, endpoint: null, tlsServerName: null, interface: null, domain: null
    }));
    const routes = Array.from({ length: 5_000 }, (_, index) => ({
      destination: `198.51.${index % 255}.0/24`, interface: 'Wan0'
    }));
    const projected = projectDnsRoutes(upstreams, routes, { Wan0: { link: 'up' } });
    expect(projected.shown).toBe(200);
    expect(projected.total).toBe(10_000);
    expect(projected.truncated).toBe(true);
  });

  it('reports only explicit failures and treats stale reachability as unknown', () => {
    const stale = buildDnsDiagnostic(evidence({
      internetReachability: available(projectDnsInternet({ checked: false, reliable: true,
        'gateway-accessible': true, 'dns-accessible': false }))
    }));
    expect(stale.findings.map(item => item.id)).not.toContain('dns-reachability-failed');
    expect(stale.checks.find(item => item.id === 'internet-dns-reachability')?.status).toBe('unknown');

    expect(projectDnsInternet({ checked: true, enabled: false, reliable: true,
      'dns-accessible': true }).current).toBe(false);
    expect(projectDnsInternet({ checked: true, enabled: true, 'dns-accessible': false }).current).toBe(false);
    expect(projectDnsInternet({ checked: '2000-01-01T00:00:00Z', enabled: true, reliable: true,
      'dns-accessible': false }).current).toBe(false);
    expect(projectDnsInternet({ checked: 'Fri Sep 11 10:40:00 2000', enabled: true, reliable: true,
      'dns-accessible': true }).current).toBe(false);
    const twentyHoursAgo = new Date(Date.now() - 20 * 60 * 60_000).toISOString()
      .replace('T', ' ').replace(/\.\d{3}Z$/, '');
    expect(projectDnsInternet({ checked: twentyHoursAgo, enabled: true, reliable: true,
      'dns-accessible': false }).current).toBe(false);
    const fiveHoursAgo = new Date(Date.now() - 5 * 60 * 60_000).toISOString()
      .replace('T', ' ').replace(/\.\d{3}Z$/, '');
    expect(projectDnsInternet({ checked: fiveHoursAgo, enabled: true, reliable: true,
      'gateway-accessible': true, 'dns-accessible': false }).current).toBe(false);
    const threeHoursAhead = new Date(Date.now() + 3 * 60 * 60_000).toISOString()
      .replace('T', ' ').replace(/\.\d{3}Z$/, '');
    expect(projectDnsInternet({ checked: threeHoursAhead, enabled: true, reliable: true,
      'gateway-accessible': true, 'dns-accessible': true }).current).toBe(false);

    const failed = buildDnsDiagnostic(evidence({
      internetReachability: available(projectDnsInternet({ checked: true, enabled: true, reliable: true,
        'gateway-accessible': true, 'dns-accessible': false, internet: false }))
    }));
    expect(failed.status).toBe('unhealthy');
    expect(failed.findings.map(item => item.id)).toContain('dns-reachability-failed');

    const conflict = buildDnsDiagnostic(evidence({
      internetReachability: available(projectDnsInternet({ checked: true, enabled: true, reliable: true,
        'gateway-accessible': true, 'dns-accessible': false, internet: true }))
    }));
    expect(conflict.findings.map(item => item.id)).not.toContain('dns-reachability-failed');
    expect(conflict.findings.map(item => item.id)).toContain('conflicting-dns-reachability');
  });

  it('treats disabled proxy state and partial config evidence conservatively', () => {
    const report = buildDnsDiagnostic(evidence({
      proxyRuntime: available(projectDnsProxy({ 'proxy-status': { enabled: false, status: 'up' } })),
      dnsProxyConfig: unavailable('rci-error')
    }));
    expect(report.checks.find(item => item.id === 'proxy-runtime')?.status).toBe('warning');
    expect(report.checks.find(item => item.id === 'upstream-configuration')?.status).toBe('warning');
    expect(report.status).toBe('degraded');
  });

  it('degrades a confirmed unavailable upstream route but not unknown routing', () => {
    const unavailableRoute = buildDnsDiagnostic(evidence({ routing: available({ items: [{
      address: '192.0.2.53', endpoint: null, interface: 'Wan0', destination: '0.0.0.0/0', state: 'unavailable'
    }], shown: 1, total: 1, truncated: false }) }));
    expect(unavailableRoute.status).toBe('degraded');
    expect(unavailableRoute.findings.map(item => item.id)).toContain('dns-upstream-route-unavailable');
    const unknownRoute = buildDnsDiagnostic(evidence({ routing: unavailable('unexpected-response') }));
    expect(unknownRoute.status).toBe('healthy');
  });

  it('does not report healthy when all core evidence is unavailable', () => {
    const report = buildDnsDiagnostic({ proxyRuntime: unavailable('transport-error'),
      internetReachability: unavailable('transport-error'), dnsProxyConfig: unavailable('transport-error'),
      nameServerConfig: unavailable('transport-error'), routing: unavailable('transport-error'),
      logs: unavailable('transport-error') });
    expect(report.status).not.toBe('healthy');
    expect(report.checks.every(item => item.status === 'unknown')).toBe(true);
  });

  it('does not call failed plus status-less runtime rows an all-upstream failure', () => {
    const report = buildDnsDiagnostic(evidence({ proxyRuntime: available(projectDnsProxy({
      'proxy-status': { enabled: true, status: 'up', server: [
        { address: '192.0.2.53', status: 'failed' }, { address: '198.51.100.53' }
      ] }
    })) }));
    expect(report.findings.map(item => item.id)).not.toContain('all-dns-upstreams-failed');
    expect(report.findings.map(item => item.id)).toContain('dns-upstream-failure-observed');
  });

  it('does not degrade automatic runtime DNS when no explicit upstream is configured', () => {
    const report = buildDnsDiagnostic(evidence({
      dnsProxyConfig: available({ items: [], shown: 0, total: 0, truncated: false }),
      nameServerConfig: available({ items: [], shown: 0, total: 0, truncated: false })
    }));
    expect(report.checks.find(item => item.id === 'upstream-configuration')?.status).toBe('pass');
    expect(report.status).toBe('healthy');
  });

  it('keeps logs untrusted and redacts long key material before truncation', () => {
    const key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst';
    const logs = projectDnsLogs([{ timestamp: null, ident: 'dns-proxy', level: null, label: null,
      line: `${'.'.repeat(500)} ${key}` }]);
    expect(logs.untrusted).toBe(true);
    expect(logs.items[0]?.line).toContain('[REDACTED_KEY]');
    expect(logs.items[0]?.line).not.toContain(key);
  });

  it('strips URL credentials, query and fragments from untrusted log text', () => {
    const unsafe = 'x_https://alice:cleartext@resolver.example.test/dns-query?profile=private-id#frag';
    const logs = projectDnsLogs([{ timestamp: unsafe, ident: 'dns-proxy', level: unsafe, label: unsafe,
      line: `failed ${unsafe}` }]);
    const text = JSON.stringify(logs);
    expect(text).toContain('https://resolver.example.test/dns-query');
    expect(text).not.toMatch(/alice|cleartext|profile|private-id|frag/);
    const proxy = projectDnsProxy({ 'proxy-status': { enabled: true, status: unsafe,
      server: [{ address: '192.0.2.53', interface: unsafe }] } });
    expect(JSON.stringify(proxy)).not.toMatch(/alice|cleartext|profile|private-id|frag/);
  });

  it('propagates intrinsic evidence caps to top-level truncation', () => {
    const logs = Array.from({ length: 21 }, (_, index) => ({ timestamp: null, ident: 'dns-proxy',
      level: null, label: null, line: `resolver event ${index}` }));
    const report = buildDnsDiagnostic(evidence({ logs: available(projectDnsLogs(logs)) }));
    expect(report.evidence.logs.data?.truncated).toBe(true);
    expect(report.truncated).toBe(true);
  });

  it('bounds list evidence while preserving checks and findings', () => {
    const rows = Array.from({ length: 80 }, (_, index) => ({ source: 'runtime' as const, scope: null,
      protocol: 'plain' as const, status: 'up', address: `192.0.2.${index + 1}`, port: null, endpoint: null,
      tlsServerName: null, interface: null, domain: null }));
    const report = buildDnsDiagnostic(evidence({ proxyRuntime: available({ enabled: true, status: 'up',
      staticHostsCount: 0, errorCount: 0, upstreams: { items: rows, shown: rows.length,
        total: rows.length, truncated: false } }), logs: unavailable('not-supported') }));
    const bounded = budgetDnsDiagnostic(report, 7_000);
    expect(bounded.checks).toHaveLength(6);
    expect(bounded.truncated).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(bounded, null, 2))).toBeLessThanOrEqual(7_000);
  });
});
