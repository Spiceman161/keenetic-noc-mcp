import { describe, expect, it } from 'vitest';
import {
  budgetDeviceDiagnostic,
  buildDeviceDiagnostic,
  projectDeviceLogs,
  projectDeviceRoutingPolicy,
  type DeviceDiagnosticEvidence
} from '../../src/shape/device-diagnostic.js';
import { available, unavailable } from '../../src/shape/internet-diagnostic.js';
import { redact } from '../../src/security/redact.js';

function evidence(): DeviceDiagnosticEvidence {
  return {
    identity: available({ mac: '02:00:00:00:00:01', name: 'device-1', hostname: 'host-1',
      registered: true, active: true, lastSeenSeconds: 1 }),
    address: available({ ipv4: '192.0.2.5', ipv6: { items: [], shown: 0, total: 0, truncated: false },
      hotspotDhcpExpiresSeconds: 100 }),
    dhcpBinding: available({ matched: true, ipv4: '192.0.2.5', expiresSeconds: 90, via: 'Bridge0' }),
    connection: available({ kind: 'wired', interface: 'Bridge0', ap: null, ssid: null,
      link: 'up', interfaceState: 'up', interfaceStateAvailable: true }),
    wifi: available({ applicable: false, associated: null, authenticated: null, rssiDbm: null,
      txRateMbps: null, rxRateMbps: null, mode: null, channelWidthMhz: null, band: null,
      associationStateAvailable: true, interfaceStateAvailable: true }),
    access: available({ access: 'permit', blocked: false, schedule: null, priority: 6 }),
    routingPolicy: available({ assigned: null, present: null, description: null,
      permittedInterfaces: { items: [], shown: 0, total: 0, truncated: false },
      interfaceStatesAvailable: true }),
    dnsContext: available({ routerWide: true, current: true, dnsAccessible: true, internet: true }),
    logs: available({ items: [], shown: 0, total: 0, truncated: false, scanned: 0, matched: 0,
      untrusted: true })
  };
}

describe('device diagnostic shaping', () => {
  it('does not treat wired Wi-Fi or optional log evidence as a fault', () => {
    const report = buildDeviceDiagnostic(evidence());
    expect(report.status).toBe('healthy');
    expect(report.checks.find(check => check.id === 'wifi')?.status).toBe('not-applicable');
    expect(report.findings).toEqual([]);
  });

  it('does not claim a device-specific DNS cause from router-wide context', () => {
    const input = evidence();
    input.dnsContext = available({ routerWide: true, current: true, dnsAccessible: false, internet: false });
    const report = buildDeviceDiagnostic(input);
    expect(report.status).toBe('healthy');
    expect(report.checks.find(check => check.id === 'dns-context')).toMatchObject({ status: 'warning' });
    expect(report.findings).toEqual([]);
  });

  it('reports missing and unavailable routing-policy interfaces conservatively', () => {
    expect(projectDeviceRoutingPolicy({ policy: 'Missing' }, {}, {}).present).toBe(false);
    const projected = projectDeviceRoutingPolicy({ policy: 'Policy0' }, {
      Policy0: { permit: [{ interface: 'Wireguard3' }] }
    }, { Wireguard3: { link: 'down', state: 'down' } });
    expect(projected.permittedInterfaces.items[0]?.state).toBe('unavailable');
  });

  it('ignores disabled policy permit rows when evaluating available paths', () => {
    const projected = projectDeviceRoutingPolicy({ policy: 'Policy0' }, {
      Policy0: { permit: [
        { enabled: true, interface: 'GigabitEthernet1' },
        { enabled: false, no: true, interface: 'Wireguard3' }
      ] }
    }, {
      GigabitEthernet1: { link: 'down' },
      Wireguard3: { link: 'up' }
    });
    expect(projected.permittedInterfaces.items).toEqual([
      { id: 'GigabitEthernet1', state: 'unavailable' }
    ]);
  });

  it('names DHCP when only DHCP evidence supplies the address', () => {
    const input = evidence();
    input.address.data!.ipv4 = null;
    const report = buildDeviceDiagnostic(input);
    expect(report.checks.find(check => check.id === 'address')).toMatchObject({
      status: 'pass', summary: expect.stringMatching(/DHCP/)
    });
  });

  it('sanitizes and bounds matching logs', () => {
    const logs = projectDeviceLogs(Array.from({ length: 30 }, (_, index) => ({
      timestamp: `00:${String(index).padStart(2, '0')}`, ident: 'Hotspot', level: null, label: null,
      line: `192.0.2.5 password=private \u001b[31mrow-${index}`
    })), ['192.0.2.5']);
    expect(logs.items).toHaveLength(20);
    expect(logs.total).toBe(30);
    expect(JSON.stringify(logs)).not.toContain('private');
    expect(JSON.stringify(logs)).not.toContain('\u001b');
  });

  it('removes URL and authorization credentials from untrusted device logs', () => {
    const logs = projectDeviceLogs([{
      timestamp: null, ident: 'Hotspot', level: null, label: null,
      line: '192.0.2.5 https://alice:swordfish@example.test/x?token=private#fragment Authorization: Bearer short-secret'
    }], ['192.0.2.5']);
    const text = JSON.stringify(logs);
    expect(text).not.toMatch(/alice|swordfish|token=|fragment|short-secret|Bearer/);
  });

  it('trims optional evidence while preserving checks and findings', () => {
    const input = evidence();
    input.access = available({ access: 'deny', blocked: true, schedule: null, priority: null });
    input.logs = available({
      items: Array.from({ length: 20 }, (_, index) => ({ timestamp: null, ident: null, level: null,
        label: null, line: `device row ${index} ${'x'.repeat(400)}` })),
      shown: 20, total: 20, truncated: false, scanned: 20, matched: 20, untrusted: true
    });
    const report = budgetDeviceDiagnostic(buildDeviceDiagnostic(input), 6_000);
    expect(report.truncated).toBe(true);
    expect(report.checks).toHaveLength(8);
    expect(report.findings.map(finding => finding.id)).toContain('device-access-blocked');
    expect(Buffer.byteLength(JSON.stringify(redact(report), null, 2), 'utf8')).toBeLessThanOrEqual(6_000);
  });

  it('marks unavailable secondary evidence incomplete', () => {
    const input = evidence();
    input.logs = unavailable('not-supported');
    expect(buildDeviceDiagnostic(input).complete).toBe(false);
  });
});
