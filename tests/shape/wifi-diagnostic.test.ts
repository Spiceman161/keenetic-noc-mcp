import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  buildWifiClientHealth,
  buildWifiDiagnostic,
  projectWifiClientEvidence,
  projectWifiTopology
} from '../../src/shape/wifi-diagnostic.js';
import { available, unavailable } from '../../src/shape/internet-diagnostic.js';

const interfaces = {
  WifiMaster0: { id: 'WifiMaster0', type: 'WifiMaster', state: 'up', connected: 'yes',
    channel: 6, bandwidth: '20', 'busy-channels': [4, 5, 6] },
  'WifiMaster0/AccessPoint0': { id: 'WifiMaster0/AccessPoint0', type: 'AccessPoint',
    state: 'up', connected: 'yes', ssid: 'private-ssid', mac: '02:00:00:00:00:aa' },
  'WifiMaster0/AccessPoint1': { id: 'WifiMaster0/AccessPoint1', type: 'AccessPoint',
    state: 'down', connected: 'no' }
};

describe('Wi-Fi topology diagnostic', () => {
  it('counts radios, APs, clients and RSSI boundary buckets without identity leakage', () => {
    const topology = projectWifiTopology(interfaces, { station: [
      { mac: '02:00:00:00:00:01', ap: 'WifiMaster0/AccessPoint0', rssi: -60, authenticated: true },
      { mac: '02:00:00:00:00:02', ap: 'WifiMaster0/AccessPoint0', rssi: '-70', authenticated: true },
      { mac: '02:00:00:00:00:03', ap: 'WifiMaster0/AccessPoint0', rssi: -71, authenticated: true }
    ] });
    const report = buildWifiDiagnostic({ topology: available(topology) });

    expect(topology.totals).toEqual({ radios: 1, accessPoints: 2, clients: 3 });
    expect(topology.signal).toEqual({ good: 1, usable: 1, weak: 1, unknown: 0 });
    expect(report.status).toBe('degraded');
    expect(report.findings).toContainEqual(expect.objectContaining({ id: 'weak-signal-clients', count: 1 }));
    const text = JSON.stringify(report);
    expect(text).not.toContain('02:00:00:00:00:01');
    expect(text).not.toContain('private-ssid');
    expect(text).not.toContain('busy-channels');
  });

  it('does not invent missing metrics or findings from roam and busy channels', () => {
    const topology = projectWifiTopology(interfaces, { station: [{
      mac: '02:00:00:00:00:01', ap: 'WifiMaster0/AccessPoint0', rssi: 'NaN',
      txrate: '65', ht: '20', roam: 'ft'
    }] });
    const report = buildWifiDiagnostic({ topology: available(topology) });
    expect(topology.signal.unknown).toBe(1);
    expect(report.evidence.telemetryAvailability).toMatchObject({
      retryCounters: 'not-exposed', channelUtilization: 'not-exposed', roamingEvents: 'not-exposed'
    });
    expect(report.findings).toEqual([]);
  });

  it('reports authentication and broken AP/master references but ignores disabled unused APs', () => {
    const topology = projectWifiTopology(interfaces, { station: [
      { mac: '02:00:00:00:00:01', ap: 'WifiMaster0/AccessPoint0', rssi: -40, authenticated: false },
      { mac: '02:00:00:00:00:02', ap: 'WifiMaster9/AccessPoint0', rssi: -40, authenticated: true }
    ] });
    const report = buildWifiDiagnostic({ topology: available(topology) });
    expect(report.status).toBe('unhealthy');
    expect(report.findings.map(item => item.id)).toEqual(expect.arrayContaining([
      'unauthenticated-clients', 'association-ap-missing', 'association-radio-missing'
    ]));
    expect(report.findings.map(item => item.id)).not.toContain('access-point-disabled');
  });

  it('requires measured interface roles for aggregate AP and radio joins', () => {
    const topology = projectWifiTopology({
      WifiMaster0: { type: 'Ethernet' },
      'WifiMaster0/AccessPoint0': { type: 'Bridge' }
    }, { station: [{ mac: '02:00:00:00:00:01', ap: 'WifiMaster0/AccessPoint0' }] });
    expect(topology.clients).toMatchObject({ missingAccessPoint: 1, missingRadio: 1 });
  });

  it('projects the sanitized measured multi-radio fixtures without invented fields', async () => {
    const load = async (name: string): Promise<unknown> => JSON.parse(await readFile(
      new URL(`../fixtures/${name}`, import.meta.url), 'utf8'));
    const [measuredInterfaces, measuredAssociations, measuredHotspot] = await Promise.all([
      load('show_interface.json'), load('show_associations.json'), load('show_ip_hotspot.json')
    ]);
    const topology = projectWifiTopology(measuredInterfaces, measuredAssociations);
    expect(topology.totals).toEqual({ radios: 2, accessPoints: 14, clients: 8 });
    expect(topology.clients).toMatchObject({ missingAccessPoint: 0, missingRadio: 0 });
    expect(topology.signal).toEqual({ good: 3, usable: 1, weak: 4, unknown: 0 });
    const hosts = (measuredHotspot as { host: Array<Record<string, unknown>> }).host;
    const selected = hosts.find(item => item['mac'] === '02:00:00:00:00:15')!;
    const client = projectWifiClientEvidence(selected, measuredAssociations, measuredInterfaces);
    expect(client.association.data).toMatchObject({ associated: true, rssiDbm: -77,
      txRateMbps: 540, rxRateMbps: null, channelWidthMhz: 80 });
    expect(client.radio.data).not.toHaveProperty('band');
    expect(JSON.stringify(buildWifiDiagnostic({ topology: available(topology) }))).not.toMatch(
      /ssid-|02:00:00:00:00:/
    );
  });

  it('treats unavailable topology as unknown and incomplete', () => {
    const report = buildWifiDiagnostic({ topology: unavailable('rci-error') });
    expect(report).toMatchObject({ status: 'unknown', complete: false, schemaVersion: 1 });
  });
});

describe('one Wi-Fi client health', () => {
  const host = { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'Phone', active: true,
    ap: 'WifiMaster0/AccessPoint0', ssid: 'operator-ssid' };

  it.each([
    [-60, 'good', 'pass'], [-70, 'usable', 'pass'], [-71, 'weak', 'warning'],
    [-128, 'unknown', 'unknown'], [1, 'unknown', 'unknown'], ['bad', 'unknown', 'unknown']
  ])('classifies RSSI %s', (rssi, bucket, status) => {
    const evidence = projectWifiClientEvidence(host, { station: [{ mac: host.mac, ap: host.ap,
      authenticated: true, rssi, txrate: '72', ht: '20', mode: '11n' }] }, interfaces);
    const report = buildWifiClientHealth(evidence);
    expect(evidence.association.data?.signal).toBe(bucket);
    expect(report.checks.find(item => item.id === 'signal')?.status).toBe(status);
  });

  it('keeps absent rxrate null and projects evidence without BSSID or inferred band', () => {
    const evidence = projectWifiClientEvidence(host, { station: [{ mac: host.mac.toUpperCase(), ap: host.ap,
      authenticated: true, rssi: -55, txrate: '72', ht: 20, mode: '11n', mcs: 7,
      txss: '1', txbytes: '100', rxbytes: 200, _11: ['k'], roam: 'ft' }] }, interfaces);
    expect(evidence.association.data).toMatchObject({ rxRateMbps: null, txRateMbps: 72,
      channelWidthMhz: 20, mode: '11n', mcs: 7, streams: 1, roam: 'ft' });
    expect(evidence.radio.data).toMatchObject({ id: 'WifiMaster0', channel: 6, channelWidthMhz: 20 });
    expect(evidence.radio.data).not.toHaveProperty('band');
    expect(JSON.stringify(evidence)).not.toContain('02:00:00:00:00:aa');
  });

  it('uses an exact current association to classify partial hotspot rows as wireless', () => {
    const partial = { mac: host.mac, ip: host.ip, interface: { id: 'Bridge0' } };
    const evidence = projectWifiClientEvidence(partial, { station: [{ mac: host.mac,
      ap: host.ap, authenticated: false, rssi: -71 }] }, interfaces);
    expect(evidence.connection.data).toMatchObject({ kind: 'wireless', apId: host.ap });
    expect(evidence.association.data).toMatchObject({ associated: true, authenticated: false, rssiDbm: -71 });
    expect(buildWifiClientHealth(evidence).status).toBe('unhealthy');
  });

  it('publishes only confirmed structural IDs, never embedded or control-only identifiers', () => {
    const hostile = {
      '\u0000': { type: 'WifiMaster', id: 'private-radio password=secret' },
      WifiMaster0: { type: 'WifiMaster', id: '02:00:00:00:00:aa' },
      'WifiMaster0/AccessPoint0': { type: 'AccessPoint', id: 'private-ssid\u001b[31m' }
    };
    const topology = projectWifiTopology(hostile, { station: [] });
    expect(topology.radios.items.map(item => item.id)).toEqual(['WifiMaster0']);
    expect(topology.accessPoints.items.map(item => item.id)).toEqual(['WifiMaster0/AccessPoint0']);
    const selected = projectWifiClientEvidence(host, { station: [{ mac: host.mac, ap: host.ap }] }, hostile);
    const text = JSON.stringify({ topology, selected });
    expect(text).not.toContain('private-radio');
    expect(text).not.toContain('private-ssid');
    expect(text).not.toContain('02:00:00:00:00:aa');
    expect(text).not.toMatch(/[\u0000\u001b]/);
  });

  it('returns not-applicable for a wired selected device', () => {
    const evidence = projectWifiClientEvidence({ mac: host.mac, ip: host.ip, name: host.name,
      active: true, interface: { id: 'Bridge0' } }, { station: [] }, interfaces);
    const report = buildWifiClientHealth(evidence);
    expect(report.status).toBe('not-applicable');
    expect(report.checks.every(item => item.status === 'not-applicable')).toBe(true);
  });

  it('warns for an active wireless host without an association', () => {
    const report = buildWifiClientHealth(projectWifiClientEvidence(host, { station: [] }, interfaces));
    expect(report.findings.map(item => item.id)).toContain('wifi-association-missing');
  });

  it('does not call an active connection wireless when its kind is unknown', () => {
    const evidence = projectWifiClientEvidence({ mac: host.mac, active: true }, { station: [] }, {});
    const report = buildWifiClientHealth(evidence);
    expect(evidence.connection.data?.kind).toBe('unknown');
    expect(report.checks.find(item => item.id === 'association')?.status).toBe('unknown');
    expect(report.findings).toEqual([]);
    expect(report.status).toBe('unknown');
  });
});
