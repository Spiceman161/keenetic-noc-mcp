import { describe, expect, it } from 'vitest';
import {
  deviceAliases,
  normalizeDeviceName,
  resolveDeviceRecord,
  type DeviceSelector
} from '../../src/router/device-state.js';

const HOSTS = [
  { mac: '02:00:00:00:00:01', ip: '192.0.2.5', name: 'Kitchen Phone', hostname: 'phone' },
  { mac: '02:00:00:00:00:02', ip: '192.0.2.6', name: 'Laptop', hostname: 'workbook' }
];

function resolve(selector: DeviceSelector) {
  return resolveDeviceRecord(HOSTS, selector);
}

describe('device state resolution', () => {
  it('resolves MAC case-insensitively and IP exactly', () => {
    expect(resolve({ mac: '02:00:00:00:00:01' })?.['name']).toBe('Kitchen Phone');
    expect(resolve({ ip: '192.0.2.6' })?.['name']).toBe('Laptop');
  });

  it('normalizes Unicode, case and whitespace for registered names and hostnames', () => {
    expect(normalizeDeviceName('Ｋｉｔｃｈｅｎ  PHONE')).toBe('kitchenphone');
    expect(resolve({ name: 'KITCHENPHONE' })?.['mac']).toBe('02:00:00:00:00:01');
    expect(resolve({ name: 'Work Book' })?.['mac']).toBe('02:00:00:00:00:02');
  });

  it('rejects normalized ambiguity even when one display name is an exact match', () => {
    const hosts = [
      { mac: '02:00:00:00:00:11', name: 'Kitchen Phone' },
      { mac: '02:00:00:00:00:12', name: 'kitchenphone' }
    ];
    expect(() => resolveDeviceRecord(hosts, { name: 'Kitchen Phone' })).toThrow(/ambiguous/i);
  });

  it('returns undefined without exposing the known-device inventory', () => {
    expect(resolve({ name: 'missing' })).toBeUndefined();
  });

  it('requires exactly one non-empty selector', () => {
    expect(() => resolveDeviceRecord(HOSTS, {}, true)).toThrow(/exactly one/i);
    expect(() => resolveDeviceRecord(HOSTS, {
      mac: HOSTS[0]!.mac as string,
      ip: HOSTS[0]!.ip as string
    }, true))
      .toThrow(/exactly one/i);
    expect(() => resolveDeviceRecord(HOSTS, { name: '  ' }, true)).toThrow(/exactly one/i);
  });

  it('preserves get_device compatibility for multiple selectors that identify one record', () => {
    expect(resolveDeviceRecord(HOSTS, { mac: '02:00:00:00:00:01', ip: '192.0.2.5' })?.['name'])
      .toBe('Kitchen Phone');
  });

  it('returns all non-empty aliases without duplicates', () => {
    expect(deviceAliases({ ...HOSTS[0], hostname: 'Kitchen Phone' })).toEqual([
      '02:00:00:00:00:01', '192.0.2.5', 'Kitchen Phone'
    ]);
    expect(deviceAliases({ mac: '   ', name: 'device-1' })).toEqual(['device-1']);
  });

  it('rejects blank and oversized free-form selectors', () => {
    expect(() => resolveDeviceRecord(HOSTS, { name: 'x'.repeat(257) }, true)).toThrow(/too long/i);
    expect(() => resolveDeviceRecord(HOSTS, { name: '   ' }, true)).toThrow(/exactly one/i);
    const legacyName = 'x'.repeat(257);
    expect(resolveDeviceRecord([{ mac: '02:00:00:00:00:03', name: legacyName }], {
      name: legacyName
    })?.['mac']).toBe('02:00:00:00:00:03');
  });
});
