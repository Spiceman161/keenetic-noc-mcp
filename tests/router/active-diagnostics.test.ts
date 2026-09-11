import { describe, expect, it } from 'vitest';
import {
  ActiveDiagnosticCoordinator,
  pingCommand,
  tracerouteCommand,
  validateDiagnosticTarget
} from '../../src/router/active-diagnostics.js';

describe('active diagnostic target validation', () => {
  it.each([['example.test', 'example.test'], ['Example.TEST', 'example.test'], ['gateway', 'gateway'],
    ['192.0.2.1', '192.0.2.1'], ['2001:DB8::1', '2001:db8::1']])('accepts and normalizes %s', (target, expected) => {
    expect(validateDiagnosticTarget(target)).toBe(expected);
  });

  it.each([
    '', '-c.example.test', 'example.test.', 'two words.test', 'https://example.test',
    'user@example.test', 'example.test:53', '192.0.2.1/24', '[2001:db8::1]',
    '2001:db8::1%eth0', 'example%2etest', 'example.test;reboot',
    '0.0.0.0', '255.255.255.255', '224.0.0.1', '::', 'ff02::1'
  ])('rejects unsafe or ambiguous target %s', target => {
    expect(() => validateDiagnosticTarget(target)).toThrow();
  });

  it('builds only the measured finite command trees', () => {
    expect(pingCommand('192.0.2.1', 'ipv4', 3)).toEqual({
      path: 'tools/ping', body: { host: '192.0.2.1', packetsize: 84, count: 3 }
    });
    expect(pingCommand('2001:db8::1', 'ipv6', 1)).toEqual({
      path: 'tools/ping6', body: { host: '2001:db8::1', packetsize: 84, count: 1 }
    });
    expect(tracerouteCommand('example.test', 15)).toEqual({
      path: 'tools/traceroute',
      body: { host: 'example.test', port: 33434, packetsize: 52, 'max-ttl': 15, type: 'udp' }
    });
  });

  it('rejects family mismatches and out-of-range native limits', () => {
    expect(() => pingCommand('2001:db8::1', 'ipv4', 1)).toThrow();
    expect(() => pingCommand('192.0.2.1', 'ipv6', 1)).toThrow();
    expect(() => pingCommand('example.test', 'ipv4', 6)).toThrow();
    expect(() => tracerouteCommand('example.test', 31)).toThrow();
  });
});

describe('active diagnostic coordinator', () => {
  it('rejects a concurrent operation and releases after completion', async () => {
    const coordinator = new ActiveDiagnosticCoordinator();
    let release!: () => void;
    const pending = coordinator.run(() => new Promise<void>(resolve => { release = resolve; }));
    await expect(coordinator.run(async () => undefined)).rejects.toThrow(/already running/i);
    release();
    await pending;
    await expect(coordinator.run(async () => 'ok')).resolves.toBe('ok');
  });

  it('limits repeated starts in one minute', async () => {
    let now = 100_000;
    const coordinator = new ActiveDiagnosticCoordinator(() => now);
    for (let index = 0; index < 10; index += 1) await coordinator.run(async () => undefined);
    await expect(coordinator.run(async () => undefined)).rejects.toThrow(/rate limit/i);
    now += 60_001;
    await expect(coordinator.run(async () => undefined)).resolves.toBeUndefined();
  });

  it('quarantines admission when router-side cancellation was uncertain', async () => {
    const { ActiveDiagnosticUncertainError } = await import('../../src/router/errors.js');
    let now = 100_000;
    const coordinator = new ActiveDiagnosticCoordinator(() => now);
    await expect(coordinator.run(async () => { throw new ActiveDiagnosticUncertainError(); }))
      .rejects.toBeInstanceOf(ActiveDiagnosticUncertainError);
    await expect(coordinator.run(async () => undefined)).rejects.toThrow(/uncertain/i);
    now += 3_600_000;
    await expect(coordinator.run(async () => undefined)).rejects.toThrow(/uncertain/i);
  });
});
