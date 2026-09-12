import { isIP } from 'node:net';
import { ActiveDiagnosticUncertainError, ResourceError, ValidationError } from './errors.js';

export type PingFamily = 'ipv4' | 'ipv6';

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function validateDiagnosticTarget(raw: string, hostnameOnly = false): string {
  if (raw !== raw.trim()) {
    throw new ValidationError('Diagnostic target must not have leading or trailing whitespace.');
  }
  const target = raw.toLowerCase();
  if (target.length === 0 || target.length > 253 ||
      /[\u0000-\u0020\u007f-\u009f]/u.test(target) || /[%\[\]\\/@?#]/u.test(target)) {
    throw new ValidationError('Diagnostic target must be a non-empty hostname or IP address without whitespace or control characters.');
  }
  const version = isIP(target);
  if (version !== 0) {
    if (hostnameOnly) throw new ValidationError('This diagnostic requires a hostname, not an IP address.');
    if (target === '0.0.0.0' || target === '255.255.255.255' || target === '::' ||
        (version === 4 && Number(target.split('.')[0]) >= 224) ||
        (version === 6 && target.startsWith('ff'))) {
      throw new ValidationError('Unspecified, multicast, and broadcast diagnostic targets are not allowed.');
    }
    return target;
  }
  if (target.startsWith('-') || target.endsWith('.') || target.includes('..') ||
      !target.split('.').every(label => HOST_LABEL.test(label))) {
    throw new ValidationError('Diagnostic target must be an ASCII hostname with valid DNS labels, or a canonical IP address.');
  }
  return target;
}

export function pingCommand(target: string, family: PingFamily, count: number): {
  path: 'tools/ping' | 'tools/ping6'; body: Record<string, unknown>;
} {
  const safe = validateDiagnosticTarget(target);
  if (isIP(safe) === 6 && family !== 'ipv6') {
    throw new ValidationError('An IPv6 target requires family="ipv6".');
  }
  if (isIP(safe) === 4 && family !== 'ipv4') {
    throw new ValidationError('An IPv4 target requires family="ipv4".');
  }
  if (!Number.isInteger(count) || count < 1 || count > 5) {
    throw new ValidationError('Ping count must be an integer from 1 through 5.');
  }
  return {
    path: family === 'ipv6' ? 'tools/ping6' : 'tools/ping',
    body: { host: safe, packetsize: 84, count }
  };
}

export function tracerouteCommand(target: string, maxHops: number): {
  path: 'tools/traceroute'; body: Record<string, unknown>;
} {
  const safe = validateDiagnosticTarget(target);
  if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 30) {
    throw new ValidationError('Traceroute max_hops must be an integer from 1 through 30.');
  }
  return {
    path: 'tools/traceroute',
    // These are the exact finite parameters used by KeeneticOS 5.1.3 Web UI.
    body: { host: safe, port: 33434, packetsize: 52, 'max-ttl': maxHops, type: 'udp' }
  };
}

export class ActiveDiagnosticCoordinator {
  private active = false;
  private starts: number[] = [];
  private uncertain = false;

  constructor(private readonly now: () => number = Date.now) {}

  async run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.active) {
      throw new ResourceError(
        'Another active diagnostic is already running.',
        'active_diagnostic_busy'
      );
    }
    if (this.uncertain) {
      throw new ResourceError(
        'A previous active diagnostic has uncertain router-side state.',
        'active_diagnostic_uncertain'
      );
    }
    const cutoff = this.now() - 60_000;
    this.starts = this.starts.filter(start => start > cutoff);
    if (this.starts.length >= 10) {
      throw new ResourceError(
        'Active diagnostic rate limit reached (10 starts per 60 seconds).',
        'active_diagnostic_rate_limited'
      );
    }
    this.active = true;
    this.starts.push(this.now());
    try {
      return await operation();
    } catch (error) {
      if (error instanceof ActiveDiagnosticUncertainError) {
        // There is no live-proven router-side time ceiling after DELETE is not
        // acknowledged. Keep this server instance closed to active work.
        this.uncertain = true;
      }
      throw error;
    } finally {
      this.active = false;
    }
  }
}
