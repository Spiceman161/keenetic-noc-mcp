import { lookup } from 'node:dns/promises';
import { connect } from 'node:tls';
import type { RouterProfile } from '../profiles/registry.js';
import type { KeeneticClient } from './client.js';
import { probeConfigCapabilities } from './config-capabilities.js';
import { AuthError, RciError, TransportError } from './errors.js';
import { STARTUP_CONFIG } from './config-state.js';

export interface PreflightCheck {
  status: 'pass' | 'warning' | 'fail' | 'skipped';
  detail: string;
}

export interface PreflightReport {
  ready: boolean;
  model?: string;
  firmware?: string;
  checks: Record<string, PreflightCheck>;
}

export interface PreflightDependencies {
  resolveDns(hostname: string): Promise<number>;
  verifyTls(hostname: string, port: number): Promise<void>;
}

const pass = (detail: string): PreflightCheck => ({ status: 'pass', detail });
const warning = (detail: string): PreflightCheck => ({ status: 'warning', detail });
const fail = (detail: string): PreflightCheck => ({ status: 'fail', detail });
const skipped = (detail: string): PreflightCheck => ({ status: 'skipped', detail });

async function resolveDns(hostname: string): Promise<number> {
  return (await lookup(hostname, { all: true })).length;
}

async function verifyTls(hostname: string, port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    // `servername` enables SNI and certificate hostname verification. The
    // default trust store and rejectUnauthorized=true remain in effect.
    const socket = connect({ host: hostname, port, servername: hostname, rejectUnauthorized: true });
    const finish = (error?: Error): void => {
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };
    socket.setTimeout(10_000, () => finish(new Error('TLS connection timed out')));
    socket.once('secureConnect', () => finish());
    socket.once('error', error => finish(error));
  });
}

const defaults: PreflightDependencies = { resolveDns, verifyTls };

function remoteOrigin(endpoint: string): { hostname: string; port: number } {
  const url = new URL(endpoint);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      !url.hostname || (url.pathname !== '/rci' && url.pathname !== '/rci/')) {
    throw new Error('invalid remote endpoint');
  }
  return { hostname: url.hostname, port: url.port ? Number(url.port) : 443 };
}

async function diagnostic(client: KeeneticClient, path: string): Promise<PreflightCheck> {
  try {
    // Responses are deliberately discarded: preflight reports availability,
    // never router data or untrusted diagnostic content.
    await client.rci.get(path, 256_000);
    return pass('available');
  } catch {
    return warning('unavailable');
  }
}

function safeTerminalField(value: string): string {
  const withoutOsc = value.replace(/\u001b\][^\u0007]*(?:\u0007|$)/g, '');
  const withoutAnsi = withoutOsc.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '');
  const singleLine = withoutAnsi.replace(/[\p{Cc}\p{Cf}]/gu, ' ').replace(/\s+/g, ' ').trim();
  return Array.from(singleLine).slice(0, 120).join('');
}

/**
 * Performs read-only onboarding probes and returns only bounded, sanitized
 * facts. A warning denotes an optional capability and never credentials.
 */
export async function runRouterPreflight(
  profile: Pick<RouterProfile, 'mode' | 'endpoint'>,
  client: KeeneticClient,
  dependencies: Partial<PreflightDependencies> = {}
): Promise<PreflightReport> {
  const deps = { ...defaults, ...dependencies };
  const checks: Record<string, PreflightCheck> = {};

  if (profile.mode === 'remote') {
    let origin: { hostname: string; port: number };
    try {
      origin = remoteOrigin(profile.endpoint);
    } catch {
      checks['Endpoint'] = fail('invalid HTTPS endpoint');
      return { ready: false, checks };
    }
    checks['Endpoint'] = pass('valid HTTPS endpoint');

    try {
      const count = await deps.resolveDns(origin.hostname);
      if (count < 1) throw new Error('no addresses');
      checks['DNS resolution'] = pass(`${count} address${count === 1 ? '' : 'es'}`);
    } catch {
      checks['DNS resolution'] = fail('failed');
      checks['TLS'] = skipped('DNS resolution failed');
      checks['Reachability'] = skipped('DNS resolution failed');
      checks['Authentication'] = skipped('endpoint unavailable');
      checks['RCI'] = skipped('endpoint unavailable');
      return { ready: false, checks };
    }

    try {
      await deps.verifyTls(origin.hostname, origin.port);
      checks['TLS'] = pass('certificate and hostname verified');
      checks['Reachability'] = pass('HTTPS endpoint reached');
    } catch {
      checks['TLS'] = fail('certificate or TLS connection failed');
      checks['Reachability'] = skipped('TLS connection failed');
      checks['Authentication'] = skipped('secure endpoint unavailable');
      checks['RCI'] = skipped('secure endpoint unavailable');
      return { ready: false, checks };
    }
  } else {
    checks['Endpoint'] = pass('LAN endpoint accepted');
    checks['DNS resolution'] = skipped('not required for LAN');
    checks['TLS'] = skipped('not required for LAN');
  }

  let model: string | undefined;
  let firmware: string | undefined;
  try {
    const capabilities = await client.capabilities();
    model = safeTerminalField(capabilities.model) || undefined;
    firmware = safeTerminalField(capabilities.firmware) || undefined;
    checks['Reachability'] = pass(profile.mode === 'remote' ? 'HTTPS endpoint reached' : 'router reached');
    checks['Authentication'] = pass('accepted');
    checks['RCI'] = pass('show/version available');
  } catch (error) {
    if (error instanceof TransportError) {
      checks['Reachability'] = fail('router unreachable');
      checks['Authentication'] = skipped('router unreachable');
      checks['RCI'] = skipped('router unreachable');
    } else if (error instanceof AuthError) {
      checks['Reachability'] ??= pass('router reached');
      checks['Authentication'] = fail('credentials rejected');
      checks['RCI'] = skipped('authentication failed');
    } else if (error instanceof RciError) {
      checks['Reachability'] ??= pass('router reached');
      checks['Authentication'] = pass('accepted');
      checks['RCI'] = fail('show/version failed');
    } else {
      checks['Reachability'] ??= fail('connection failed');
      checks['Authentication'] = skipped('could not be established');
      checks['RCI'] = fail('show/version failed');
    }
    return { ready: false, checks };
  }

  const [config, system, internet, dns, backup] = await Promise.all([
    probeConfigCapabilities(client.rci).catch(() => null),
    diagnostic(client, 'show/system'),
    diagnostic(client, 'show/internet/status'),
    diagnostic(client, 'show/dns-proxy'),
    profile.mode === 'lan'
      ? client.rci.getText(STARTUP_CONFIG, 256_000).then(() => pass('available through /ci/startup-config.txt')).catch(() => warning('unavailable through /ci/startup-config.txt'))
      : Promise.resolve(skipped('write backup requires a LAN profile for /ci/startup-config.txt; read-only use is ready'))
  ]);

  if (config) {
    checks['Running config'] = config.runningConfig.available
      ? pass('available through RCI')
      : warning('unavailable through RCI');
    checks['Startup config'] = config.startupConfig.available
      ? pass('available through RCI')
      : warning('unavailable through RCI');
  } else {
    checks['Running config'] = warning('capability probe failed');
    checks['Startup config'] = warning('capability probe failed');
  }
  checks['System diagnostic'] = system;
  checks['Internet diagnostic'] = internet;
  checks['DNS diagnostic'] = dns;
  checks['Backup'] = backup;

  return { ready: true, ...(model ? { model } : {}), ...(firmware ? { firmware } : {}), checks };
}
