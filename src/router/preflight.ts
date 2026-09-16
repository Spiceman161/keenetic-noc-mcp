import { lookup } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';
import { connect } from 'node:tls';
import type { RouterProfile } from '../profiles/registry.js';
import type { KeeneticClient } from './client.js';
import type { CapabilityAccess, ProbedCapabilities } from './config-capabilities.js';
import { AuthError, RciError, TransportError } from './errors.js';

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
  verifyTls(hostname: string, port: number, timeoutMs: number): Promise<void>;
  sleep(ms: number): Promise<void>;
  now(): number;
}

const TLS_MAX_ATTEMPTS = 5;
const TLS_TOTAL_BUDGET_MS = 30_000;
const TLS_ATTEMPT_TIMEOUT_MS = 10_000;

type TlsFailureCategory = 'certificate' | 'timeout' | 'transient';

class TlsProbeError extends Error {
  constructor(readonly category: Exclude<TlsFailureCategory, 'transient'>) {
    super(category);
  }
}

const pass = (detail: string): PreflightCheck => ({ status: 'pass', detail });
const warning = (detail: string): PreflightCheck => ({ status: 'warning', detail });
const fail = (detail: string): PreflightCheck => ({ status: 'fail', detail });
const skipped = (detail: string): PreflightCheck => ({ status: 'skipped', detail });

async function resolveDns(hostname: string): Promise<number> {
  return (await lookup(hostname, { all: true })).length;
}

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object' || !('code' in error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

const certificateOrHostnameCodes = new Set([
  'AKID_ISSUER_SERIAL_MISMATCH',
  'AKID_SKID_MISMATCH',
  'CERT_CHAIN_TOO_LONG',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'CERT_REJECTED',
  'CERT_REVOKED',
  'CERT_SIGNATURE_FAILURE',
  'CERT_UNTRUSTED',
  'CRL_HAS_EXPIRED',
  'CRL_NOT_YET_VALID',
  'CRL_SIGNATURE_FAILURE',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'ERR_TLS_CERT_ALTNAME_FORMAT',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'ERROR_IN_CERT_NOT_AFTER_FIELD',
  'ERROR_IN_CERT_NOT_BEFORE_FIELD',
  'ERROR_IN_CRL_LAST_UPDATE_FIELD',
  'ERROR_IN_CRL_NEXT_UPDATE_FIELD',
  'INVALID_CA',
  'INVALID_NON_CA',
  'INVALID_PURPOSE',
  'KEYUSAGE_NO_CERTSIGN',
  'KEYUSAGE_NO_CRL_SIGN',
  'KEYUSAGE_NO_DIGITAL_SIGNATURE',
  'PATH_LENGTH_EXCEEDED',
  'PROXY_PATH_LENGTH_EXCEEDED',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'SUBJECT_ISSUER_MISMATCH',
  'UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY',
  'UNABLE_TO_DECRYPT_CERT_SIGNATURE',
  'UNABLE_TO_DECRYPT_CRL_SIGNATURE',
  'UNABLE_TO_GET_CRL',
  'UNABLE_TO_GET_CRL_ISSUER',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNHANDLED_CRITICAL_CRL_EXTENSION',
  'UNHANDLED_CRITICAL_EXTENSION'
]);

function isCertificateOrHostnameError(error: unknown): boolean {
  return certificateOrHostnameCodes.has(errorCode(error) ?? '');
}

function tlsFailureCategory(error: unknown): TlsFailureCategory {
  if (error instanceof TlsProbeError) return error.category;
  if (isCertificateOrHostnameError(error)) return 'certificate';
  return errorCode(error) === 'ETIMEDOUT' ? 'timeout' : 'transient';
}

async function verifyTls(hostname: string, port: number, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    // `servername` enables SNI and certificate hostname verification. The
    // default trust store and rejectUnauthorized=true remain in effect.
    const socket = connect({ host: hostname, port, servername: hostname, rejectUnauthorized: true });
    let finished = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: Error): void => {
      if (finished) return;
      finished = true;
      if (deadlineTimer) clearTimeout(deadlineTimer);
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };
    deadlineTimer = setTimeout(() => finish(new TlsProbeError('timeout')), timeoutMs);
    socket.setTimeout(timeoutMs, () => finish(new TlsProbeError('timeout')));
    socket.once('secureConnect', () => {
      if (!socket.authorized) finish(new TlsProbeError('certificate'));
      else finish();
    });
    socket.once('error', error => finish(isCertificateOrHostnameError(error) ||
      (!socket.authorized && Boolean(socket.authorizationError))
      ? new TlsProbeError('certificate') : error));
  });
}

const defaults: PreflightDependencies = {
  resolveDns,
  verifyTls,
  sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
  now: () => performance.now()
};

function withinDeadline<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new TlsProbeError('timeout')), timeoutMs);
    void operation.then(
      value => {
        clearTimeout(timer);
        resolve(value);
      },
      error => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

interface TlsProbeResult {
  failure: TlsFailureCategory | null;
  recovered: boolean;
}

async function verifyRemoteTls(
  hostname: string,
  port: number,
  deps: PreflightDependencies
): Promise<TlsProbeResult> {
  const deadline = deps.now() + TLS_TOTAL_BUDGET_MS;
  let lastFailure: TlsFailureCategory = 'timeout';

  for (let attempt = 1; attempt <= TLS_MAX_ATTEMPTS; attempt++) {
    const remaining = deadline - deps.now();
    if (remaining <= 0) return { failure: 'timeout', recovered: false };
    try {
      const attemptTimeout = Math.min(TLS_ATTEMPT_TIMEOUT_MS, remaining);
      await withinDeadline(deps.verifyTls(hostname, port, attemptTimeout), attemptTimeout);
      if (deps.now() >= deadline) return { failure: 'timeout', recovered: false };
      return { failure: null, recovered: attempt > 1 };
    } catch (error) {
      lastFailure = tlsFailureCategory(error);
      if (lastFailure === 'certificate' || attempt === TLS_MAX_ATTEMPTS) {
        return { failure: lastFailure, recovered: false };
      }
      const delay = 1_000 * 2 ** (attempt - 1);
      const remainingAfterFailure = deadline - deps.now();
      if (delay >= remainingAfterFailure) return { failure: 'timeout', recovered: false };
      try {
        await withinDeadline(deps.sleep(delay), remainingAfterFailure);
      } catch {
        return { failure: 'timeout', recovered: false };
      }
    }
  }
  return { failure: lastFailure, recovered: false };
}

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

function capabilityCheck(value: CapabilityAccess<string>, surface?: string): PreflightCheck {
  if (value.state === 'available') return pass(`available through ${value.method}`);
  return warning(`${surface ? `${surface} ` : ''}${value.state}: ${value.reason ?? 'unspecified'}`);
}

function probeFailureDetail(error: unknown): string {
  if (error instanceof AuthError) return 'capability probe authentication failed';
  if (error instanceof TransportError) return 'capability probe transport failed';
  if (error instanceof RciError) return 'capability probe RCI failure';
  return 'capability probe failed';
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

    const tls = await verifyRemoteTls(origin.hostname, origin.port, deps);
    if (!tls.failure) {
      checks['TLS'] = pass(tls.recovered
        ? 'certificate and hostname verified after retry'
        : 'certificate and hostname verified');
      checks['Reachability'] = pass('HTTPS endpoint reached');
    } else {
      checks['TLS'] = fail(tls.failure === 'certificate'
        ? 'certificate or hostname verification failed'
        : tls.failure === 'timeout'
          ? 'TLS connection timeout or retry budget exhausted'
          : 'transient TCP/TLS connection failed after bounded retries');
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

  const [configResult, system, internet, dns] = await Promise.all([
    client.probedCapabilities().catch((error: unknown) => error),
    diagnostic(client, 'show/system'),
    diagnostic(client, 'show/internet/status'),
    diagnostic(client, 'show/dns-proxy')
  ]);

  if (typeof configResult === 'object' && configResult !== null && 'config' in configResult) {
    const capabilities = configResult as ProbedCapabilities;
    checks['Running config'] = capabilityCheck(capabilities.config.runningCli);
    checks['Startup config'] = capabilityCheck(capabilities.config.startup);
    checks['Backup'] = profile.mode === 'remote'
      ? skipped('write backup requires a LAN profile for /ci/startup-config.txt; read-only use is ready')
      : capabilityCheck(capabilities.config.backup, '/ci/startup-config.txt');
  } else {
    const detail = probeFailureDetail(configResult);
    checks['Running config'] = warning(detail);
    checks['Startup config'] = warning(detail);
    checks['Backup'] = profile.mode === 'remote'
      ? skipped('write backup requires a LAN profile for /ci/startup-config.txt; read-only use is ready')
      : warning(detail);
  }
  checks['System diagnostic'] = system;
  checks['Internet diagnostic'] = internet;
  checks['DNS diagnostic'] = dns;

  return { ready: true, ...(model ? { model } : {}), ...(firmware ? { firmware } : {}), checks };
}
