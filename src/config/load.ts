import { readFile } from 'node:fs/promises';

export type AuthMode = 'lan' | 'remote';
export interface AppConfig {
  routerId: string;
  mode: AuthMode;
  host: string;
  endpoint: string;
  login: string;
  password: string;
  readOnly: boolean;
  maxResponseBytes: number;
  timeoutMs: number;
  allowRawWrite: boolean;
}

export interface StoredCredentials {
  host?: string;
  login?: string;
  password?: string;
}

export const DEFAULT_MAX_RESPONSE_BYTES = 25_000;
export const MIN_MAX_RESPONSE_BYTES = 512;
export const DEFAULT_LAN_TIMEOUT_MS = 10_000;
export const DEFAULT_REMOTE_TIMEOUT_MS = 30_000;

export function normalizeRemoteUrl(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== 'https:') throw new Error('KEENETIC_URL must use https://');
  if (url.username || url.password) throw new Error('KEENETIC_URL must not contain credentials');
  if (url.search || url.hash) throw new Error('KEENETIC_URL must not contain query or fragment');
  if (url.pathname === '/' || url.pathname === '' || url.pathname === '/rci') url.pathname = '/rci/';
  if (url.pathname !== '/rci/') throw new Error('KEENETIC_URL path must be /rci/');
  return url.toString();
}

function bool(env: NodeJS.ProcessEnv, name: string): boolean {
  return env[name]?.toLowerCase() === 'true';
}

function flagValue(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

/**
 * Merges the three sources of configuration.
 *
 * The environment wins over both the flag and the stored value: a container or
 * a CI run has no keychain to read, and must never be redirected by whatever
 * happens to be configured on a developer machine.
 */
export async function loadConfig(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  stored?: StoredCredentials
): Promise<AppConfig> {
  const rawUrl = env['KEENETIC_URL'];
  const explicitMode = env['KEENETIC_AUTH_MODE'];
  if (explicitMode && explicitMode !== 'lan' && explicitMode !== 'remote') {
    throw new Error('KEENETIC_AUTH_MODE must be "lan" or "remote"');
  }
  const mode: AuthMode = (explicitMode as AuthMode | undefined) ?? (rawUrl ? 'remote' : 'lan');
  const host = env['KEENETIC_HOST'] ?? flagValue(argv, '--host') ?? stored?.host ?? '';
  const passwordFile = env['KEENETIC_PASSWORD_FILE'];
  const filePassword = passwordFile ? (await readFile(passwordFile, 'utf8')).trimEnd() : undefined;
  const password = env['KEENETIC_PASSWORD'] ?? filePassword ?? stored?.password;
  const defaultTimeoutMs = mode === 'remote' ? DEFAULT_REMOTE_TIMEOUT_MS : DEFAULT_LAN_TIMEOUT_MS;
  const timeoutMs = Number.parseInt(env['KEENETIC_TIMEOUT_MS'] ?? String(defaultTimeoutMs), 10);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('KEENETIC_TIMEOUT_MS must be a positive integer');
  const login = env['KEENETIC_USER'] ?? stored?.login ?? 'admin';

  const rawMax = flagValue(argv, '--max-response-bytes');
  const parsedMax = rawMax === undefined ? DEFAULT_MAX_RESPONSE_BYTES : Number.parseInt(rawMax, 10);
  if (!Number.isFinite(parsedMax) || parsedMax < MIN_MAX_RESPONSE_BYTES) {
    throw new Error(`--max-response-bytes must be an integer of at least ${MIN_MAX_RESPONSE_BYTES}, got "${rawMax}"`);
  }

  if ((mode === 'lan' && !host) || (mode === 'remote' && !rawUrl) || !password) {
    throw new Error(
      'No router configured. Run "npx keenetic-noc-mcp router add" to set one up, or set ' +
        'KEENETIC_HOST (or KEENETIC_URL), KEENETIC_USER, and KEENETIC_PASSWORD_FILE.'
    );
  }

  return {
    routerId: env['KEENETIC_ROUTER_ID']?.trim() || 'home',
    mode,
    host,
    endpoint: mode === 'remote' ? normalizeRemoteUrl(rawUrl as string) : `http://${host}/rci/`,
    login,
    password,
    readOnly: argv.includes('--read-only'),
    maxResponseBytes: parsedMax,
    timeoutMs,
    allowRawWrite: bool(env, 'KEENETIC_ALLOW_RAW_WRITE')
  };
}
