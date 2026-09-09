import { lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join, posix, win32 } from 'node:path';

export function gatewayCommand(platform: NodeJS.Platform): { command: string; args: string[] } {
  if (platform === 'darwin') return { command: 'route', args: ['-n', 'get', 'default'] };
  if (platform === 'win32') {
    return {
      command: 'powershell',
      args: ['-NoProfile', '-Command', '(Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop']
    };
  }
  return { command: 'ip', args: ['route', 'show', 'default'] };
}

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;

export function parseGateway(platform: NodeJS.Platform, stdout: string): string | null {
  if (platform === 'darwin') {
    const line = stdout.split('\n').find(l => l.trim().startsWith('gateway:'));
    return line?.match(IPV4)?.[1] ?? null;
  }
  if (platform === 'win32') {
    return stdout.match(IPV4)?.[1] ?? null;
  }
  const line = stdout.split('\n').find(l => l.startsWith('default'));
  return line?.match(IPV4)?.[1] ?? null;
}

/**
 * Confirms a host is a Keenetic by asking for /auth and reading the realm,
 * which is the same signal the session layer authenticates against. Anything
 * else answering on port 80 will not carry that header.
 */
export async function identifyRouter(
  host: string,
  fetchImpl: typeof fetch = fetch
): Promise<{ realm: string } | null> {
  try {
    const res = await fetchImpl(`http://${host}/auth`, {
      signal: AbortSignal.timeout(4000),
      redirect: 'manual'
    });
    const realm = res.headers.get('X-NDM-Realm');
    return realm ? { realm } : null;
  } catch {
    return null;
  }
}

function platformConfigDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv, directory: string): string {
  const home = env['HOME'] ?? env['USERPROFILE'] ?? '.';
  if (platform === 'win32') return win32.join(env['APPDATA'] ?? home, directory);
  if (platform === 'darwin') {
    return posix.join(home, 'Library', 'Application Support', directory);
  }
  return posix.join(env['XDG_CONFIG_HOME'] ?? posix.join(home, '.config'), directory);
}

/** The directory advertised by the package and used by every normal MCP launch. */
export function configDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  return env['KEENETIC_CONFIG_DIR'] ?? platformConfigDir(platform, env, 'keenetic-noc-mcp');
}

function legacyConfigDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string | null {
  // An explicit directory belongs to the operator. Never infer or move data
  // beside it, even if it happens to be empty.
  if (env['KEENETIC_CONFIG_DIR']) return null;
  return platformConfigDir(platform, env, 'keenetic-mcp');
}

/**
 * Moves the pre-release profile directory to the published package location.
 *
 * A rename preserves file ownership and restrictive modes for file-backed
 * secrets. It runs only when the canonical directory is absent: configurations
 * are never merged, overwritten, or copied between two existing directories.
 */
export async function migrateLegacyConfigDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): Promise<boolean> {
  const legacy = legacyConfigDir(platform, env);
  if (legacy === null) return false;
  const target = configDir(platform, env);
  try {
    await lstat(target);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return false;
    // The target is absent; inspect the source before attempting its atomic move.
  }
  try {
    if (!(await lstat(legacy)).isDirectory()) return false;
    await rename(legacy, target);
    return true;
  } catch {
    // Setup must remain usable even when no legacy directory exists or a
    // concurrent process has already created the canonical one.
    return false;
  }
}

export interface StoredConfig {
  host: string;
  login: string;
}

const FILE = 'config.json';

export async function readStoredConfig(dir: string): Promise<StoredConfig | null> {
  try {
    const parsed = JSON.parse(await readFile(join(dir, FILE), 'utf8')) as Partial<StoredConfig>;
    if (typeof parsed.host !== 'string' || typeof parsed.login !== 'string') return null;
    return { host: parsed.host, login: parsed.login };
  } catch {
    return null;
  }
}

/**
 * JSON rather than TOML: Node has no built-in parser and three fields do not
 * justify a dependency. The password is never written here; it lives in the
 * keychain, keyed by `login@host`.
 */
export async function writeStoredConfig(dir: string, config: StoredConfig): Promise<string> {
  await mkdir(dir, { recursive: true });
  const path = join(dir, FILE);
  await writeFile(
    path,
    `${JSON.stringify({ host: config.host, login: config.login }, null, 2)}\n`,
    'utf8'
  );
  return path;
}
