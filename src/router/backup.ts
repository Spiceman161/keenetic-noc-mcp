import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { join, posix, win32 } from 'node:path';
import { STARTUP_CONFIG } from './config-state.js';
import type { Rci } from './rci.js';

export interface BackupResult {
  path: string;
  bytes: number;
  createdAt: string;
}

/** What every mutating tool needs from the backup machinery. */
export interface BackupGuard {
  ensure(): Promise<BackupResult>;
  taken(): BackupResult | null;
}

/**
 * Where a backup belongs on the given platform. KEENETIC_STATE_DIR overrides it.
 *
 * The path flavour is chosen from the `platform` argument rather than from the
 * host, so the Windows layout is still produced correctly when this runs
 * anywhere else. Using the ambient `join` would emit `C:\a/keenetic-noc-mcp`.
 */
export function stateDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  const override = env['KEENETIC_STATE_DIR'];
  if (override) return override;

  const home = env['HOME'] ?? env['USERPROFILE'] ?? '.';
  if (platform === 'win32') return win32.join(env['LOCALAPPDATA'] ?? home, 'keenetic-noc-mcp');
  if (platform === 'darwin') {
    return posix.join(home, 'Library', 'Application Support', 'keenetic-noc-mcp');
  }
  return posix.join(env['XDG_STATE_HOME'] ?? posix.join(home, '.local', 'state'), 'keenetic-noc-mcp');
}

export function createBackupGuard(rci: Rci, host: string, now: () => Date): BackupGuard {
  let done: BackupResult | null = null;
  let pending: Promise<BackupResult> | null = null;

  async function take(): Promise<BackupResult> {
    // startup-config, not running-config: the point is to capture the state a
    // reboot would return to.
    const text = await rci.getText(STARTUP_CONFIG);
    const dir = join(stateDir(process.platform, process.env), 'backups');
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await chmod(dir, 0o700);

    const createdAt = now().toISOString();
    const stamp = createdAt.replace(/[:.]/g, '-');
    // routerId is operator-controlled for environment-based launches. Keep it
    // a filename component even if a malformed value contains path separators.
    const safeHost = host.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '') || 'router';
    const path = join(dir, `${safeHost}-${stamp}.txt`);
    await writeFile(path, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await chmod(path, 0o600);

    done = { path, bytes: Buffer.byteLength(text, 'utf8'), createdAt };
    return done;
  }

  return {
    ensure(): Promise<BackupResult> {
      if (done) return Promise.resolve(done);
      // Latched like the auth handshake: concurrent writes must not race to
      // snapshot the same configuration twice.
      pending ??= take().finally(() => {
        pending = null;
      });
      return pending;
    },
    taken: () => done
  };
}
