import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createKeychainStore, spawnRunner, type SecretStore } from '../config/secrets.js';

export type ProfileSecretBackend = 'keychain' | 'file';
export interface ProfileSecretStore {
  backend: ProfileSecretBackend;
  ref(id: string): string;
  save(id: string, secret: string): Promise<void>;
  read(id: string): Promise<string | null>;
  remove(id: string): Promise<void>;
}

const account = (id: string): string => `router:${id}`;

/** A password suitable for a dedicated router account, never persisted here. */
export function generatePassword(): string {
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digit = '23456789';
  const symbol = '!@#$%^&*_-+=';
  const sets = [lower, upper, digit, symbol];
  const bytes = randomBytes(24);
  const chars = sets.map((set, index) => set[bytes[index] as number % set.length] as string);
  const alphabet = sets.join('');
  for (let index = chars.length; index < 24; index += 1) chars.push(alphabet[bytes[index] as number % alphabet.length] as string);
  // Fisher-Yates, using independent random bytes, prevents fixed category positions.
  const shuffle = randomBytes(chars.length);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const target = (shuffle[index] as number) % (index + 1);
    [chars[index], chars[target]] = [chars[target] as string, chars[index] as string];
  }
  return chars.join('');
}

export async function keychainAvailable(store: SecretStore): Promise<boolean> {
  const probe = `probe:${randomBytes(12).toString('hex')}`;
  const secret = randomBytes(18).toString('base64url');
  try {
    const result = await store.save(probe, secret);
    const value = await store.read(probe);
    await store.remove(probe);
    return result === 'the system keychain' && value === secret;
  } catch { return false; }
}

async function isGitWorktree(path: string): Promise<boolean> {
  let current = resolve(path);
  while (dirname(current) !== current) {
    try { await readFile(join(current, '.git')); return true; } catch { /* .git can be a directory */ }
    try { const stat = await import('node:fs/promises').then(fs => fs.stat(join(current, '.git'))); if (stat.isDirectory()) return true; } catch { /* onward */ }
    current = dirname(current);
  }
  return false;
}

export async function createProfileSecretStore(dir: string, backend: ProfileSecretBackend): Promise<ProfileSecretStore> {
  if (backend === 'keychain') {
    const store = createKeychainStore(process.platform, spawnRunner);
    return {
      backend, ref: id => `keychain:${account(id)}`,
      async save(id, secret) { const where = await store.save(account(id), secret); if (where !== 'the system keychain' || await store.read(account(id)) !== secret) throw new Error('System keychain could not save the password'); },
      read: id => store.read(account(id)), remove: id => store.remove(account(id))
    };
  }
  if (await isGitWorktree(dir)) throw new Error('File secret fallback is not allowed inside a Git worktree');
  const secrets = join(dir, 'secrets');
  return {
    backend, ref: id => `file:${id}`,
    async save(id, secret) {
      await mkdir(secrets, { recursive: true, mode: 0o700 }); await chmod(secrets, 0o700);
      const path = join(secrets, id); const tmp = `${path}.${process.pid}.tmp`;
      await writeFile(tmp, `${secret}\n`, { mode: 0o600 }); await chmod(tmp, 0o600); await rename(tmp, path);
    },
    async read(id) { try { return (await readFile(join(secrets, id), 'utf8')).trimEnd(); } catch { return null; } },
    async remove(id) { await rm(join(secrets, id), { force: true }); }
  };
}
