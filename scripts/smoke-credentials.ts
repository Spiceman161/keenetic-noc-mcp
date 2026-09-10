import { configDir, migrateLegacyConfigDir } from '../src/config/discover.js';
import { resolveProfile } from '../src/profiles/registry.js';
import { createProfileSecretStore, type ProfileSecretBackend } from '../src/profiles/secrets.js';

export interface RemoteSmokeCredentials {
  endpoint: string;
  login: string;
  password: string;
  routerId: string;
  source: 'environment' | 'profile';
}

function routerArgument(argv: readonly string[]): string | undefined {
  const index = argv.indexOf('--router');
  if (index === -1) {
    if (argv.length > 0) throw new Error(`Unknown smoke argument "${argv[0]}". Use --router <profile-id>.`);
    return undefined;
  }
  const id = argv[index + 1];
  if (!id || id.startsWith('--')) throw new Error('--router requires a profile ID.');
  if (argv.length !== 2 || index !== 0) throw new Error('Use only --router <profile-id> for profile selection.');
  return id;
}

/** Loads an explicit CI environment or, by default, the normal profile registry. */
export async function loadRemoteSmokeCredentials(
  argv: readonly string[], env: NodeJS.ProcessEnv
): Promise<RemoteSmokeCredentials> {
  const endpoint = env['KEENETIC_TEST_URL'];
  const login = env['KEENETIC_TEST_USER'];
  const password = env['KEENETIC_TEST_PASSWORD'];
  if (endpoint || login || password) {
    if (!endpoint || !login || !password) {
      throw new Error('Set all of KEENETIC_TEST_URL, KEENETIC_TEST_USER and KEENETIC_TEST_PASSWORD.');
    }
    return { endpoint, login, password, routerId: env['KEENETIC_ROUTER_ID']?.trim() || 'smoke', source: 'environment' };
  }

  const requested = routerArgument(argv);
  await migrateLegacyConfigDir(process.platform, env);
  const dir = configDir(process.platform, env);
  const profile = await resolveProfile(dir, requested);
  if (!profile) throw new Error(requested ? `No profile named "${requested}".` : 'No default router profile is configured.');
  if (profile.mode !== 'remote') throw new Error(`Profile "${profile.id}" is not a remote profile.`);
  const backend: ProfileSecretBackend = profile.secretRef.startsWith('file:') ? 'file' : 'keychain';
  const secret = await (await createProfileSecretStore(dir, backend)).read(profile.id);
  if (!secret) throw new Error(`Password for profile "${profile.id}" is unavailable.`);
  return { endpoint: profile.endpoint, login: profile.login, password: secret, routerId: profile.id, source: 'profile' };
}
