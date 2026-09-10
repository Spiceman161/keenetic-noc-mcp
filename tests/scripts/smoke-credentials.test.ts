import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadRemoteSmokeCredentials } from '../../scripts/smoke-credentials.js';
import { addProfile } from '../../src/profiles/registry.js';
import { createProfileSecretStore } from '../../src/profiles/secrets.js';

describe('remote smoke credentials', () => {
  it('loads the default remote profile and its secret without CLI plumbing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-smoke-profile-'));
    await addProfile(dir, { id: 'remote', name: 'Remote', mode: 'remote',
      endpoint: 'https://rci.example.test/rci/', login: 'agent', secretRef: 'file:remote',
      default: true, readOnly: true });
    await (await createProfileSecretStore(dir, 'file')).save('remote', 'not-a-real-password');

    await expect(loadRemoteSmokeCredentials([], { KEENETIC_CONFIG_DIR: dir })).resolves.toEqual({
      endpoint: 'https://rci.example.test/rci/', login: 'agent', password: 'not-a-real-password',
      routerId: 'remote', source: 'profile'
    });
  });

  it('selects a named profile with --router', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-smoke-profile-'));
    await addProfile(dir, { id: 'selected', name: 'Selected', mode: 'remote',
      endpoint: 'https://selected.example.test/rci/', login: 'agent', secretRef: 'file:selected',
      readOnly: true });
    await (await createProfileSecretStore(dir, 'file')).save('selected', 'not-a-real-password');
    const result = await loadRemoteSmokeCredentials(['--router', 'selected'], { KEENETIC_CONFIG_DIR: dir });
    expect(result.routerId).toBe('selected');
  });

  it('keeps the complete test environment as the CI override', async () => {
    const result = await loadRemoteSmokeCredentials([], {
      KEENETIC_TEST_URL: 'https://ci.example.test/rci/', KEENETIC_TEST_USER: 'ci-agent',
      KEENETIC_TEST_PASSWORD: 'not-a-real-password'
    });
    expect(result).toMatchObject({ source: 'environment', routerId: 'smoke' });
  });

  it('rejects partial environment credentials instead of mixing sources', async () => {
    await expect(loadRemoteSmokeCredentials([], {
      KEENETIC_TEST_URL: 'https://ci.example.test/rci/'
    })).rejects.toThrow(/Set all/);
  });
});
