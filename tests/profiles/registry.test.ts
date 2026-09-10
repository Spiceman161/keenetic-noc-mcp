import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { addProfile, readLastTest, readProfiles, resolveProfile, saveLastTest, setDefaultProfile } from '../../src/profiles/registry.js';
import { createProfileSecretStore, generatePassword, keychainAvailable } from '../../src/profiles/secrets.js';

describe('router profiles', () => {
  it('stores only profile metadata and resolves the default', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-profiles-'));
    await addProfile(dir, { id: 'home', name: 'Home', mode: 'lan', endpoint: '192.0.2.1', login: 'mcp_agent', secretRef: 'keychain:router:home', default: true, readOnly: true });
    await addProfile(dir, { id: 'remote', name: 'Remote', mode: 'remote', endpoint: 'https://rci.example.test/rci/', login: 'mcp_agent', secretRef: 'keychain:router:remote', readOnly: true });
    await setDefaultProfile(dir, 'remote');
    expect((await resolveProfile(dir))?.id).toBe('remote');
    const contents = await readFile(join(dir, 'routers.json'), 'utf8');
    expect(contents).not.toMatch(/password|hunter2/i);
    expect((await readProfiles(dir)).profiles).toHaveLength(2);
  });

  it('atomically keeps bounded, secret-free last test state', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-state-'));
    await saveLastTest(dir, 'home', { at: '2026-09-09T13:12:00.000Z', overall: 'healthy', checks: { RCI: '✓' } });
    expect(await readLastTest(dir, 'home')).toEqual({ at: '2026-09-09T13:12:00.000Z', overall: 'healthy', checks: { RCI: '✓' } });
  });

  it('generates a 24-character password with every required character class', () => {
    const value = generatePassword();
    expect(value).toHaveLength(24);
    expect(value).toMatch(/[a-z]/); expect(value).toMatch(/[A-Z]/); expect(value).toMatch(/[0-9]/); expect(value).toMatch(/[!@#$%^&*_\-+=]/);
  });

  it('uses an owner-only per-profile fallback file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-secret-'));
    const store = await createProfileSecretStore(dir, 'file');
    await store.save('home', 'not-in-registry');
    expect(await store.read('home')).toBe('not-in-registry');
    expect((await stat(join(dir, 'secrets'))).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, 'secrets', 'home'))).mode & 0o777).toBe(0o600);
  });

  it('rejects a keychain probe whose disposable secret cannot be removed', async () => {
    let saved = '';
    const store = {
      save: vi.fn(async (_account: string, secret: string) => { saved = secret; return 'the system keychain'; }),
      read: vi.fn(async (_account: string) => saved),
      remove: vi.fn(async () => { throw new Error('cleanup failed'); })
    };
    await expect(keychainAvailable(store)).resolves.toBe(false);
    expect(store.remove).toHaveBeenCalledOnce();
  });
});
