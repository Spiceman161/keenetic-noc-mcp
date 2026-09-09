import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { normalizeRemoteUrl, type AuthMode } from '../config/load.js';

export interface RouterProfile {
  id: string;
  name: string;
  mode: AuthMode;
  /** LAN hostname for LAN profiles, normalized RCI URL for remote profiles. */
  endpoint: string;
  login: string;
  secretRef: string;
  default?: boolean;
  readOnly: boolean;
}

export interface Registration { client: 'codex' | 'claude'; instanceName: string }
export interface LastTest { at: string; overall: 'healthy' | 'degraded' | 'unhealthy'; checks: Record<string, string> }
interface RegistryFile { version: 1; profiles: RouterProfile[]; registrations?: Record<string, Registration[]> }

const registryPath = (dir: string): string => join(dir, 'routers.json');
const statePath = (dir: string): string => join(dir, 'router-state.json');

function validId(id: string): boolean { return /^[a-z][a-z0-9_-]{0,63}$/.test(id); }

async function atomicJson(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, '..'), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
}

export async function readProfiles(dir: string): Promise<RegistryFile> {
  try {
    const value = JSON.parse(await readFile(registryPath(dir), 'utf8')) as Partial<RegistryFile>;
    if (value.version !== 1 || !Array.isArray(value.profiles)) throw new Error('invalid registry');
    return { version: 1, profiles: value.profiles.filter(profile =>
      typeof profile.id === 'string' && validId(profile.id) && typeof profile.name === 'string' &&
      (profile.mode === 'lan' || profile.mode === 'remote') && typeof profile.endpoint === 'string' &&
      typeof profile.login === 'string' && typeof profile.secretRef === 'string' && typeof profile.readOnly === 'boolean'
    ), ...(value.registrations ? { registrations: value.registrations } : {}) };
  } catch { return { version: 1, profiles: [] }; }
}

export async function saveProfiles(dir: string, registry: RegistryFile): Promise<void> { await atomicJson(registryPath(dir), registry); }

export async function addProfile(dir: string, profile: RouterProfile): Promise<void> {
  if (!validId(profile.id)) throw new Error('Profile ID must start with a lowercase letter and contain only lowercase letters, digits, _ or -');
  if (!profile.name.trim() || !profile.login.trim()) throw new Error('Profile name and login are required');
  if (profile.mode === 'remote') profile.endpoint = normalizeRemoteUrl(profile.endpoint);
  const registry = await readProfiles(dir);
  if (registry.profiles.some(item => item.id === profile.id)) throw new Error(`Profile "${profile.id}" already exists`);
  if (profile.default || registry.profiles.length === 0) registry.profiles.forEach(item => { item.default = false; });
  registry.profiles.push(profile);
  await saveProfiles(dir, registry);
}

export async function getProfile(dir: string, id: string): Promise<RouterProfile | null> {
  return (await readProfiles(dir)).profiles.find(profile => profile.id === id) ?? null;
}

export async function resolveProfile(dir: string, requested?: string): Promise<RouterProfile | null> {
  const profiles = (await readProfiles(dir)).profiles;
  return profiles.find(item => item.id === requested) ?? (!requested ? profiles.find(item => item.default) ?? null : null);
}

export async function setDefaultProfile(dir: string, id: string): Promise<void> {
  const registry = await readProfiles(dir);
  let found = false;
  for (const profile of registry.profiles) { profile.default = profile.id === id; found ||= profile.default === true; }
  if (!found) throw new Error(`No profile named "${id}"`);
  await saveProfiles(dir, registry);
}

export async function removeProfile(dir: string, id: string): Promise<RouterProfile | null> {
  const registry = await readProfiles(dir);
  const profile = registry.profiles.find(item => item.id === id) ?? null;
  if (!profile) return null;
  registry.profiles = registry.profiles.filter(item => item.id !== id);
  if (profile.default && registry.profiles[0]) registry.profiles[0].default = true;
  if (registry.registrations) delete registry.registrations[id];
  await saveProfiles(dir, registry);
  return profile;
}

export async function saveRegistration(dir: string, id: string, registration: Registration): Promise<void> {
  const registry = await readProfiles(dir);
  if (!registry.profiles.some(p => p.id === id)) throw new Error(`No profile named "${id}"`);
  const registrations = registry.registrations ?? {};
  const previous = registrations[id] ?? [];
  registrations[id] = [...previous.filter(item => item.client !== registration.client), registration];
  registry.registrations = registrations;
  await saveProfiles(dir, registry);
}

export async function readLastTest(dir: string, id: string): Promise<LastTest | null> {
  try { const all = JSON.parse(await readFile(statePath(dir), 'utf8')) as Record<string, LastTest>; return all[id] ?? null; } catch { return null; }
}
export async function saveLastTest(dir: string, id: string, state: LastTest): Promise<void> {
  let all: Record<string, LastTest> = {};
  try { all = JSON.parse(await readFile(statePath(dir), 'utf8')) as Record<string, LastTest>; } catch { /* empty */ }
  all[id] = state;
  await atomicJson(statePath(dir), all);
}

export async function removeState(dir: string, id: string): Promise<void> {
  try { const all = JSON.parse(await readFile(statePath(dir), 'utf8')) as Record<string, LastTest>; delete all[id]; await atomicJson(statePath(dir), all); } catch { /* no state */ }
}

export async function removeRegistryForTests(dir: string): Promise<void> { await unlink(registryPath(dir)).catch(() => undefined); }
