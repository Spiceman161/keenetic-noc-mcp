import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { link, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createKeychainStore, spawnRunner } from '../config/secrets.js';
import { addProfile, readProfiles, saveRegistration, type RouterProfile } from '../profiles/registry.js';
import { createProfileSecretStore, generatePassword, keychainAvailable, type ProfileSecretBackend, type ProfileSecretStore } from '../profiles/secrets.js';
import { createClient, createRemoteClient, type KeeneticClient } from '../router/client.js';
import { runRouterPreflight, type PreflightReport } from '../router/preflight.js';
import { DEV_VERSION, resolveVersion } from '../version.js';
import { accountInstructions } from './ui/hints.js';
import type { PromptAdapter, PromptResult } from './ui/prompts.js';
import { deriveProfileId, normalizeWizardEndpoint } from './router-wizard-helpers.js';

export type RegistrationChoice = 'neither' | 'codex' | 'claude' | 'both';

export interface RouterWizardDraft {
  name: string;
  id: string;
  mode: 'remote' | 'lan';
  endpoint: string;
  login: string;
  password: string;
  backend?: ProfileSecretBackend;
  registration: RegistrationChoice;
  preflight?: PreflightReport;
}

export interface RegistrationInvocation { command: string; args: string[] }
export interface McpServerLaunch { command: string; args: string[] }

// Exact SemVer only: this value becomes part of an executable npm package
// spec, so ranges, tags, aliases, paths, and URLs must never be accepted.
const EXACT_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** Uses stable absolute paths instead of assuming the package bin is global. */
export function currentMcpServerLaunch(
  executable = process.execPath,
  entrypoint = process.argv[1],
  options: { platform?: NodeJS.Platform; version?: string } = {}
): McpServerLaunch {
  if (!entrypoint) throw new Error('Cannot register MCP: the current entrypoint is unavailable');
  const resolvedEntrypoint = realpathSync(entrypoint);
  if (resolvedEntrypoint.replaceAll('\\', '/').includes('/_npx/')) {
    const version = options.version ?? resolveVersion();
    if (version === DEV_VERSION) {
      throw new Error('Cannot durably register a development build from the temporary npx cache; run it from a checkout or install it first');
    }
    if (!EXACT_SEMVER.test(version)) {
      throw new Error('Cannot durably register from npx without an exact semantic version');
    }
    return { command: (options.platform ?? process.platform) === 'win32' ? 'npx.cmd' : 'npx',
      args: ['-y', `keenetic-noc-mcp@${version}`] };
  }
  return { command: realpathSync(executable), args: [resolvedEntrypoint] };
}

export function registrationInvocation(
  client: 'codex' | 'claude',
  id: string,
  server = currentMcpServerLaunch()
): RegistrationInvocation {
  const instance = `keenetic_${id}`;
  return { command: client, args: ['mcp', 'add', instance, '--', server.command,
    ...server.args, '--router', id, '--read-only'] };
}

export function registrationPreview(invocation: RegistrationInvocation): string {
  // JSON escaping keeps control characters and shell metacharacters inert on
  // every platform. This is deliberately display-only, not a shell command.
  return JSON.stringify([invocation.command, ...invocation.args]);
}

export interface RouterWizardDependencies {
  readProfiles(dir: string): ReturnType<typeof readProfiles>;
  generatePassword(): string;
  keychainAvailable(): Promise<boolean>;
  createSecretStore(dir: string, backend: ProfileSecretBackend): Promise<ProfileSecretStore>;
  createClient(profile: Pick<RouterProfile, 'id' | 'mode' | 'endpoint' | 'login'>, password: string): KeeneticClient;
  preflight(profile: Pick<RouterProfile, 'mode' | 'endpoint'>, client: KeeneticClient): Promise<PreflightReport>;
  addProfile(dir: string, profile: RouterProfile): Promise<void>;
  serverLaunch(): McpServerLaunch;
  runRegistration(invocation: RegistrationInvocation): Promise<number>;
  saveRegistration(dir: string, id: string, client: 'codex' | 'claude', instanceName: string): Promise<void>;
  withPersistenceLock<T>(dir: string, task: (recoveredStaleLock: boolean) => Promise<T>): Promise<T>;
}

interface PersistenceLock { pid: number; token: string; createdAt: number }

function processExists(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}

async function readLock(path: string): Promise<PersistenceLock | null> {
  try {
    const value = JSON.parse(await readFile(path, 'utf8')) as Partial<PersistenceLock>;
    return Number.isSafeInteger(value.pid) && (value.pid ?? 0) > 0 && typeof value.token === 'string' &&
      Number.isSafeInteger(value.createdAt) && (value.createdAt ?? 0) > 0
      ? { pid: value.pid as number, token: value.token, createdAt: value.createdAt as number } : null;
  } catch { return null; }
}

export async function withPersistenceLock<T>(dir: string, task: (recoveredStaleLock: boolean) => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, '.router-add.lock');
  const mine: PersistenceLock = { pid: process.pid, token: randomUUID(), createdAt: Date.now() };
  const candidate = join(dir, `.router-add.${mine.token}.candidate`);
  await writeFile(candidate, `${JSON.stringify(mine)}\n`, { flag: 'wx', mode: 0o600 });
  let recoveredStaleLock = false;
  try {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try { await link(candidate, lock); break; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        const owner = await readLock(lock);
        if (owner && processExists(owner.pid)) throw new Error('Another router setup is currently being saved; retry after it completes');
        await unlink(lock).catch(current => {
          if ((current as NodeJS.ErrnoException).code !== 'ENOENT') throw current;
        });
        recoveredStaleLock = true;
        if (attempt === 2) throw new Error('Could not recover a stale router setup lock');
      }
    }
    try { return await task(recoveredStaleLock); }
    finally {
      const owner = await readLock(lock);
      if (owner?.token === mine.token) await unlink(lock).catch(() => undefined);
    }
  } finally {
    await unlink(candidate).catch(() => undefined);
  }
}

async function rollbackSecret(store: ProfileSecretStore, id: string, primary: unknown): Promise<never> {
  try { await store.remove(id); }
  catch (cleanup) {
    throw new AggregateError([primary, cleanup], `Profile was not saved and its local secret for "${id}" could not be removed; remove it before retrying`);
  }
  throw primary;
}

const defaultDependencies: RouterWizardDependencies = {
  readProfiles,
  generatePassword,
  keychainAvailable: () => keychainAvailable(createKeychainStore(process.platform, spawnRunner)),
  createSecretStore: createProfileSecretStore,
  createClient(profile, password) {
    return profile.mode === 'remote'
      ? createRemoteClient({ endpoint: profile.endpoint, login: profile.login, password, routerId: profile.id })
      : createClient({ host: profile.endpoint, login: profile.login, password });
  },
  preflight: runRouterPreflight,
  addProfile,
  serverLaunch: currentMcpServerLaunch,
  runRegistration: invocation => new Promise(resolve => {
    const child = spawn(invocation.command, invocation.args, { stdio: 'inherit' });
    child.on('close', code => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  }),
  saveRegistration: (dir, id, client, instanceName) => saveRegistration(dir, id, { client, instanceName }),
  withPersistenceLock
};

function value<T>(result: PromptResult<T>): T | undefined {
  return result.kind === 'value' ? result.value : undefined;
}

function preflightText(report: PreflightReport): string {
  const lines = Object.entries(report.checks).map(([name, check]) => {
    const mark = check.status === 'pass' ? '✓' : check.status === 'fail' ? '✗' : check.status === 'warning' ? '!' : '-';
    return `${mark} ${name}: ${check.detail}`;
  });
  return [`Preflight: ${report.ready ? 'ready' : 'not ready'}`, ...lines].join('\n');
}

function review(draft: RouterWizardDraft, isDefault: boolean): string {
  return `Review

Profile ID:       ${draft.id}
Name:             ${draft.name}
Mode:             ${draft.mode === 'remote' ? 'remote KeenDNS' : 'LAN'}
Endpoint:         ${draft.endpoint}
Router:           ${draft.preflight?.model || 'not reported'}
Firmware:         ${draft.preflight?.firmware || 'not reported'}
Login:            ${draft.login}
Secret backend:   ${draft.backend === 'keychain' ? 'system keychain' : 'owner-only file'}
Default profile:  ${isDefault ? 'yes' : 'no'}
MCP mode:         read-only
Registration:     ${draft.registration}`;
}

function invalidatesPreflight<T>(previous: T, next: T, draft: RouterWizardDraft): void {
  if (previous !== next) delete draft.preflight;
}

/** Testable onboarding state machine. It performs no router mutation. */
export async function runRouterWizard(
  dir: string,
  ui: PromptAdapter,
  overrides: Partial<RouterWizardDependencies> = {}
): Promise<number> {
  const deps = { ...defaultDependencies, ...overrides };
  const registry = await deps.readProfiles(dir);
  const existingIds = registry.profiles.map(profile => profile.id);
  const draft: RouterWizardDraft = {
    name: '', id: '', mode: 'remote', endpoint: '', login: 'mcp_agent',
    password: deps.generatePassword(), registration: 'neither'
  };
  const endpoints: Partial<Record<'remote' | 'lan', string>> = {};
  let revealed = false;
  let instructionsKey = '';
  let step = 0;

  while (step < 9) {
    if (step === 0) {
      const result = await ui.input('Router name', draft.name || 'Home router');
      if (result.kind !== 'value') return 1;
      const name = result.value.trim();
      if (!name) { ui.output('Router name is required.'); continue; }
      draft.name = name;
      draft.id = deriveProfileId(name, existingIds);
      ui.output(`Profile ID: ${draft.id}`);
      step += 1;
    } else if (step === 1) {
      const result = await ui.select('Connection mode', [
        { value: 'remote', label: 'Remote KeenDNS', hint: 'recommended; works away from the LAN' },
        { value: 'lan', label: 'LAN', hint: 'direct local connection' }
      ], draft.mode);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back') { step -= 1; continue; }
      const mode = result.value;
      invalidatesPreflight(draft.mode, mode, draft);
      if (draft.mode !== mode) {
        endpoints[draft.mode] = draft.endpoint;
        draft.endpoint = endpoints[mode] ?? '';
      }
      draft.mode = mode;
      step += 1;
    } else if (step === 2) {
      const result = await ui.input('Dedicated Keenetic account name', draft.login);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back') { step -= 1; continue; }
      const login = result.value.trim();
      if (!login) { ui.output('Account name is required.'); continue; }
      invalidatesPreflight(draft.login, login, draft);
      draft.login = login;
      step += 1;
    } else if (step === 3) {
      const nextInstructionsKey = `${draft.mode}:${draft.login}`;
      if (!revealed) {
        ui.output(accountInstructions(draft.mode, draft.login, draft.password));
        revealed = true;
      } else if (instructionsKey !== nextInstructionsKey) {
        ui.output(`Update the dedicated router user to "${draft.login}" and complete the ${draft.mode === 'remote' ? 'local HTTP, TCP 79, authorized access, and external KeenDNS HTTPS' : 'local HTTP, TCP 79, and authorized access'} settings. Use the generated password shown earlier.`);
      } else {
        ui.output('Complete the dedicated account and access settings shown earlier, using the generated password.');
      }
      instructionsKey = nextInstructionsKey;
      const result = await ui.confirm('I have completed these router settings', false);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back' || !result.value) { step -= 1; continue; }
      step += 1;
    } else if (step === 4) {
      const result = await ui.input(draft.mode === 'remote' ? 'KeenDNS HTTPS endpoint' : 'Router LAN address', draft.endpoint || undefined);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back') { step -= 1; continue; }
      try {
        const endpoint = normalizeWizardEndpoint(result.value, draft.mode);
        invalidatesPreflight(draft.endpoint, endpoint, draft);
        draft.endpoint = endpoint;
        endpoints[draft.mode] = endpoint;
        step += 1;
      } catch (error) { ui.output(error instanceof Error ? error.message : 'Invalid endpoint'); }
    } else if (step === 5) {
      if (!draft.preflight) {
        const profile = { id: draft.id, mode: draft.mode, endpoint: draft.endpoint, login: draft.login };
        draft.preflight = await deps.preflight(profile, deps.createClient(profile, draft.password));
      }
      ui.output(preflightText(draft.preflight));
      if (!draft.preflight.ready) {
        const result = await ui.select('Preflight failed', [
          { value: 'retry', label: 'Retry' }, { value: 'back', label: 'Change endpoint or credentials' },
          { value: 'regenerate', label: 'Generate a new password' }
        ], 'retry');
        if (result.kind === 'cancel') return 1;
        if (result.kind === 'back' || value(result) === 'back') { delete draft.preflight; step -= 1; continue; }
        if (value(result) === 'regenerate') {
          draft.password = deps.generatePassword();
          delete draft.preflight;
          revealed = false;
          step = 3;
          continue;
        }
        delete draft.preflight;
        continue;
      }
      const result = await ui.select('Preflight passed', [
        { value: 'continue', label: 'Continue' }, { value: 'back', label: 'Change endpoint or credentials' },
        { value: 'regenerate', label: 'Generate a new password' }
      ], 'continue');
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back' || value(result) === 'back') { step -= 1; continue; }
      if (value(result) === 'regenerate') {
        draft.password = deps.generatePassword();
        delete draft.preflight;
        revealed = false;
        step = 3;
        continue;
      }
      step += 1;
    } else if (step === 6) {
      if (!draft.backend) {
        if (await deps.keychainAvailable()) draft.backend = 'keychain';
        else {
          ui.output(`The system keychain is unavailable. The fallback stores the password in an owner-only file under ${join(dir, 'secrets')} (directory 0700, file 0600).`);
          const result = await ui.confirm('Use the owner-only file fallback', false);
          if (result.kind === 'cancel') return 1;
          if (result.kind === 'back') { step -= 1; continue; }
          if (!result.value) return 1;
          draft.backend = 'file';
        }
      }
      step += 1;
    } else if (step === 7) {
      const result = await ui.select('Register this profile with an MCP client', [
        { value: 'neither', label: 'Neither' }, { value: 'codex', label: 'Codex' },
        { value: 'claude', label: 'Claude' }, { value: 'both', label: 'Both' }
      ], draft.registration);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back') {
        if (draft.backend === 'file') { delete draft.backend; step = 6; }
        else step = 5;
        continue;
      }
      draft.registration = result.value;
      step += 1;
    } else {
      ui.output(review(draft, registry.profiles.length === 0));
      const result = await ui.confirm('Save this profile', false);
      if (result.kind === 'cancel') return 1;
      if (result.kind === 'back' || !result.value) { if (result.kind === 'back') { step -= 1; continue; } return 1; }
      step += 1;
    }
  }

  const backend = draft.backend;
  if (!backend || !draft.preflight?.ready) return 1;
  await deps.withPersistenceLock(dir, async _recoveredStaleLock => {
    const current = await deps.readProfiles(dir);
    if (current.profiles.some(profile => profile.id === draft.id)) {
      throw new Error(`Profile "${draft.id}" was created by another process; restart setup to choose a new ID`);
    }
    const store = await deps.createSecretStore(dir, backend);
    const previous = await store.read(draft.id);
    if (previous !== null) throw new Error(`A secret already exists for profile "${draft.id}" and was not overwritten; remove that orphan through its secret backend or choose another router name`);
    try {
      await store.save(draft.id, draft.password);
      if (await store.read(draft.id) !== draft.password) throw new Error('Saved password could not be verified');
    } catch (error) {
      await rollbackSecret(store, draft.id, error);
    }
    const profile: RouterProfile = {
      id: draft.id, name: draft.name, mode: draft.mode, endpoint: draft.endpoint, login: draft.login,
      secretRef: store.ref(draft.id), default: current.profiles.length === 0, readOnly: true
    };
    try { await deps.addProfile(dir, profile); }
    catch (error) { await rollbackSecret(store, draft.id, error); }
  });
  ui.output(`✓ Profile "${draft.id}" saved.`);

  const clients: Array<'codex' | 'claude'> = draft.registration === 'both'
    ? ['codex', 'claude'] : draft.registration === 'neither' ? [] : [draft.registration];
  for (const client of clients) {
    const instanceName = `keenetic_${draft.id}`;
    let code = 1;
    try {
      const invocation = registrationInvocation(client, draft.id, deps.serverLaunch());
      code = await deps.runRegistration(invocation);
    } catch { /* handled below */ }
    if (code !== 0) {
      ui.output(`! Registration with ${client} failed; the profile remains saved. Run router register again from a durable installation.`);
      continue;
    }
    try {
      await deps.saveRegistration(dir, draft.id, client, instanceName);
      ui.output(`✓ Registered ${instanceName} with ${client}.`);
    } catch {
      ui.output(`! ${client} registration succeeded, but its local status could not be recorded. Profile "${draft.id}" remains saved.`);
    }
  }
  if (clients.length === 0) ui.output(`Optional: run "keenetic-noc-mcp router register ${draft.id}" later.`);
  return 0;
}
