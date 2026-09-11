import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { configDir, migrateLegacyConfigDir } from '../config/discover.js';
import { createClient, createRemoteClient, type KeeneticClient } from '../router/client.js';
import { getProfile, readLastTest, readProfiles, removeProfile, removeState, saveLastTest, saveRegistration, setDefaultProfile, type RouterProfile } from '../profiles/registry.js';
import { createProfileSecretStore, generatePassword, type ProfileSecretBackend } from '../profiles/secrets.js';
import { runRouterPreflight, type PreflightDependencies, type PreflightReport } from '../router/preflight.js';
import { stateDir } from '../router/backup.js';
import { collectRouterSnapshot } from '../router/snapshot-collector.js';
import { createSnapshotStore, type SnapshotWriteResult } from '../router/snapshot-store.js';
import type { RouterSnapshotV1 } from '../shape/router-snapshot.js';
import { currentMcpServerLaunch, registrationInvocation, registrationPreview, runRouterWizard, type McpServerLaunch, type RegistrationInvocation } from './router-wizard.js';
import { createPromptAdapter } from './ui/prompts.js';

export interface Terminal { ask(question: string): Promise<string>; close(): void; out(line: string): void; }
function terminal(): Terminal {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return { ask: question => rl.question(question).then(value => value.trim()), close: () => rl.close(), out: line => process.stdout.write(`${line}\n`) };
}
function requireTty(): void { if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Secret-bearing router commands require an interactive TTY'); }
function masked(secret: string): string { return `${'*'.repeat(Math.max(0, secret.length - 4))}${secret.slice(-4)}`; }
function profileClient(profile: RouterProfile, password: string): KeeneticClient {
  return profile.mode === 'remote'
    ? createRemoteClient({ endpoint: profile.endpoint, login: profile.login, password, routerId: profile.id })
    : createClient({ host: profile.endpoint, login: profile.login, password });
}
async function confirm(ui: Terminal, prompt: string, defaultYes = true): Promise<boolean> { const answer = (await ui.ask(`${prompt} [${defaultYes ? 'Y/n' : 'y/N'}] `)).toLowerCase(); return answer === '' ? defaultYes : answer === 'y' || answer === 'yes'; }

export interface RouterRegistrationDependencies {
  getProfile(dir: string, id: string): ReturnType<typeof getProfile>;
  serverLaunch(): McpServerLaunch;
  runRegistration(invocation: RegistrationInvocation): Promise<number>;
  saveRegistration(dir: string, id: string, client: 'codex' | 'claude', instanceName: string): Promise<void>;
}

export interface RouterRemovalDependencies {
  getProfile(dir: string, id: string): ReturnType<typeof getProfile>;
  removeProfile(dir: string, id: string): ReturnType<typeof removeProfile>;
  removeSecret(dir: string, profile: RouterProfile): Promise<void>;
  removeState(dir: string, id: string): Promise<void>;
  removeSnapshots(id: string, finalize: () => Promise<void>): Promise<void>;
}

const removalDependencies: RouterRemovalDependencies = {
  getProfile,
  removeProfile,
  async removeSecret(dir, profile) {
    await (await createProfileSecretStore(dir,
      profile.secretRef.startsWith('file:') ? 'file' : 'keychain')).remove(profile.id);
  },
  removeState,
  removeSnapshots: (id, finalize) => createSnapshotStore(
    stateDir(process.platform, process.env), id
  ).removeAll(finalize)
};

export async function runRouterRemoval(
  dir: string,
  id: string,
  ui: Terminal,
  overrides: Partial<RouterRemovalDependencies> = {}
): Promise<number> {
  const deps = { ...removalDependencies, ...overrides };
  const profile = await deps.getProfile(dir, id);
  if (!profile) throw new Error(`No profile named "${id}"`);
  ui.out(`Remove profile ${id}, its local secret, and its local snapshots. ` +
    'This does not change the router or delete its user.');
  if (!await confirm(ui, 'Remove profile, local secret, and snapshots?', false)) return 1;
  await deps.removeSecret(dir, profile);
  await deps.removeState(dir, id);
  await deps.removeSnapshots(id, async () => {
    if (!await deps.removeProfile(dir, id)) throw new Error(`No profile named "${id}"`);
  });
  ui.out('✓ Profile removed.');
  return 0;
}

const registrationDependencies: RouterRegistrationDependencies = {
  getProfile,
  serverLaunch: currentMcpServerLaunch,
  runRegistration: invocation => new Promise(resolve => {
    const child = spawn(invocation.command, invocation.args, { stdio: 'inherit' });
    child.on('close', code => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  }),
  saveRegistration: (dir, id, client, instanceName) =>
    saveRegistration(dir, id, { client, instanceName })
};

/** Registers an existing profile without changing it or exposing its secret. */
export async function runRouterRegistration(
  dir: string,
  id: string,
  client: 'codex' | 'claude',
  ui: Terminal,
  overrides: Partial<RouterRegistrationDependencies> = {}
): Promise<number> {
  const deps = { ...registrationDependencies, ...overrides };
  if (!await deps.getProfile(dir, id)) throw new Error(`No profile named "${id}"`);
  let invocation: RegistrationInvocation;
  try { invocation = registrationInvocation(client, id, deps.serverLaunch()); }
  catch {
    ui.out('✗ Registration launch path could not be resolved; the profile was not changed. Run this command from a durable installation.');
    return 1;
  }
  ui.out(`Registration argv (display only; no secrets):\n  ${registrationPreview(invocation)}`);
  if (!await confirm(ui, 'Register this MCP?')) return 1;
  let code = 1;
  try { code = await deps.runRegistration(invocation); } catch { /* handled below */ }
  if (code !== 0) {
    ui.out('✗ Registration failed; the profile was not changed.');
    return 1;
  }
  const instanceName = `keenetic_${id}`;
  try { await deps.saveRegistration(dir, id, client, instanceName); }
  catch {
    ui.out(`! Registered ${instanceName}, but its local profile metadata could not be updated.`);
    return 1;
  }
  ui.out('✓ Registered.');
  return 0;
}

async function add(dir: string): Promise<number> {
  requireTty();
  const ui = createPromptAdapter();
  try { return await runRouterWizard(dir, ui); } finally { ui.close(); }
}

async function show(dir: string, id: string): Promise<number> { const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); const registry = await readProfiles(dir); const state = await readLastTest(dir, id); const regs = registry.registrations?.[id] ?? []; console.log(`Profile: ${profile.id}\nName: ${profile.name}\nMode: ${profile.mode}\nEndpoint: ${profile.endpoint}\nLogin: ${profile.login}\nSecret backend: ${profile.secretRef.startsWith('keychain:') ? 'keychain' : 'file'}\nDefault: ${profile.default ? 'yes' : 'no'}\nMCP mode: ${profile.readOnly ? 'read-only' : 'read-write'}\n\nLast test:\n  ${state ? `${state.at} - ${state.overall}` : 'not run'}\n\nRegistrations:\n  Codex: ${regs.find(r => r.client === 'codex')?.instanceName ?? 'not registered'}\n  Claude: ${regs.find(r => r.client === 'claude')?.instanceName ?? 'not registered'}`); return 0; }
async function list(dir: string): Promise<number> { const profiles = (await readProfiles(dir)).profiles; if (!profiles.length) { console.log('No router profiles. Run "keenetic-noc-mcp router add".'); return 0; } for (const p of profiles) console.log(`${p.id}${p.default ? ' (default)' : ''}\t${p.name}\t${p.mode}\t${p.endpoint}`); return 0; }

export interface ConnectionTestResult {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  checks: Record<string, string>;
}

export interface RouterSnapshotDependencies {
  getProfile(dir: string, id: string): ReturnType<typeof getProfile>;
  readPassword(dir: string, profile: RouterProfile): Promise<string | null>;
  createClient(profile: RouterProfile, password: string): KeeneticClient;
  collect(client: KeeneticClient): Promise<RouterSnapshotV1>;
  write(dir: string, routerId: string, snapshot: RouterSnapshotV1): Promise<SnapshotWriteResult>;
}

const snapshotDependencies: RouterSnapshotDependencies = {
  getProfile,
  async readPassword(dir, profile) {
    const backend: ProfileSecretBackend = profile.secretRef.startsWith('file:') ? 'file' : 'keychain';
    return (await createProfileSecretStore(dir, backend)).read(profile.id);
  },
  createClient: profileClient,
  collect: client => collectRouterSnapshot(client),
  write: (dir, routerId, snapshot) => createSnapshotStore(
    stateDir(process.platform, process.env), routerId
  ).write(snapshot, new Date(), async () => {
    if (!await getProfile(dir, routerId)) throw new Error(`No profile named "${routerId}"`);
  })
};

/** Captures one explicit local summary without changing the router or MCP registry. */
export async function runRouterSnapshot(
  dir: string,
  id: string,
  out: (line: string) => void = line => console.log(line),
  overrides: Partial<RouterSnapshotDependencies> = {}
): Promise<number> {
  const deps = { ...snapshotDependencies, ...overrides };
  const profile = await deps.getProfile(dir, id);
  if (!profile) throw new Error(`No profile named "${id}"`);
  const password = await deps.readPassword(dir, profile);
  if (!password) throw new Error('Profile password is unavailable');
  const snapshot = await deps.collect(deps.createClient(profile, password));
  const stored = await deps.write(dir, profile.id, snapshot);
  const unavailable = Object.values(snapshot.sources).filter(source => source.status === 'unavailable').length +
    (snapshot.sources.configuration.data?.savedState === 'available' ? 0 : 1);
  out(`Snapshot saved: ${snapshot.at} - ${snapshot.complete ? 'complete' : 'partial'}; ` +
    `unavailable domains: ${unavailable}; ${stored.bytes} bytes; pruned: ${stored.pruned}.`);
  return 0;
}

/** Projects the richer onboarding preflight into the stable router-test result. */
export function connectionTestFromPreflight(report: PreflightReport): ConnectionTestResult {
  const checks: Record<string, string> = {};
  for (const [name, check] of Object.entries(report.checks)) {
    const mark = check.status === 'pass' ? '✓' : check.status === 'fail' ? '✗' : check.status === 'warning' ? '!' : '→';
    checks[name] = `${mark} ${check.detail}`;
  }
  if (report.model) checks['System'] = `✓ ${report.model}${report.firmware ? ` (${report.firmware})` : ''}`;
  const degraded = Object.entries(report.checks).some(([name, check]) =>
    check.status === 'warning' && !(name === 'Backup' && check.detail.includes('requires a LAN profile'))
  );
  return { overall: !report.ready ? 'unhealthy' : degraded ? 'degraded' : 'healthy', checks };
}

/** Runs real, read-only probes without retaining response bodies or private values. */
export async function runConnectionChecks(
  profile: RouterProfile,
  client: KeeneticClient,
  dependencies: Partial<PreflightDependencies> = {}
): Promise<ConnectionTestResult> {
  return connectionTestFromPreflight(await runRouterPreflight(profile, client, dependencies));
}

async function test(dir: string, id: string): Promise<number> {
  const profile = await getProfile(dir, id);
  if (!profile) throw new Error(`No profile named "${id}"`);
  const backend: ProfileSecretBackend = profile.secretRef.startsWith('file:') ? 'file' : 'keychain';
  const password = await (await createProfileSecretStore(dir, backend)).read(id);
  if (!password) throw new Error('Profile password is unavailable');
  const result = await runConnectionChecks(profile, profileClient(profile, password));
  await saveLastTest(dir, id, { at: new Date().toISOString(), ...result });
  console.log(`Connection test: ${id}\n\n${Object.entries(result.checks).map(([key, value]) => `${key.padEnd(16)} ${value}`).join('\n')}\n\nOverall: ${result.overall}`);
  return result.overall === 'healthy' ? 0 : 1;
}

async function register(dir: string, id: string, clientArg?: string): Promise<number> {
  requireTty();
  const ui = terminal();
  try {
    const client = (clientArg ?? await ui.ask('Client (codex/claude): ')).toLowerCase();
    if (client !== 'codex' && client !== 'claude') throw new Error('Client must be codex or claude');
    return await runRouterRegistration(dir, id, client, ui);
  } finally { ui.close(); }
}

async function rotate(dir: string, id: string): Promise<number> { requireTty(); const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); const ui = terminal(); try { const backend: ProfileSecretBackend = profile.secretRef.startsWith('file:') ? 'file' : 'keychain'; const store = await createProfileSecretStore(dir, backend); const old = await store.read(id); if (!old) throw new Error('Profile password is unavailable'); const next = generatePassword(); ui.out(`New password: ${masked(next)}`); await ui.ask('Press Enter to reveal it: '); ui.out(next); ui.out('→ Set this password for the existing router user.'); if (!await confirm(ui, 'Password changed on router?')) return 1; try { await profileClient(profile, next).capabilities(); } catch { try { await profileClient(profile, old).capabilities(); ui.out('✗ New credentials rejected; old credentials still work.'); } catch { ui.out('→ action required: router password state is ambiguous.'); } return 1; } await store.save(id, next); ui.out('✓ Password rotated.'); return 0; } finally { ui.close(); } }

export function isWizardAction(action: string | undefined): boolean { return action === 'add' || action === 'init'; }

export async function runRouterFromTerminal(argv: readonly string[]): Promise<number> { await migrateLegacyConfigDir(process.platform, process.env); const dir = configDir(process.platform, process.env); const [action, id, ...rest] = argv; if (isWizardAction(action)) return add(dir); if (action === 'list') return list(dir); if (!id) throw new Error('A router profile ID is required'); if (action === 'show') return show(dir, id); if (action === 'test') return test(dir, id); if (action === 'snapshot') return runRouterSnapshot(dir, id); if (action === 'register') return register(dir, id, rest[0] === '--client' ? rest[1] : undefined); if (action === 'rotate-password') return rotate(dir, id); if (action === 'set-default') { await setDefaultProfile(dir, id); console.log(`✓ Default profile is now ${id}.`); return 0; } if (action === 'remove') { requireTty(); const ui = terminal(); try { return await runRouterRemoval(dir, id, ui); } finally { ui.close(); } } throw new Error(`Unknown router command "${action ?? ''}"`); }
