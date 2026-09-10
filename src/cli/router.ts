import { createInterface } from 'node:readline/promises';
import { configDir, identifyRouter, migrateLegacyConfigDir } from '../config/discover.js';
import { createClient, createRemoteClient, type KeeneticClient } from '../router/client.js';
import { createKeychainStore, spawnRunner } from '../config/secrets.js';
import { normalizeRemoteUrl } from '../config/load.js';
import { addProfile, getProfile, readLastTest, readProfiles, removeProfile, removeState, saveLastTest, saveRegistration, setDefaultProfile, type RouterProfile } from '../profiles/registry.js';
import { createProfileSecretStore, generatePassword, keychainAvailable, type ProfileSecretBackend } from '../profiles/secrets.js';
import { AuthError, RemoteCapabilityError } from '../router/errors.js';
import { STARTUP_CONFIG } from '../router/config-state.js';

interface Terminal { ask(question: string): Promise<string>; close(): void; out(line: string): void; }
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

async function add(dir: string): Promise<number> {
  requireTty(); const ui = terminal();
  try {
    const id = (await ui.ask('Profile ID [home]: ')) || 'home'; const name = (await ui.ask(`Name [${id}]: `)) || id;
    const mode = ((await ui.ask('Mode (lan/remote) [lan]: ')) || 'lan').toLowerCase();
    if (mode !== 'lan' && mode !== 'remote') throw new Error('Mode must be lan or remote');
    if (mode === 'remote') ui.out('! This endpoint gives the MCP access to router configuration.\nUse a dedicated user and do not reuse your administrator password.');
    const endpointRaw = await ui.ask(mode === 'remote' ? 'Remote HTTPS endpoint: ' : 'Router address: ');
    const endpoint = mode === 'remote' ? normalizeRemoteUrl(endpointRaw) : endpointRaw;
    if (!endpoint) throw new Error('Endpoint is required');
    if (mode === 'lan' && !(await identifyRouter(endpoint))) throw new Error('Nothing at that address looks like a Keenetic router');
    const login = (await ui.ask('Dedicated router login [mcp_agent]: ')) || 'mcp_agent';
    const legacy = createKeychainStore(process.platform, spawnRunner);
    const available = await keychainAvailable(legacy);
    let backend: ProfileSecretBackend = 'keychain';
    if (!available) {
      backend = 'file'; ui.out(`! System keychain is unavailable.\n\nFallback:\n  Store the password in an owner-only local file:\n  ${dir}/secrets/${id}\n\nPermissions:\n  directory 0700\n  file      0600`);
      if (!await confirm(ui, 'Use file fallback?', false)) return 1;
    }
    const password = generatePassword(); ui.out(`Generated password: ${masked(password)}`); await ui.ask('Press Enter to reveal it: '); ui.out(password);
    ui.out('→ Create the dedicated user on the router, set this password, and grant RCI/KeenDNS access.');
    if (!await confirm(ui, 'Have you completed this?')) return 1;
    const draft: RouterProfile = { id, name, mode, endpoint, login, secretRef: `${backend}:${id}`, default: (await readProfiles(dir)).profiles.length === 0, readOnly: true };
    let caps;
    try { caps = await profileClient(draft, password).capabilities(); } catch { ui.out('✗ The router rejected those credentials. Nothing was saved.'); return 1; }
    ui.out(`Review\n\nProfile ID:       ${id}\nName:             ${name}\nMode:             ${mode}\nEndpoint:         ${endpoint}\nRouter:           ${caps.model}\nLogin:            ${login}\nSecret backend:   ${backend === 'keychain' ? 'system keychain' : 'owner-only file'}\nDefault profile:  ${draft.default ? 'yes' : 'no'}\nMCP mode:         read-only`);
    if (!await confirm(ui, 'Save this profile?')) return 1;
    const secrets = await createProfileSecretStore(dir, backend);
    await secrets.save(id, password);
    try { await addProfile(dir, draft); } catch (error) { await secrets.remove(id); throw error; }
    ui.out(`✓ Profile "${id}" saved.`); ui.out(`→ Optional: run "keenetic-noc-mcp router register ${id}" to register it with an agent.`); return 0;
  } finally { ui.close(); }
}

async function show(dir: string, id: string): Promise<number> { const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); const registry = await readProfiles(dir); const state = await readLastTest(dir, id); const regs = registry.registrations?.[id] ?? []; console.log(`Profile: ${profile.id}\nName: ${profile.name}\nMode: ${profile.mode}\nEndpoint: ${profile.endpoint}\nLogin: ${profile.login}\nSecret backend: ${profile.secretRef.startsWith('keychain:') ? 'keychain' : 'file'}\nDefault: ${profile.default ? 'yes' : 'no'}\nMCP mode: ${profile.readOnly ? 'read-only' : 'read-write'}\n\nLast test:\n  ${state ? `${state.at} - ${state.overall}` : 'not run'}\n\nRegistrations:\n  Codex: ${regs.find(r => r.client === 'codex')?.instanceName ?? 'not registered'}\n  Claude: ${regs.find(r => r.client === 'claude')?.instanceName ?? 'not registered'}`); return 0; }
async function list(dir: string): Promise<number> { const profiles = (await readProfiles(dir)).profiles; if (!profiles.length) { console.log('No router profiles. Run "keenetic-noc-mcp router add".'); return 0; } for (const p of profiles) console.log(`${p.id}${p.default ? ' (default)' : ''}\t${p.name}\t${p.mode}\t${p.endpoint}`); return 0; }

export interface ConnectionTestResult {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  checks: Record<string, string>;
}

/** Runs real, read-only probes without retaining response bodies or private values. */
export async function runConnectionChecks(profile: RouterProfile, client: KeeneticClient): Promise<ConnectionTestResult> {
  const checks: Record<string, string> = {};
  try {
    const caps = await client.capabilities();
    checks['Authentication'] = '✓';
    checks['RCI'] = '✓';
    checks['System'] = caps.model ? `✓ ${caps.model}` : '✓';
    checks['TLS'] = profile.mode === 'remote' ? '✓ valid certificate' : '- not applicable';
  } catch (error) {
    checks['Authentication'] = error instanceof AuthError ? '✗ failed' : '? not established';
    checks['RCI'] = '✗ failed';
    checks['System'] = '→ skipped';
    checks['Config read'] = '→ skipped';
    checks['DNS'] = '→ skipped';
    checks['Startup config'] = '→ skipped';
    checks['Backup'] = '→ skipped';
    checks['TLS'] = profile.mode === 'remote' ? '? not established' : '- not applicable';
    return { overall: 'unhealthy', checks };
  }

  let degraded = false;
  try {
    await client.rci.get('show/last-change');
    checks['Config read'] = '✓';
  } catch {
    checks['Config read'] = '✗ failed';
    degraded = true;
  }

  try {
    await client.rci.get('show/dns-proxy');
    checks['DNS'] = '✓';
  } catch {
    checks['DNS'] = '✗ failed';
    degraded = true;
  }

  try {
    await client.rci.getText(STARTUP_CONFIG);
    checks['Startup config'] = '✓ available';
    checks['Backup'] = '✓ ready';
  } catch (error) {
    if (profile.mode === 'remote' && error instanceof RemoteCapabilityError) {
      checks['Startup config'] = '- unsupported remotely';
      checks['Backup'] = '- requires LAN profile';
    } else {
      checks['Startup config'] = '✗ failed';
      checks['Backup'] = '✗ unavailable';
      degraded = true;
    }
  }

  return { overall: degraded ? 'degraded' : 'healthy', checks };
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

async function register(dir: string, id: string, clientArg?: string): Promise<number> { requireTty(); const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); const ui = terminal(); try { const client = (clientArg ?? await ui.ask('Client (codex/claude): ')).toLowerCase(); if (client !== 'codex' && client !== 'claude') throw new Error('Client must be codex or claude'); const instanceName = `keenetic_${id}`; const command = client === 'codex' ? `codex mcp add ${instanceName} -- keenetic-noc-mcp --router ${id} --read-only` : `claude mcp add ${instanceName} -- keenetic-noc-mcp --router ${id} --read-only`; ui.out(`Command preview (no secrets):\n  ${command}`); if (!await confirm(ui, 'Register this MCP?')) return 1; const { spawn } = await import('node:child_process'); const [cmd, ...args] = command.split(' '); const code = await new Promise<number>(resolve => spawn(cmd as string, args, { stdio: 'inherit' }).on('close', value => resolve(value ?? 1)).on('error', () => resolve(1))); if (code !== 0) { ui.out('✗ Registration failed; the profile was not changed.'); return 1; } await saveRegistration(dir, id, { client, instanceName }); ui.out('✓ Registered.'); return 0; } finally { ui.close(); } }

async function rotate(dir: string, id: string): Promise<number> { requireTty(); const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); const ui = terminal(); try { const backend: ProfileSecretBackend = profile.secretRef.startsWith('file:') ? 'file' : 'keychain'; const store = await createProfileSecretStore(dir, backend); const old = await store.read(id); if (!old) throw new Error('Profile password is unavailable'); const next = generatePassword(); ui.out(`New password: ${masked(next)}`); await ui.ask('Press Enter to reveal it: '); ui.out(next); ui.out('→ Set this password for the existing router user.'); if (!await confirm(ui, 'Password changed on router?')) return 1; try { await profileClient(profile, next).capabilities(); } catch { try { await profileClient(profile, old).capabilities(); ui.out('✗ New credentials rejected; old credentials still work.'); } catch { ui.out('→ action required: router password state is ambiguous.'); } return 1; } await store.save(id, next); ui.out('✓ Password rotated.'); return 0; } finally { ui.close(); } }

export async function runRouterFromTerminal(argv: readonly string[]): Promise<number> { await migrateLegacyConfigDir(process.platform, process.env); const dir = configDir(process.platform, process.env); const [action, id, ...rest] = argv; if (action === 'add') return add(dir); if (action === 'list') return list(dir); if (!id) throw new Error('A router profile ID is required'); if (action === 'show') return show(dir, id); if (action === 'test') return test(dir, id); if (action === 'register') return register(dir, id, rest[0] === '--client' ? rest[1] : undefined); if (action === 'rotate-password') return rotate(dir, id); if (action === 'set-default') { await setDefaultProfile(dir, id); console.log(`✓ Default profile is now ${id}.`); return 0; } if (action === 'remove') { requireTty(); const ui = terminal(); try { const profile = await getProfile(dir, id); if (!profile) throw new Error(`No profile named "${id}"`); ui.out(`Remove profile ${id}. This does not change the router or delete its user.`); if (!await confirm(ui, 'Remove profile and local secret?', false)) return 1; const removed = await removeProfile(dir, id); if (removed) { await (await createProfileSecretStore(dir, removed.secretRef.startsWith('file:') ? 'file' : 'keychain')).remove(id); await removeState(dir, id); } ui.out('✓ Profile removed.'); return 0; } finally { ui.close(); } } throw new Error(`Unknown router command "${action ?? ''}"`); }
