import { describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { currentMcpServerLaunch, registrationInvocation, registrationPreview, runRouterWizard, withPersistenceLock, type McpServerLaunch, type RouterWizardDependencies } from '../../src/cli/router-wizard.js';
import type { PromptAdapter, PromptResult } from '../../src/cli/ui/prompts.js';
import type { ProfileSecretStore } from '../../src/profiles/secrets.js';

const answer = <T>(value: T): PromptResult<T> => ({ kind: 'value', value });
const back: PromptResult<never> = { kind: 'back' };
const cancel: PromptResult<never> = { kind: 'cancel' };
const SERVER_LAUNCH: McpServerLaunch = {
  command: '/usr/bin/node',
  args: ['/opt/keenetic noc/dist/index.js']
};

class FakePrompt implements PromptAdapter {
  readonly outputs: string[] = [];
  readonly selections: Array<{ message: string; initial?: string }> = [];
  readonly inputs: Array<{ message: string; initial?: string }> = [];
  readonly confirmations: Array<{ message: string; initial: boolean }> = [];
  constructor(private readonly script: PromptResult<unknown>[]) {}
  private next<T>(): Promise<PromptResult<T>> {
    const result = this.script.shift();
    if (!result) throw new Error('Prompt script exhausted');
    return Promise.resolve(result as PromptResult<T>);
  }
  input(message: string, initial?: string): Promise<PromptResult<string>> {
    this.inputs.push({ message, ...(initial === undefined ? {} : { initial }) });
    return this.next();
  }
  select<T extends string>(message: string, _choices: readonly unknown[], initial?: T): Promise<PromptResult<T>> {
    this.selections.push({ message, ...(initial === undefined ? {} : { initial }) });
    return this.next();
  }
  confirm(message: string, initial: boolean): Promise<PromptResult<boolean>> {
    this.confirmations.push({ message, initial });
    return this.next();
  }
  output(message: string): void { this.outputs.push(message); }
  close(): void {}
}

function successfulScript(mode: 'remote' | 'lan' = 'remote', registration = 'neither'): PromptResult<unknown>[] {
  return [answer('My Router'), answer(mode), answer('mcp_agent'), answer(true),
    answer(mode === 'remote' ? 'router.keenetic.pro' : '192.0.2.1'), answer('continue'), answer(registration), answer(true)];
}

function harness(options: { keychain?: boolean; addError?: Error; registrationCode?: number } = {}) {
  let stored: string | null = null;
  const store: ProfileSecretStore = {
    backend: options.keychain === false ? 'file' : 'keychain',
    ref: id => `${options.keychain === false ? 'file' : 'keychain'}:${id}`,
    save: vi.fn(async (_id, secret) => { stored = secret; }),
    read: vi.fn(async () => stored),
    remove: vi.fn(async () => { stored = null; })
  };
  const deps: Partial<RouterWizardDependencies> = {
    readProfiles: vi.fn(async () => ({ version: 1 as const, profiles: [] })),
    generatePassword: () => 'Abcdefghijk2345!Qrstuvwx',
    keychainAvailable: vi.fn(async () => options.keychain !== false),
    createSecretStore: vi.fn(async () => store),
    createClient: vi.fn(() => ({}) as never),
    preflight: vi.fn(async () => ({ ready: true, model: 'Keenetic Test', firmware: '5.1.3', checks: {} })),
    addProfile: vi.fn(async () => { if (options.addError) throw options.addError; }),
    serverLaunch: () => SERVER_LAUNCH,
    runRegistration: vi.fn(async () => options.registrationCode ?? 0),
    saveRegistration: vi.fn(async () => undefined),
    withPersistenceLock: vi.fn(async (_dir, task) => task(false))
  };
  return { deps, store };
}

describe('router onboarding state machine', () => {
  it.each(['remote', 'lan'] as const)('saves a verified read-only %s profile', async mode => {
    const ui = new FakePrompt(successfulScript(mode));
    const { deps, store } = harness();

    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(store.save).toHaveBeenCalledWith('my-router', 'Abcdefghijk2345!Qrstuvwx');
    expect(store.read).toHaveBeenCalledWith('my-router');
    expect(deps.addProfile).toHaveBeenCalledWith('/safe/config', expect.objectContaining({
      id: 'my-router', mode, readOnly: true, default: true,
      endpoint: mode === 'remote' ? 'https://router.keenetic.pro/rci/' : '192.0.2.1'
    }));
    expect(ui.outputs.join('\n')).toContain('Keenetic Test');
    expect(ui.outputs.join('\n')).not.toContain('/safe/config/secrets');
    expect(ui.selections[0]?.initial).toBe('remote');
    expect(ui.selections.at(-1)?.initial).toBe('neither');
  });

  it('requires explicit file fallback confirmation default path before saving', async () => {
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'),
      answer('continue'), answer(true), answer('neither'), answer(true)
    ]);
    const { deps } = harness({ keychain: false });
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(deps.createSecretStore).toHaveBeenCalledWith('/safe/config', 'file');
  });

  it.each([cancel, back] as const)('Esc or Ctrl+C on the first step saves nothing', async outcome => {
    const ui = new FakePrompt([outcome]);
    const { deps, store } = harness();
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(1);
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it.each([0, 1, 2, 3, 4, 5, 6, 7])('cancellation at prompt %i crosses no persistence boundary', async promptIndex => {
    const script = successfulScript();
    script[promptIndex] = cancel;
    const { deps, store } = harness();
    await expect(runRouterWizard('/safe/config', new FakePrompt(script.slice(0, promptIndex + 1)), deps)).resolves.toBe(1);
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('retains answers on back and reruns preflight after an endpoint change', async () => {
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('one.keenetic.pro'),
      back, answer('two.keenetic.pro'), answer('continue'), answer('neither'), answer(true)
    ]);
    const { deps } = harness();
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(deps.preflight).toHaveBeenCalledTimes(2);
    expect(deps.addProfile).toHaveBeenCalledWith('/safe/config', expect.objectContaining({ endpoint: 'https://two.keenetic.pro/rci/' }));
  });

  it('supports back through endpoint, instructions, login and mode while retaining defaults', async () => {
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('one.keenetic.pro'),
      answer('continue'), back, back, back, back, back, answer('lan'), answer('mcp_agent'), answer(true),
      answer('router.lan'), answer('continue'), answer('neither'), answer(true)
    ]);
    const { deps } = harness();
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(deps.preflight).toHaveBeenCalledTimes(2);
    expect(deps.addProfile).toHaveBeenCalledWith('/safe/config', expect.objectContaining({ mode: 'lan', endpoint: 'router.lan' }));
    expect(ui.inputs.filter(item => item.message.includes('account')).at(-1)?.initial).toBe('mcp_agent');
  });

  it('revisits explicit file fallback when registration goes back', async () => {
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'),
      answer('continue'), answer(true), back, answer(true), answer('neither'), answer(true)
    ]);
    const { deps } = harness({ keychain: false });
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(ui.confirmations.filter(item => item.message.includes('file fallback'))).toHaveLength(2);
  });

  it('returns from mode to the retained router name and from review to registration', async () => {
    const ui = new FakePrompt([
      answer('Router'), back, answer('Router'), answer('remote'), answer('mcp_agent'), answer(true),
      answer('router.keenetic.pro'), answer('continue'), answer('neither'), back, answer('neither'), answer(true)
    ]);
    const { deps } = harness();
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(ui.inputs.filter(item => item.message === 'Router name').at(-1)?.initial).toBe('Router');
    expect(ui.selections.filter(item => item.message.includes('Register'))).toHaveLength(2);
  });

  it('declining review leaves both persistence boundaries untouched', async () => {
    const script = successfulScript();
    script[script.length - 1] = answer(false);
    const { deps, store } = harness();
    await expect(runRouterWizard('/safe/config', new FakePrompt(script), deps)).resolves.toBe(1);
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('removes a verified secret when registry persistence fails', async () => {
    const { deps, store } = harness({ addError: new Error('registry failed') });
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toThrow('registry failed');
    expect(store.remove).toHaveBeenCalledWith('my-router');
  });

  it('reports rollback failure without losing the primary error', async () => {
    const { deps, store } = harness({ addError: new Error('registry failed') });
    vi.mocked(store.remove).mockRejectedValueOnce(new Error('keychain cleanup failed'));
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toMatchObject({
      name: 'AggregateError', errors: [expect.objectContaining({ message: 'registry failed' }), expect.objectContaining({ message: 'keychain cleanup failed' })]
    });
  });

  it('does not persist a profile when secret read-back fails', async () => {
    const { deps, store } = harness();
    vi.mocked(store.read).mockResolvedValueOnce(null).mockResolvedValueOnce('different');
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toThrow('could not be verified');
    expect(store.remove).toHaveBeenCalledWith('my-router');
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('removes a possibly written secret when save or read throws', async () => {
    for (const failingOperation of ['save', 'read'] as const) {
      const { deps, store } = harness();
      vi.mocked(store.read).mockResolvedValueOnce(null);
      if (failingOperation === 'save') vi.mocked(store.save).mockRejectedValueOnce(new Error('save verification failed'));
      else vi.mocked(store.read).mockRejectedValueOnce(new Error('read failed'));
      await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toThrow();
      expect(store.remove).toHaveBeenCalledWith('my-router');
      expect(deps.addProfile).not.toHaveBeenCalled();
    }
  });

  it('does not touch a colliding profile secret discovered under the commit lock', async () => {
    const { deps, store } = harness();
    vi.mocked(deps.readProfiles!)
      .mockResolvedValueOnce({ version: 1, profiles: [] })
      .mockResolvedValueOnce({ version: 1, profiles: [{
        id: 'my-router', name: 'Other', mode: 'lan', endpoint: 'router.lan', login: 'agent',
        secretRef: 'keychain:my-router', readOnly: true
      }] });
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toThrow('another process');
    expect(store.save).not.toHaveBeenCalled();
    expect(store.remove).not.toHaveBeenCalled();
  });

  it('never deletes an existing secret while recovering a stale lock', async () => {
    const { deps, store } = harness();
    deps.withPersistenceLock = vi.fn(async (_dir, task) => task(true));
    vi.mocked(store.read).mockResolvedValueOnce('pre-existing');
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript()), deps)).rejects.toThrow('was not overwritten');
    expect(store.remove).not.toHaveBeenCalled();
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('blocks persistence after a failed preflight', async () => {
    const { deps, store } = harness();
    vi.mocked(deps.preflight!).mockResolvedValue({
      ready: false,
      checks: { Authentication: { status: 'fail', detail: 'credentials rejected' } }
    });
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'), cancel
    ]);
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(1);
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('declining owner-only file fallback saves nothing', async () => {
    const { deps, store } = harness({ keychain: false });
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'),
      answer('continue'), answer(false)
    ]);
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(1);
    expect(store.save).not.toHaveBeenCalled();
    expect(deps.addProfile).not.toHaveBeenCalled();
  });

  it('keeps a saved profile and prints a secret-free retry instruction when registration fails', async () => {
    const { deps, store } = harness({ registrationCode: 1 });
    const ui = new FakePrompt(successfulScript('remote', 'codex'));
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(store.remove).not.toHaveBeenCalled();
    expect(deps.addProfile).toHaveBeenCalledOnce();
    expect(deps.runRegistration).toHaveBeenCalledWith(
      registrationInvocation('codex', 'my-router', SERVER_LAUNCH)
    );
    expect(ui.outputs.join('\n')).toContain('Run router register again');
    expect(ui.outputs.find(line => line.startsWith('Review'))).not.toContain('Abcdefghijk2345!Qrstuvwx');
    expect(ui.outputs.at(-1)).not.toContain('Abcdefghijk2345!Qrstuvwx');
  });

  it('keeps the profile when the registration runner throws or metadata cannot be recorded', async () => {
    for (const failure of ['runner', 'metadata'] as const) {
      const { deps, store } = harness();
      if (failure === 'runner') vi.mocked(deps.runRegistration!).mockRejectedValueOnce(new Error('missing executable'));
      else vi.mocked(deps.saveRegistration!).mockRejectedValueOnce(new Error('registry write failed'));
      const ui = new FakePrompt(successfulScript('remote', 'codex'));
      await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
      expect(store.remove).not.toHaveBeenCalled();
      expect(deps.addProfile).toHaveBeenCalledOnce();
      expect(ui.outputs.at(-1)).toContain('remains saved');
    }
  });

  it('keeps the saved profile when the durable server launch cannot be resolved', async () => {
    const { deps, store } = harness();
    deps.serverLaunch = () => { throw new Error('entrypoint disappeared'); };
    const ui = new FakePrompt(successfulScript('remote', 'codex'));
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(store.remove).not.toHaveBeenCalled();
    expect(deps.addProfile).toHaveBeenCalledOnce();
    expect(deps.runRegistration).not.toHaveBeenCalled();
    expect(ui.outputs.at(-1)).toContain('profile remains saved');
  });

  it('registers both clients with separate argv calls and metadata', async () => {
    const { deps } = harness();
    await expect(runRouterWizard('/safe/config', new FakePrompt(successfulScript('remote', 'both')), deps)).resolves.toBe(0);
    expect(deps.runRegistration).toHaveBeenNthCalledWith(1,
      registrationInvocation('codex', 'my-router', SERVER_LAUNCH));
    expect(deps.runRegistration).toHaveBeenNthCalledWith(2,
      registrationInvocation('claude', 'my-router', SERVER_LAUNCH));
    expect(deps.saveRegistration).toHaveBeenCalledTimes(2);
  });

  it('changing login invalidates preflight while retaining the endpoint', async () => {
    const { deps } = harness();
    const ui = new FakePrompt([
      answer('Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'),
      answer('continue'), back, back, back, back, answer('new_agent'), answer(true),
      answer('router.keenetic.pro'), answer('continue'), answer('neither'), answer(true)
    ]);
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(deps.preflight).toHaveBeenCalledTimes(2);
    expect(deps.addProfile).toHaveBeenCalledWith('/safe/config', expect.objectContaining({ login: 'new_agent' }));
    expect(ui.inputs.filter(item => item.message.includes('endpoint')).at(-1)?.initial).toBe('https://router.keenetic.pro/rci/');
  });

  it('regenerates the password and invalidates a completed preflight', async () => {
    const { deps, store } = harness();
    deps.generatePassword = vi.fn()
      .mockReturnValueOnce('Abcdefghijk2345!Qrstuvwx')
      .mockReturnValueOnce('Zyxwvutsrq9876!Ponmlkji');
    const ui = new FakePrompt([
      answer('My Router'), answer('remote'), answer('mcp_agent'), answer(true), answer('router.keenetic.pro'),
      answer('regenerate'), answer(true), answer('router.keenetic.pro'), answer('continue'), answer('neither'), answer(true)
    ]);
    await expect(runRouterWizard('/safe/config', ui, deps)).resolves.toBe(0);
    expect(deps.preflight).toHaveBeenCalledTimes(2);
    expect(store.save).toHaveBeenCalledWith('my-router', 'Zyxwvutsrq9876!Ponmlkji');
    expect(ui.outputs.join('\n')).toContain('Zyxwvutsrq9876!Ponmlkji');
  });
});

describe('wizard persistence lock', () => {
  it('recovers a lock owned by a dead process and removes its lock file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keenetic-lock-'));
    try {
      await writeFile(join(dir, '.router-add.lock'), JSON.stringify({ pid: 2147483647, token: 'stale', createdAt: Date.now() }), { mode: 0o600 });
      await expect(withPersistenceLock(dir, async recovered => recovered)).resolves.toBe(true);
      await expect(import('node:fs/promises').then(fs => fs.access(join(dir, '.router-add.lock')))).rejects.toThrow();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('does not steal a lock from a live process', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keenetic-lock-'));
    try {
      await writeFile(join(dir, '.router-add.lock'), JSON.stringify({ pid: process.pid, token: 'live', createdAt: Date.now() }), { mode: 0o600 });
      await expect(withPersistenceLock(dir, async () => undefined)).rejects.toThrow('currently being saved');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('fails closed for an old lock whose process is still alive', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keenetic-lock-'));
    try {
      await writeFile(join(dir, '.router-add.lock'), JSON.stringify({
        pid: process.pid, token: 'old-live', createdAt: Date.now() - 24 * 60 * 60_000
      }), { mode: 0o600 });
      await expect(withPersistenceLock(dir, async () => undefined)).rejects.toThrow('currently being saved');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe('registration argv', () => {
  it('resolves the current executable and entrypoint to absolute existing paths', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keenetic entry '));
    try {
      const entrypoint = join(dir, 'index.js');
      await writeFile(entrypoint, '#!/usr/bin/env node\n');
      const launch = currentMcpServerLaunch(process.execPath, entrypoint);
      expect(launch.command).toMatch(/^\//);
      expect(launch.args).toEqual([entrypoint]);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('fails clearly when no current entrypoint can be resolved', () => {
    expect(() => currentMcpServerLaunch(process.execPath, ''))
      .toThrow(/entrypoint is unavailable/);
  });

  it('registers the absolute executable and entrypoint instead of a missing global bin', () => {
    const invocation = registrationInvocation('claude', 'home', SERVER_LAUNCH);
    expect(invocation).toEqual({
      command: 'claude',
      args: ['mcp', 'add', 'keenetic_home', '--', '/usr/bin/node',
        '/opt/keenetic noc/dist/index.js', '--router', 'home', '--read-only']
    });
    expect(invocation.args).not.toContain('keenetic-noc-mcp');
  });

  it('renders escaped display-only argv without exposing control characters', () => {
    const launch = { command: '/usr/bin/node',
      args: ["/opt/keenetic noc/& dangerous/' quote\nline/index.js"] };
    const invocation = registrationInvocation('codex', 'home', launch);
    const preview = registrationPreview(invocation);
    expect(JSON.parse(preview)).toEqual([invocation.command, ...invocation.args]);
    expect(preview).not.toContain('\n');
    expect(preview).toContain('\\n');
    expect(invocation.args[5]).toBe(launch.args[0]);
  });

  it.each([['linux', 'npx'], ['win32', 'npx.cmd']] as const)(
    'pins published one-shot npx registrations on %s', async (platform, command) => {
      const dir = await mkdtemp(join(tmpdir(), 'npm-cache-'));
      try {
        const npxDir = join(dir, '_npx', 'temporary', 'node_modules', 'keenetic-noc-mcp', 'dist');
        await mkdir(npxDir, { recursive: true });
        const entrypoint = join(npxDir, 'index.js');
        await writeFile(entrypoint, '#!/usr/bin/env node\n');
        expect(currentMcpServerLaunch(process.execPath, entrypoint,
          { platform, version: '1.2.3' })).toEqual({
          command,
          args: ['-y', 'keenetic-noc-mcp@1.2.3']
        });
      } finally { await rm(dir, { recursive: true, force: true }); }
    }
  );

  it('refuses an ephemeral npx development build that cannot be pinned', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'npm-cache-'));
    try {
      const npxDir = join(dir, '_npx', 'temporary');
      await mkdir(npxDir, { recursive: true });
      const entrypoint = join(npxDir, 'index.js');
      await writeFile(entrypoint, '#!/usr/bin/env node\n');
      expect(() => currentMcpServerLaunch(process.execPath, entrypoint,
        { version: '0.0.0-dev' })).toThrow(/temporary npx cache/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each(['latest', '^1.2.3', 'npm:other-package@1.2.3', 'https://example.test/pkg.tgz'])(
    'refuses non-exact npx package version %s', async version => {
      const dir = await mkdtemp(join(tmpdir(), 'npm-cache-'));
      try {
        const npxDir = join(dir, '_npx', 'temporary');
        await mkdir(npxDir, { recursive: true });
        const entrypoint = join(npxDir, 'index.js');
        await writeFile(entrypoint, '#!/usr/bin/env node\n');
        expect(() => currentMcpServerLaunch(process.execPath, entrypoint, { version }))
          .toThrow(/exact semantic version/);
      } finally { await rm(dir, { recursive: true, force: true }); }
    }
  );

  it('accepts an exact prerelease version for a published npx build', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'npm-cache-'));
    try {
      const npxDir = join(dir, '_npx', 'temporary');
      await mkdir(npxDir, { recursive: true });
      const entrypoint = join(npxDir, 'index.js');
      await writeFile(entrypoint, '#!/usr/bin/env node\n');
      expect(currentMcpServerLaunch(process.execPath, entrypoint,
        { version: '1.2.3-rc.1+build.5' })).toEqual({
        command: 'npx',
        args: ['-y', 'keenetic-noc-mcp@1.2.3-rc.1+build.5']
      });
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
