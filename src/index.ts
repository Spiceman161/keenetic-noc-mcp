#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { runRouterFromTerminal } from './cli/router.js';
import { configDir, migrateLegacyConfigDir, readStoredConfig } from './config/discover.js';
import { loadConfig, type StoredCredentials } from './config/load.js';
import { createSecretStore, spawnRunner } from './config/secrets.js';
import { createBackupGuard } from './router/backup.js';
import { createClient, createRemoteClient, type KeeneticClient } from './router/client.js';
import { Rci } from './router/rci.js';
import { registerConfigTools } from './tools/config.js';
import { registerDeviceTools } from './tools/devices.js';
import { registerInterfaceTools } from './tools/interfaces.js';
import { registerNetworkTools } from './tools/network.js';
import { registerRawTool } from './tools/raw.js';
import type { ToolContext } from './tools/registry.js';
import { registerSegmentTools } from './tools/segments.js';
import { registerSystemTools } from './tools/system.js';
import { registerDnsTools } from './tools/dns.js';
import { registerLogTools } from './tools/logs.js';
import { registerVpnTools } from './tools/vpn.js';
import { loadLocalEnv, resolveVersion } from './version.js';
import { createAuditWriter } from './security/audit.js';
import { stateDir } from './router/backup.js';
import { resolveProfile } from './profiles/registry.js';
import { createProfileSecretStore } from './profiles/secrets.js';

export function createServer(ctx: ToolContext): McpServer {
  const server = new McpServer({ name: 'keenetic', version: resolveVersion() });
  registerSystemTools(server, ctx);
  registerDeviceTools(server, { ...ctx, readOnly: true });
  registerInterfaceTools(server, ctx);
  registerNetworkTools(server, ctx);
  registerDnsTools(server, ctx);
  registerVpnTools(server, ctx);
  registerLogTools(server, ctx);
  registerSegmentTools(server, { ...ctx, readOnly: true });
  registerConfigTools(server, ctx);
  registerRawTool(server, ctx);
  return server;
}

/**
 * An MCP server must finish its handshake even when its optional router
 * configuration has not been created yet. Otherwise clients only see a vague
 * "connection closed" error and cannot use the server's own diagnostic tools.
 *
 * The placeholder never opens a socket. Every router operation fails through
 * the normal guarded tool path with a concrete, safe setup instruction.
 */
function createUnconfiguredClient(): KeeneticClient {
  const unavailable = (): never => {
    throw new Error(
      'Router configuration is unavailable. In an interactive terminal run "keenetic-noc-mcp router add", ' +
        'then "keenetic-noc-mcp router test <id>". Alternatively set KEENETIC_HOST (or KEENETIC_URL), ' +
        'KEENETIC_USER, and KEENETIC_PASSWORD_FILE for this MCP process.'
    );
  };
  const rci = new Rci({ request: async () => unavailable() });
  return { rci, capabilities: async () => unavailable() };
}

function unconfiguredContext(): ToolContext {
  const client = createUnconfiguredClient();
  return {
    client,
    maxResponseBytes: 25_000,
    // Never advertise write tools until a real configuration has loaded.
    readOnly: true,
    backup: createBackupGuard(client.rci, 'unconfigured', () => new Date()),
    allowRawWrite: false,
    routerId: 'unconfigured',
    connection: { mode: 'lan', endpoint: 'http://router.invalid/rci/' }
  };
}

async function main(): Promise<void> {
  // Before anything reads the environment, so a checkout can keep its router
  // credentials in .env instead of exporting them. A no-op once installed.
  loadLocalEnv();

  // Before the config is read, so it answers on a machine that has never been
  // set up. Every bug report starts by asking which version is running.
  if (process.argv.includes('--version') || process.argv.includes('-v')) {
    process.stdout.write(`${resolveVersion()}\n`);
    return;
  }

  // `init` is a subcommand rather than a second binary, so the published
  // surface stays a single command.
  if (process.argv[2] === 'router') {
    process.exit(await runRouterFromTerminal(process.argv.slice(3)));
  }
  if (process.argv[2] === 'init') {
    // Kept as the historical spelling for the new profile wizard.
    process.exit(await runRouterFromTerminal(['add']));
  }

  let ctx: ToolContext;
  try {
    await migrateLegacyConfigDir(process.platform, process.env);
    const dir = configDir(process.platform, process.env);
    const storedConfig = await readStoredConfig(dir);
    const store = createSecretStore(process.platform, spawnRunner, dir);

    // Assigned conditionally: exactOptionalPropertyTypes rejects an explicit
    // undefined for an optional property.
    const stored: StoredCredentials = {};
    const routerFlag = process.argv.indexOf('--router');
    const requestedRouter = routerFlag === -1 ? process.env['KEENETIC_ROUTER_ID'] : process.argv[routerFlag + 1];
    const hasExplicitEnvironment = Boolean(process.env['KEENETIC_URL'] || process.env['KEENETIC_HOST'] || process.env['KEENETIC_PASSWORD'] || process.env['KEENETIC_PASSWORD_FILE']);
    const profile = hasExplicitEnvironment ? null : await resolveProfile(dir, requestedRouter);
    if (profile) {
      const profileStore = await createProfileSecretStore(dir, profile.secretRef.startsWith('file:') ? 'file' : 'keychain');
      const secret = await profileStore.read(profile.id);
      if (secret === null) throw new Error(`Password for router profile "${profile.id}" is unavailable`);
      stored.host = profile.mode === 'lan' ? profile.endpoint : '';
      stored.login = profile.login;
      stored.password = secret;
    } else if (storedConfig) {
      stored.host = storedConfig.host;
      stored.login = storedConfig.login;
      const secret = await store.read(`${storedConfig.login}@${storedConfig.host}`);
      if (secret !== null) stored.password = secret;
    }

    const profileEnvironment = profile
      ? { ...process.env, ...(profile.mode === 'remote' ? { KEENETIC_URL: profile.endpoint } : { KEENETIC_HOST: profile.endpoint }) }
      : process.env;
    const config = await loadConfig(process.argv.slice(2), profileEnvironment, stored);
    if (profile) {
      config.routerId = profile.id;
      config.mode = profile.mode;
      config.host = profile.mode === 'lan' ? profile.endpoint : '';
      config.endpoint = profile.mode === 'remote' ? profile.endpoint : `http://${profile.endpoint}/rci/`;
      config.readOnly = true;
    }
    const client = config.mode === 'remote'
      ? createRemoteClient({ endpoint: config.endpoint, login: config.login, password: config.password,
          routerId: config.routerId, timeoutMs: config.timeoutMs })
      : createClient({ host: config.host, login: config.login, password: config.password,
          timeoutMs: config.timeoutMs });
    ctx = {
      client,
      maxResponseBytes: config.maxResponseBytes,
      readOnly: config.readOnly,
      backup: createBackupGuard(client.rci, config.routerId, () => new Date()),
      allowRawWrite: config.allowRawWrite,
      routerId: config.routerId,
      connection: { mode: config.mode, endpoint: config.endpoint },
      audit: createAuditWriter(stateDir(process.platform, process.env), config.routerId),
      protectedInterfaces: new Set((process.env['KEENETIC_PROTECTED_INTERFACES'] ?? '').split(',').map(v => v.trim()).filter(Boolean)),
      allowDestructive: process.env['KEENETIC_ALLOW_DESTRUCTIVE']?.toLowerCase() === 'true'
    };
  } catch {
    ctx = unconfiguredContext();
  }

  await createServer(ctx).connect(new StdioServerTransport());
}

/**
 * True when this module is the program being run, rather than imported.
 *
 * The entry path has to be resolved through symlinks first: npm installs a bin
 * as a symlink in node_modules/.bin. Comparing its entry path unresolved
 * with import.meta.url never
 * matches, and the server exits silently without ever starting.
 */
function isProgramEntry(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isProgramEntry()) {
  main().catch((error: unknown) => {
    // stderr only: stdout carries the MCP protocol stream.
    process.stderr.write(`keenetic-noc-mcp failed to start: ${(error as Error).message}\n`);
    process.exit(1);
  });
}
