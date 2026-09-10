import { chmod, writeFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import {
  lastChangeMoved,
  readConfigState,
  readLastChange,
  STARTUP_CONFIG,
  type LastChange
} from '../router/config-state.js';
import { fail, guard, ok, type ToolContext, type ToolResult } from './registry.js';
import { GuardError } from '../router/errors.js';
import { ValidationError } from '../router/errors.js';
import {
  assertStructuredSection,
  readCliConfig,
  readStructuredRunningConfig,
  type ConfigSource
} from '../router/config-reader.js';
import { redactConfigLines, redactStructuredConfig } from '../security/redact.js';
import {
  boundedArrayEnvelope,
  boundedStructuredEnvelope,
  filterConfigLines,
  searchConfigLines,
  selectConfigSection,
  type ConfigSection
} from '../shape/config.js';
import { READ_ONLY } from './registry.js';

const sectionSchema = z.enum(['dns', 'interfaces', 'routing', 'wifi', 'vpn', 'users', 'system', 'all']);
const formatSchema = z.enum(['cli', 'structured']).optional().default('cli');

function requireFullLimit(section: ConfigSection, limit: number | undefined): number {
  if (section === 'all' && (limit === undefined || limit < 200)) {
    throw new ValidationError('section=all requires an explicit limit of at least 200.');
  }
  return limit ?? 200;
}

function unavailableEnvelope(
  source: ConfigSource,
  format: 'cli' | 'structured',
  section: ConfigSection,
  read: { state: string; method: null; reason: unknown }
): Record<string, unknown> {
  return { source, format, section, available: false, state: read.state,
    method: read.method, reason: read.reason };
}

async function getConfig(
  ctx: ToolContext,
  source: ConfigSource,
  args: { section: ConfigSection; format: 'cli' | 'structured'; filter?: string | undefined;
    limit?: number | undefined }
): Promise<ToolResult> {
  const { section, format, filter } = args;
  const limit = requireFullLimit(section, args.limit);
  if (format === 'structured') {
    if (source === 'startup') throw new ValidationError('Startup configuration is available only in format=cli.');
    if (filter !== undefined) throw new ValidationError('filter is supported only with format=cli.');
    assertStructuredSection(section);
    const read = await readStructuredRunningConfig(ctx.client, section);
    return ok(boundedStructuredEnvelope({ source, format, section, available: true,
      method: read.method, omittedBranches: read.omittedBranches },
    redactStructuredConfig(read.data) as Record<string, unknown>, limit,
    ctx.maxResponseBytes), ctx.maxResponseBytes);
  }

  const read = await readCliConfig(ctx.client, source);
  if (!read.available) return ok(unavailableEnvelope(source, format, section, read), ctx.maxResponseBytes);
  const sectionLines = selectConfigSection(redactConfigLines(read.lines), section);
  const selected = filterConfigLines(sectionLines, filter);
  const limited = selected.slice(0, limit).map(line => line.text);
  const payload = boundedArrayEnvelope({ source, format, section, available: true,
    method: read.method }, 'lines', limited, ctx.maxResponseBytes, selected.length);
  return ok(payload, ctx.maxResponseBytes);
}

function registerConfigReadTools(server: McpServer, ctx: ToolContext): void {
  const common = {
    section: sectionSchema.describe('Required configuration section; use all only with an explicit limit of at least 200.'),
    filter: z.string().max(500).optional().describe('Optional normalized literal filter for CLI lines.'),
    limit: z.number().int().min(1).max(1000).optional()
  };
  server.registerTool('get_running_config', {
    title: 'Read running configuration',
    description: 'Returns a bounded, secret-redacted section of the active running configuration without changing the router.',
    inputSchema: { ...common, format: formatSchema },
    annotations: READ_ONLY
  }, guard(async args => getConfig(ctx, 'running', args)));

  server.registerTool('get_startup_config', {
    title: 'Read startup configuration',
    description: 'Returns a bounded, secret-redacted CLI section saved for reboot, or an explicit measured capability result.',
    inputSchema: { ...common, format: z.literal('cli').optional().default('cli') },
    annotations: READ_ONLY
  }, guard(async args => getConfig(ctx, 'startup', args)));

  server.registerTool('search_config', {
    title: 'Search router configuration',
    description: 'Searches one explicitly selected running or startup configuration using bounded normalized literal matching.',
    inputSchema: {
      source: z.enum(['running', 'startup']),
      query: z.string().min(1).max(500).refine(value => value.trim().length > 0,
        'query must contain non-whitespace text'),
      section: sectionSchema.optional().default('all'),
      limit: z.number().int().min(1).max(200).optional().default(50),
      context: z.number().int().min(0).max(5).optional().default(2)
    },
    annotations: READ_ONLY
  }, guard(async ({ source, query, section, limit, context }) => {
    const read = await readCliConfig(ctx.client, source);
    if (!read.available) return ok(unavailableEnvelope(source, 'cli', section, read), ctx.maxResponseBytes);
    const corpus = selectConfigSection(redactConfigLines(read.lines), section);
    const found = searchConfigLines(corpus, query, limit, context);
    const payload = boundedArrayEnvelope({ source, format: 'cli', section, available: true,
      method: read.method, shownMatches: found.totalMatches, totalMatches: found.totalMatches,
      context }, 'groups', found.groups, ctx.maxResponseBytes, found.groups.length,
    found.shownMatches < found.totalMatches);
    const returnedGroups = payload['groups'] as typeof found.groups;
    payload['shownMatches'] = returnedGroups.flatMap(group => group.lines)
      .filter(line => line.match).length;
    return ok(payload, ctx.maxResponseBytes);
  }));
}

/**
 * The router answers the save command with "saving (http/rci)." in the present
 * tense, so the write may still be in flight. A single immediate check would
 * report a false failure; this polls briefly instead.
 *
 * The loop watches show/last-change, which is a small JSON document. The
 * confirmation reads startup-config.txt at about 17 KB, so it runs once at the
 * end rather than on every attempt.
 *
 * Only an explicit `false` counts as saved. An unknown saved state resolves to
 * "not confirmed", so a failed read sends the caller to look rather than
 * telling them the save landed.
 */
async function waitForSaved(
  ctx: ToolContext,
  before: LastChange,
  attempts = 5,
  delayMs = 400
): Promise<boolean> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (lastChangeMoved(before, await readLastChange(ctx.client.rci))) break;
    await new Promise(resolve => setTimeout(resolve, delayMs));
  }
  return (await readConfigState(ctx.client.rci)).unsavedChanges === false;
}

export function registerConfigTools(server: McpServer, ctx: ToolContext): void {
  registerConfigReadTools(server, ctx);
  if (ctx.readOnly) return;

  server.registerTool(
    'backup_config',
    {
      title: 'Download a configuration backup',
      description:
        'Writes the router startup configuration to a new owner-only local file. Existing ' +
        'files are never overwritten. Preview the destination before confirming the write.',
      inputSchema: {
        path: z.string().describe('Absolute path of the new local file to create.'),
        dry_run: z.boolean().optional().default(true),
        confirm: z.boolean().optional().default(false)
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false }
    },
    guard(async ({ path, dry_run, confirm }): Promise<ToolResult> => {
      if (!isAbsolute(path)) return fail(new Error('Backup destination must be an absolute path.'));
      if (dry_run !== false) return ok({ dryRun: true, path, effect: 'create owner-only startup-config backup; existing files are refused' }, ctx.maxResponseBytes);
      if (!confirm) throw new GuardError('Writing a local backup requires confirm=true together with dry_run=false.');
      const text = await ctx.client.rci.getText(STARTUP_CONFIG);
      try {
        await writeFile(path, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        await chmod(path, 0o600);
      } catch (error) {
        return fail(
          new Error(
            `Could not create "${path}": ${(error as Error).message} ` +
              'Give an unused absolute path in a directory that exists.'
          )
        );
      }
      return ok({ path, bytes: Buffer.byteLength(text, 'utf8') }, ctx.maxResponseBytes);
    })
  );

  server.registerTool(
    'save_config',
    {
      title: 'Save the configuration',
      description:
        'Writes the running configuration to the startup configuration, so pending ' +
        'changes survive a reboot. Nothing else in this server saves, so call this only ' +
        'once the user has confirmed the changes are what they want.',
      inputSchema: { dry_run: z.boolean().optional().default(true), confirm: z.boolean().optional().default(false) },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true }
    },
    guard(async ({ dry_run, confirm }): Promise<ToolResult> => {
      const planned = { system: { configuration: { save: {} } } };
      const base = { tool: 'save_config', dryRun: dry_run, confirmed: confirm, risk: 'high', target: 'startup configuration', planned };
      if (dry_run !== false) { await ctx.audit?.write({ ...base, success: true }); return ok({ dryRun: true, plannedRciRequest: planned, expectedVerification: 'saved checksum equals running checksum', risk: 'high' }, ctx.maxResponseBytes); }
      if (!confirm) { await ctx.audit?.write({ ...base, success: false, error: 'confirmation required' }); throw new GuardError('Real save requires confirm=true.'); }
      // Taken before the command so the poll can tell the router has acted.
      const before = await readLastChange(ctx.client.rci);
      try {
        const snapshot = await ctx.backup.ensure();
        await ctx.client.rci.post(planned);
        if (!(await waitForSaved(ctx, before))) throw new Error('The save command was accepted but the router still reports unsaved changes. Call get_config_state before retrying.');
        await ctx.audit?.write({ ...base, before, verified: true, saved: true, success: true });
        return ok({ saved: true, backup: snapshot.path, note: 'The running configuration is now the startup configuration.' }, ctx.maxResponseBytes);
      } catch (error) {
        await ctx.audit?.write({ ...base, before, verified: false, saved: false, success: false, error: (error as Error).message });
        throw error;
      }
    })
  );
}
