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
