import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { capList } from '../shape/budget.js';
import { projectInterface } from '../shape/project.js';
import { fail, guard, ok, READ_ONLY, type ToolContext, type ToolResult } from './registry.js';
import { describeWrite, verifiedWrite } from './write.js';
import { GuardError, VerificationError } from '../router/errors.js';

type InterfaceKind = 'all' | 'wan' | 'lan' | 'wifi' | 'vpn' | 'bridge';

/**
 * Reads one interface by name.
 *
 * Asked through POST rather than by building `show/interface/<name>`: every
 * Wi-Fi access point is named like `WifiMaster0/AccessPoint0`, and the slash is
 * read as a further path segment, so the GET form is a 404 for exactly the
 * interfaces list_interfaces reports under kind=wifi.
 */
async function readInterface(ctx: ToolContext, name: string): Promise<Record<string, unknown>> {
  const raw = await ctx.client.rci.post({ show: { interface: { name } } });
  const outer = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
  const show = typeof outer['show'] === 'object' && outer['show'] !== null
    ? (outer['show'] as Record<string, unknown>)
    : {};
  const record = show['interface'];
  return typeof record === 'object' && record !== null ? (record as Record<string, unknown>) : {};
}

const VPN_TYPES = new Set(['Wireguard', 'OpenVPN', 'L2TP', 'PPTP', 'IPsec', 'Sstp']);

function matchesKind(id: string, record: Record<string, unknown>, kind: InterfaceKind): boolean {
  const type = typeof record['type'] === 'string' ? record['type'] : '';
  switch (kind) {
    case 'wan':
      return record['role'] === 'inet' || record['defaultgw'] === true;
    case 'wifi':
      return id.includes('WifiMaster') || type === 'AccessPoint';
    case 'vpn':
      return VPN_TYPES.has(type);
    case 'bridge':
      return type === 'Bridge';
    case 'lan':
      return type === 'Bridge' || type.includes('Ethernet');
    default:
      return true;
  }
}

export function registerInterfaceTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'list_interfaces',
    {
      title: 'List network interfaces',
      description:
        'Every interface on the router - WAN links, bridges, Wi-Fi access points and VPN ' +
        'tunnels - with link state, address and whether it carries the default route. ' +
        'Summary detail is the default because the full listing is very large.',
      inputSchema: {
        kind: z
          .enum(['all', 'wan', 'lan', 'wifi', 'vpn', 'bridge'])
          .optional()
          .describe('Which interfaces to include. Defaults to all.'),
        detail: z
          .enum(['summary', 'full'])
          .optional()
          .describe('summary returns seven fields per interface; full returns every field.'),
        limit: z.number().int().min(1).max(200).optional().describe('Maximum rows. Defaults to 100.')
      },
      annotations: READ_ONLY
    },
    guard(async ({ kind, detail, limit }) => {
      const raw = await ctx.client.rci.get('show/interface');
      const all = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};

      const selected = Object.entries(all).filter(([id, record]) =>
        matchesKind(
          id,
          typeof record === 'object' && record !== null ? (record as Record<string, unknown>) : {},
          kind ?? 'all'
        )
      );

      const shaped =
        detail === 'full'
          ? selected.map(([id, record]) => ({ id, ...(record as Record<string, unknown>) }))
          : selected.map(([id, record]) => projectInterface(id, record));

      const capped = capList(shaped, limit ?? 100, ctx.maxResponseBytes);
      return ok({
        interfaces: capped.items,
        shown: capped.shown,
        total: capped.total,
        ...(capped.note ? { note: capped.note } : {})
      });
    })
  );

  server.registerTool(
    'get_interface',
    {
      title: 'Get one interface in full',
      description:
        'Every field for a single interface, including protocol-specific detail such as ' +
        'WireGuard peers or PPPoE session state. Get the exact name from list_interfaces first.',
      inputSchema: {
        name: z.string().describe('Interface id, for example Bridge0 or Wireguard3.')
      },
      annotations: READ_ONLY
    },
    guard(async ({ name }): Promise<ToolResult> => {
      try {
        return ok(await readInterface(ctx, name));
      } catch (error) {
        return fail(
          new Error(
            `Could not read interface "${name}": ${(error as Error).message} ` +
              'Call list_interfaces to see the exact ids available on this router.'
          )
        );
      }
    })
  );

  // A read-only server must not advertise what it will refuse to do.
  if (ctx.readOnly) return;

  server.registerTool(
    'set_interface_state',
    {
      title: 'Bring an interface up or down',
      description:
        'Enables or disables a network interface. Taking down a bridge or the WAN link ' +
        'can cut off access to the router itself, including this connection. Confirm what ' +
        'the interface carries with get_interface before calling this.',
      inputSchema: {
        name: z.string().describe('Interface id from list_interfaces.'),
        state: z.enum(['up', 'down']).describe('Desired administrative state.'),
        dry_run: z.boolean().optional().default(true),
        confirm: z.boolean().optional().default(false)
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true }
    },
    guard(async ({ name, state, dry_run, confirm }): Promise<ToolResult> => {
      const body =
        state === 'up'
          ? { interface: { [name]: { up: true } } }
          : { interface: { [name]: { up: { no: true } } } };
      const base = { tool: 'set_interface_state', dryRun: dry_run, confirmed: confirm, risk: state === 'down' ? 'high' : 'medium', target: name, planned: body };
      if (ctx.protectedInterfaces?.has(name)) { await ctx.audit?.write({ ...base, success: false, error: 'protected interface' }); throw new GuardError(`Interface "${name}" is protected.`); }
      if (dry_run !== false) { await ctx.audit?.write({ ...base, success: true, verified: false }); return ok({ dryRun: true, target: name, plannedRciRequest: body, expectedVerification: `state=${state}`, risk: base.risk }); }
      if (!confirm) { await ctx.audit?.write({ ...base, success: false, error: 'confirmation required' }); throw new GuardError('Real mutation requires confirm=true.'); }
      try {
        const before = await readInterface(ctx, name);
        if (state === 'down' && before['defaultgw'] === true && !ctx.allowDestructive) throw new GuardError(`Disabling default-gateway interface "${name}" requires KEENETIC_ALLOW_DESTRUCTIVE=true.`);
        const snapshot = await ctx.backup.ensure();
        const after = await verifiedWrite({ apply: () => ctx.client.rci.post(body), readBack: () => readInterface(ctx, name), check: r => r['state'] === state, what: `${name} state=${state}` });
        await ctx.audit?.write({ ...base, before, after, verified: true, saved: false, backupPath: snapshot.path, success: true });
        return ok(describeWrite({ interface: name, state }, snapshot.path));
      } catch (error) { await ctx.audit?.write({ ...base, verified: false, success: false, error: (error as Error).message }); throw error; }
    })
  );

  server.registerTool('restart_interface', {
    title: 'Restart an interface', description: 'Bounded down/up cycle with verification. Previewed by default.',
    inputSchema: { name: z.string(), dry_run: z.boolean().optional().default(true), confirm: z.boolean().optional().default(false) },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false }
  }, guard(async ({ name, dry_run, confirm }) => {
    const planned = [{ interface: { [name]: { up: { no: true } } } }, { interface: { [name]: { up: true } } }];
    const base = { tool: 'restart_interface', dryRun: dry_run, confirmed: confirm, risk: 'high', target: name, planned };
    if (ctx.protectedInterfaces?.has(name)) { await ctx.audit?.write({ ...base, success: false, error: 'protected interface' }); throw new GuardError(`Interface "${name}" is protected.`); }
    if (dry_run !== false) { await ctx.audit?.write({ ...base, success: true }); return ok({ dryRun: true, plannedRciRequests: planned, expectedVerification: 'down then final state up', risk: 'high' }); }
    if (!confirm) { await ctx.audit?.write({ ...base, success: false, error: 'confirmation required' }); throw new GuardError('Real mutation requires confirm=true.'); }
    let backupPath: string | null = null;
    try { const before = await readInterface(ctx, name);
      if (before['defaultgw'] === true && !ctx.allowDestructive) throw new GuardError(`Restarting default-gateway interface "${name}" requires KEENETIC_ALLOW_DESTRUCTIVE=true.`);
      const snapshot = await ctx.backup.ensure(); backupPath = snapshot.path;
      await ctx.client.rci.post(planned[0]); if ((await readInterface(ctx, name))['state'] !== 'down') throw new VerificationError(`${name} did not go down.`);
      await new Promise(resolve => setTimeout(resolve, 500)); await ctx.client.rci.post(planned[1]); const after = await readInterface(ctx, name);
      if (after['state'] !== 'up') throw new VerificationError(`${name} did not return up.`);
      await ctx.audit?.write({ ...base, after, verified: true, saved: false, backupPath, success: true }); return ok(describeWrite({ interface: name, action: 'restart' }, backupPath));
    } catch (error) { await ctx.audit?.write({ ...base, success: false, error: (error as Error).message, backupPath }); throw error; }
  }));
}
