import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { ValidationError } from '../router/errors.js';
import { isVpnInterfaceType } from '../shape/project.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

const record = (v: unknown): Record<string, unknown> => v && typeof v === 'object' ? v as Record<string, unknown> : {};
const scalar = (value: unknown, fallback: string | null): string | number | boolean | null =>
  typeof value === 'string' || typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value)) ? value : fallback;

export function projectVpn(name: string, value: unknown): Record<string, unknown> {
  const item = record(value);
  return {
    name,
    type: scalar(item['type'], 'unknown'),
    description: scalar(item['description'], ''),
    state: scalar(item['state'], ''),
    link: scalar(item['link'], ''),
    address: scalar(item['address'], null),
    uptime: scalar(item['uptime'], null)
  };
}

async function all(ctx: ToolContext): Promise<Array<Record<string, unknown>>> {
  const raw = record(await ctx.client.rci.get('show/interface'));
  return Object.entries(raw)
    .filter(([, value]) => isVpnInterfaceType(record(value)['type']))
    .map(([name, value]) => projectVpn(name, value));
}

export function registerVpnTools(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool('list_vpn', { title: 'List VPN interfaces', description: 'Compact interface observations for exactly classified VPN interfaces.', inputSchema: {}, annotations: READ_ONLY }, guard(ctx, async () => ok({ vpn: await all(ctx) }, ctx.maxResponseBytes)));
  server.registerTool('get_vpn', { title: 'Get one VPN interface', description: 'Interface observations for one exactly classified VPN interface.', inputSchema: { name: z.string() }, annotations: READ_ONLY }, guard(ctx, async ({ name }) => {
    const found = (await all(ctx)).find(item => item['name'] === name);
    if (!found) throw new ValidationError(`VPN interface "${name}" was not found. Call list_vpn.`);
    return ok(found, ctx.maxResponseBytes);
  }));
}
