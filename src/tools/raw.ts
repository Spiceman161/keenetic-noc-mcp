import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { GuardError, ValidationError } from '../router/errors.js';
import { fail, guard, ok, type ToolContext, type ToolResult } from './registry.js';
import { writeAuditOutcome } from '../security/audit.js';

type RawBody = string | Record<string, unknown> | unknown[];

type Decoded = { ok: true; body: unknown } | { ok: false; message: string };

/**
 * Accepts a body that arrived as text and turns it back into a command tree.
 *
 * The schema for `body` used to be `z.unknown()`, which emits a JSON Schema
 * carrying no `type` at all. A client given nothing to go on may serialise the
 * argument to a string; that string was then JSON-encoded a second time on the
 * way out, so the router received a bare string, matched no command and
 * answered `{}`. Shaped like success, a no-op in fact - the exact failure this
 * server exists to prevent everywhere else.
 *
 * Decoding keeps those callers working. Anything that still is not a command
 * tree afterwards is refused rather than sent.
 */
function decodeBody(body: RawBody): Decoded {
  if (typeof body !== 'string') return { ok: true, body };

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      ok: false,
      message:
        'The body is a string that is not JSON (invalid syntax). Send the command as ' +
        'JSON, for example {"show": {"version": {}}}.'
    };
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return {
      ok: false,
      message:
        `The body decoded to a ${typeof parsed}, not a command tree. Send an object such as ` +
        '{"show": {"version": {}}}, or an array of them for a batch.'
    };
  }

  return { ok: true, body: parsed };
}

function unsafeRaw(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(unsafeRaw);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value as Record<string, unknown>).some(([key, child]) =>
    /^(user|crypto|auth|security|http-proxy)$/i.test(key) || unsafeRaw(child));
}

export function registerRawTool(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool(
    'rci_call',
    {
      title: 'Call the router API directly',
      description:
        'Sends a raw request to the router RCI interface, for anything the other tools do ' +
        'not cover. GET reads a path such as "show/version" or "interface/Bridge0"; POST ' +
        'sends a command object mirroring the CLI tree. The response is capped, so ask for ' +
        'a narrow path rather than a broad one: show/ip/nat alone is over 100 KB.',
      inputSchema: {
        method: z.enum(['GET', 'POST']).describe('GET reads, POST executes a command.'),
        path: z
          .string()
          .optional()
          .describe('Path after /rci/, for GET. Example: show/interface/Bridge0'),
        // Typed as a union rather than z.unknown() so the emitted schema tells a
        // client what shape to send; see decodeBody for what the loose form cost.
        body: z
          .union([z.record(z.string(), z.unknown()), z.array(z.unknown()), z.string()])
          .optional()
          .describe(
            'Command object for POST, mirroring the CLI tree, or an array of them for a ' +
              'batch. Send JSON, not a stringified object.'
          ),
        max_bytes: z
          .number()
          .int()
          .min(200)
          .optional()
          .describe('Lower the response ceiling for this call. It can never raise it.'),
        dry_run: z.boolean().optional().default(true).describe('POST preview; defaults true.'),
        confirm: z.boolean().optional().default(false).describe('Required with dry_run=false.')
      },
      // In read-only mode POST is refused, so the tool genuinely cannot modify
      // anything and the annotation says so rather than overstating the risk.
      annotations: ctx.readOnly
        ? { readOnlyHint: true, openWorldHint: false }
        : { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
    },
    guard(ctx, async ({ method, path, body, max_bytes, dry_run, confirm }): Promise<ToolResult> => {
      let payload: unknown;
      const ceiling = Math.min(ctx.maxResponseBytes, max_bytes ?? ctx.maxResponseBytes);

      if (method === 'GET') {
        if (path === undefined || path.length === 0) {
          return fail(new ValidationError('GET needs a path, for example "show/version".'), ceiling);
        }
      } else {
        if (ctx.readOnly) {
          return fail(
            new GuardError(
              'This server is running read-only, so raw POST is refused.'
            ), ceiling
          );
        }
        if (ctx.allowRawWrite === false) {
          return fail(new GuardError('Raw POST is disabled. Set KEENETIC_ALLOW_RAW_WRITE=true to enable its guarded use.'), ceiling);
        }
        if (body === undefined) {
          return fail(new ValidationError('POST needs a body, for example {"show": {"version": {}}}.'), ceiling);
        }
        const decoded = decodeBody(body);
        if (!decoded.ok) return fail(new ValidationError(decoded.message), ceiling);
        payload = decoded.body;
        if (unsafeRaw(payload)) return fail(new GuardError('Raw POST refused: payload touches an auth, crypto, security, user, or HTTP proxy branch.'), ceiling);
        if (dry_run !== false) return ok({ dryRun: true, plannedRciRequest: payload,
          risk: 'high', expectedVerification: 'manual narrow GET read-back required' }, ceiling);
        if (!confirm) return fail(new GuardError('Raw POST requires confirm=true together with dry_run=false.'), ceiling);
        await ctx.audit?.write({ tool: 'rci_call', dryRun: false, confirmed: true,
          risk: 'high', target: 'raw RCI', planned: payload, phase: 'started', success: null });
        await ctx.backup.ensure();
      }

      let result: unknown;
      let auditRecorded = true;
      try {
        result = method === 'GET'
          ? await ctx.client.rci.get(path as string, ceiling)
          : await ctx.client.rci.post(payload, ceiling);
        if (method === 'POST') auditRecorded = await writeAuditOutcome(ctx.audit, { tool: 'rci_call',
          dryRun: false, confirmed: true, risk: 'high', target: 'raw RCI', planned: payload,
          verified: false, saved: false, success: true });
      } catch (error) {
        if (method === 'POST') {
          const auditRecorded = await writeAuditOutcome(ctx.audit, { tool: 'rci_call',
            dryRun: false, confirmed: true, risk: 'high', target: 'raw RCI', planned: payload,
            verified: false, saved: false, success: null, uncertain: true,
            error: (error as Error).message });
          return ok({ applied: 'unknown', verified: false, retrySafe: false, auditRecorded,
            note: 'Read current state; do not retry blindly.' }, ceiling);
        }
        if (method === 'GET') return fail(error, ceiling);
      }

      // max_bytes may only tighten the ceiling: a tool argument must not be able
      // to overrun the budget the operator configured with --max-response-bytes.
      return ok(method === 'POST' && !auditRecorded
        ? { auditRecorded: false, auditWarning: 'Final audit outcome could not be recorded.',
            resultIncluded: false }
        : result, ceiling);
    })
  );
}
