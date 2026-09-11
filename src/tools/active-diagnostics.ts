import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import {
  ActiveDiagnosticCoordinator,
  pingCommand,
  tracerouteCommand
} from '../router/active-diagnostics.js';
import {
  activeDiagnosticReport,
  budgetActiveDiagnostic
} from '../shape/active-diagnostics.js';
import { guard, ok, type ToolContext } from './registry.js';

const ACTIVE = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true
} as const;
const INPUT_BYTES = 64_000;

export function registerActiveDiagnosticTools(server: McpServer, ctx: ToolContext): void {
  const coordinator = new ActiveDiagnosticCoordinator();

  server.registerTool('ping', {
    title: 'Ping from the router',
    description:
      'Sends a small, finite ICMP echo test from the selected router to one target. ' +
      'This emits network traffic but does not change or save router configuration.',
    inputSchema: {
      target: z.string().min(1).max(253).describe('One ASCII hostname, IPv4 address, or IPv6 address.'),
      family: z.enum(['ipv4', 'ipv6']).optional().default('ipv4'),
      count: z.number().int().min(1).max(5).optional().default(3),
      timeout_ms: z.number().int().min(1_000).max(15_000).optional().default(5_000)
    },
    annotations: ACTIVE
  }, guard(async ({ target, family, count, timeout_ms }, request) => {
    const command = pingCommand(target, family, count);
    return coordinator.run(async () => {
      const result = await ctx.client.rci.runContinued(command.path, command.body, INPUT_BYTES, {
        signal: request.mcpReq.signal, timeoutMs: timeout_ms
      });
      const report = activeDiagnosticReport({ operation: 'ping', target: command.body['host'] as string,
        limitsApplied: { family, count, timeoutMs: result.effectiveTimeoutMs },
        messages: result.messages, termination: result.termination });
      return ok(budgetActiveDiagnostic(report, ctx.maxResponseBytes), ctx.maxResponseBytes);
    });
  }));

  server.registerTool('traceroute', {
    title: 'Trace a route from the router',
    description:
      'Runs one finite UDP traceroute from the selected router to one target with a hard hop ' +
      'and time ceiling. This emits network traffic but does not change router configuration.',
    inputSchema: {
      target: z.string().min(1).max(253).describe('One ASCII hostname, IPv4 address, or IPv6 address.'),
      max_hops: z.number().int().min(1).max(30).optional().default(15),
      timeout_ms: z.number().int().min(1_000).max(30_000).optional().default(15_000)
    },
    annotations: ACTIVE
  }, guard(async ({ target, max_hops, timeout_ms }, request) => {
    const command = tracerouteCommand(target, max_hops);
    return coordinator.run(async () => {
      const result = await ctx.client.rci.runContinued(command.path, command.body, INPUT_BYTES, {
        signal: request.mcpReq.signal, timeoutMs: timeout_ms
      });
      const report = activeDiagnosticReport({ operation: 'traceroute', target: command.body['host'] as string,
        limitsApplied: { maxHops: max_hops, probesPerHop: 3,
          timeoutMs: result.effectiveTimeoutMs }, messages: result.messages,
        termination: result.termination });
      return ok(budgetActiveDiagnostic(report, ctx.maxResponseBytes), ctx.maxResponseBytes);
    });
  }));
}
