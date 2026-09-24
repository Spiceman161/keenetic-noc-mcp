import * as z from 'zod/v4';
import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import {
  ActiveDiagnosticCoordinator,
  iperf3Command,
  pingCommand,
  tracerouteCommand
} from '../router/active-diagnostics.js';
import { parseCapabilities } from '../router/capabilities.js';
import { RciError } from '../router/errors.js';
import {
  activeDiagnosticReport,
  budgetActiveDiagnostic,
  budgetIperf3Report,
  iperf3Report
} from '../shape/active-diagnostics.js';
import { compactOk, guard, ok, type ToolContext } from './registry.js';

const ACTIVE = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true
} as const;
const INPUT_BYTES = 64_000;

export function registerActiveDiagnosticTools(server: ToolRegistrar, ctx: ToolContext): void {
  const coordinator = new ActiveDiagnosticCoordinator();

  server.registerTool('ping', {
    title: 'Ping from the router',
    description:
      'Sends a small, finite ICMP echo test from the selected router to one target. ' +
      'This emits network traffic but does not change or save router configuration.',
    inputSchema: {
      target: z.string().min(1).max(253).describe('One ASCII hostname, IPv4 address, or IPv6 address.'),
      family: z.enum(['ipv4', 'ipv6']).optional().default('ipv4'),
      source_interface: z.string().min(1).max(128).optional()
        .describe('Exact router interface ID from list_interfaces; IPv4 only. Requests that the router use this interface for bounded traffic; actual egress is not independently verified.'),
      count: z.number().int().min(1).max(5).optional().default(3),
      timeout_ms: z.number().int().min(1_000).max(15_000).optional().default(5_000)
    },
    annotations: ACTIVE
  }, guard(ctx, async ({ target, family, source_interface, count, timeout_ms }, request) => {
    const command = pingCommand(target, family, count, source_interface);
    return coordinator.run(async () => {
      const result = await ctx.client.rci.runContinued(command.path, command.body, INPUT_BYTES, {
        signal: request.mcpReq.signal, timeoutMs: timeout_ms
      });
      const report = activeDiagnosticReport({ operation: 'ping', target: command.body['host'] as string,
        limitsApplied: { family, count, timeoutMs: result.effectiveTimeoutMs,
          ...(source_interface === undefined ? {} : { sourceInterface: source_interface }) },
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
  }, guard(ctx, async ({ target, max_hops, timeout_ms }, request) => {
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

  server.registerTool('iperf3', {
    title: 'Bounded iPerf3 client characterization',
    description: 'Starts one finite byte-limited TCP iPerf3 client job to an explicitly authorized server. ' +
      'This emits active network traffic; reverse direction and router-side cancellation are not yet ' +
      'independently proven. Completion does not establish transfer success or throughput.',
    inputSchema: {
      server_host: z.string().min(1).max(253).describe('One explicitly authorized ASCII hostname or IPv4 address.'),
      server_port: z.number().int().min(5201).max(5210),
      source_interface: z.string().min(1).max(128).optional()
        .describe('Exact interface ID from list_interfaces; requested source only, not independently verified egress.'),
      direction: z.enum(['upload', 'reverse']),
      byte_limit_bytes: z.number().int().min(1_048_576).max(20_971_520),
      timeout_ms: z.number().int().min(1_000).max(30_000)
    },
    annotations: ACTIVE
  }, guard(ctx, async ({ server_host, server_port, source_interface, direction,
    byte_limit_bytes, timeout_ms }, request) => {
    const command = iperf3Command(server_host, server_port, direction, byte_limit_bytes,
      source_interface);
    const capabilities = await ctx.client.capabilities();
    if (!capabilities.components.has('iperf3')) {
      const version: unknown = await ctx.client.rci.get('show/version', 64_000);
      const ndw = version !== null && typeof version === 'object' && !Array.isArray(version)
        ? (version as Record<string, unknown>)['ndw'] : undefined;
      const components = ndw !== null && typeof ndw === 'object' && !Array.isArray(ndw)
        ? (ndw as Record<string, unknown>)['components'] : undefined;
      if (typeof components !== 'string' ||
          (components.length > 0 && components.split(',').some(part => part.trim() === ''))) {
        throw new RciError('show/version did not provide a valid components list', {
          path: 'show/version', code: 'unexpected-response', ident: 'rci'
        });
      }
      if (!parseCapabilities(version).components.has('iperf3')) {
        return compactOk(budgetIperf3Report(iperf3Report({ serverHost: command.body['host'] as string,
          serverPort: server_port, requestedDirection: direction,
          ...(source_interface === undefined ? {} : { requestedSourceInterface: source_interface }),
          byteLimitBytes: byte_limit_bytes,
          timeoutMs: timeout_ms }), ctx.maxResponseBytes), ctx.maxResponseBytes);
      }
    }
    return coordinator.run(async () => {
      const result = await ctx.client.rci.runContinued(command.path, command.body, INPUT_BYTES, {
        signal: request.mcpReq.signal, timeoutMs: timeout_ms
      });
      return compactOk(budgetIperf3Report(iperf3Report({ serverHost: command.body['host'] as string,
        serverPort: server_port, requestedDirection: direction,
        ...(source_interface === undefined ? {} : { requestedSourceInterface: source_interface }),
        byteLimitBytes: byte_limit_bytes,
        timeoutMs: result.effectiveTimeoutMs, termination: result.termination,
        messages: result.messages }), ctx.maxResponseBytes), ctx.maxResponseBytes);
    });
  }));
}
