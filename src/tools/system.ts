import type { McpServer } from '@modelcontextprotocol/server';
import { readConfigState } from '../router/config-state.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

export function registerSystemTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'get_connection_status',
    { title: 'Connection status', description: 'Safely tests RCI reachability and authentication without exposing credentials.', inputSchema: {}, annotations: READ_ONLY },
    guard(async () => {
      const started = performance.now();
      const caps = await ctx.client.capabilities();
      const endpoint = new URL(ctx.connection?.endpoint ?? 'http://router.invalid/');
      return ok({ routerId: ctx.routerId ?? 'home', mode: ctx.connection?.mode ?? 'lan', endpointHostname: endpoint.hostname,
        https: endpoint.protocol === 'https:', tlsVerified: endpoint.protocol === 'https:' ? true : null,
        rciReachable: true, authentication: 'ok', latencyMs: Math.round(performance.now() - started),
        model: caps.model, firmware: caps.firmware, backupPathCapability: ctx.backup.taken() ? 'verified' : 'not-tested' });
    })
  );
  server.registerTool(
    'get_system_info',
    {
      title: 'Router system information',
      description:
        'Model, firmware version, uptime, CPU and memory load, and the list of installed ' +
        'KeeneticOS components. Call this first when you need to know what the router supports: ' +
        'the component list tells you which features exist on this device.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(async () => {
      const [caps, system] = await Promise.all([
        ctx.client.capabilities(),
        ctx.client.rci.get('show/system')
      ]);
      const s = asRecord(system);

      return ok({
        model: caps.model,
        hardwareId: caps.hwId,
        firmware: caps.firmware,
        hostname: s['hostname'] ?? '',
        uptimeSeconds: Number(s['uptime'] ?? 0),
        cpuLoad: s['cpuload'] ?? null,
        memoryTotalKb: s['memtotal'] ?? null,
        memoryFreeKb: s['memfree'] ?? null,
        connectionsTotal: s['conntotal'] ?? null,
        connectionsFree: s['connfree'] ?? null,
        components: [...caps.components].sort(),
        features: [...caps.features].sort()
      });
    })
  );

  server.registerTool(
    'get_config_state',
    {
      title: 'Configuration state',
      description:
        'Whether the running configuration has unsaved changes, who last changed it and when, ' +
        'and the state of the router fail-safe timer. Unsaved changes are lost on reboot. ' +
        'unsavedChanges is null when the saved checksum could not be read - treat that as ' +
        'unknown, not as saved.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(async () => ok(await readConfigState(ctx.client.rci)))
  );
}
