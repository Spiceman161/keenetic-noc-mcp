import type { ToolRegistrar } from '../telemetry/instrumentation.js';
import { readConfigState } from '../router/config-state.js';
import { guard, ok, READ_ONLY, type ToolContext } from './registry.js';

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

export function registerSystemTools(server: ToolRegistrar, ctx: ToolContext): void {
  server.registerTool(
    'get_connection_status',
    { title: 'Connection status', description: 'Safely tests RCI reachability and authentication without exposing credentials.', inputSchema: {}, annotations: READ_ONLY },
    guard(ctx, async () => {
      const started = performance.now();
      const [caps, measured] = await Promise.all([
        ctx.client.capabilities(),
        ctx.client.probedCapabilities()
      ]);
      const endpoint = new URL(ctx.connection?.endpoint ?? 'http://router.invalid/');
      const mode = ctx.connection?.mode ?? 'lan';
      const startup = measured.config.startup;
      const backup = measured.config.backup;
      const startupConfigCapability = startup.state === 'available'
        ? startup.method
        : startup.state;
      const backupPathCapability = mode === 'remote'
        ? 'unsupported-remotely'
        : ctx.backup.taken() || backup.state === 'available'
          ? 'verified'
          : backup.state === 'unavailable' ? 'unavailable' : 'not-tested';
      const backupBeforeWrite = mode === 'remote'
        ? 'requires-lan-profile'
        : backup.state === 'available'
          ? 'available-when-verified'
          : backup.state;
      return ok({ routerId: ctx.routerId ?? 'home', mode: ctx.connection?.mode ?? 'lan', endpointHostname: endpoint.hostname,
        https: endpoint.protocol === 'https:', tlsVerified: endpoint.protocol === 'https:' ? true : null,
        rciReachable: true, authentication: 'ok', latencyMs: Math.round(performance.now() - started),
        model: caps.model, firmware: caps.firmware, startupConfigCapability,
        backupPathCapability, backupBeforeWrite, configCapabilities: measured.config }, ctx.maxResponseBytes);
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
    guard(ctx, async () => {
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
      }, ctx.maxResponseBytes);
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
    guard(ctx, async () => ok(await readConfigState(ctx.client.rci), ctx.maxResponseBytes))
  );
}
