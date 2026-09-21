import { isAbsolute, join, win32 } from 'node:path';
import { stateDir } from '../router/backup.js';

export type TelemetryConfig =
  | { enabled: false }
  | { enabled: true; path: string; retainRciEdgeIps: boolean };

function absolute(platform: NodeJS.Platform, path: string): boolean {
  return platform === 'win32' ? win32.isAbsolute(path) : isAbsolute(path);
}

export function loadTelemetryConfig(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv
): TelemetryConfig {
  const rawEnabled = env['KEENETIC_TELEMETRY_ENABLED'];
  if (rawEnabled === undefined || rawEnabled.toLowerCase() === 'false') return { enabled: false };
  if (rawEnabled.toLowerCase() !== 'true') {
    throw new Error('KEENETIC_TELEMETRY_ENABLED must be "true" or "false".');
  }

  // This is intentionally stricter than the enable switch: only the exact
  // lower-case spelling authorizes persistence of recognized Cloud edge IPs.
  const retainRciEdgeIps = env['KEENETIC_TELEMETRY_RCI_EDGE_IPS'] === 'true';

  const configured = env['KEENETIC_TELEMETRY_PATH'];
  if (configured !== undefined) {
    if (!absolute(platform, configured)) throw new Error('KEENETIC_TELEMETRY_PATH must be absolute.');
    return { enabled: true, path: configured, retainRciEdgeIps };
  }
  return {
    enabled: true,
    path: join(stateDir(platform, env), 'mcp-calls.jsonl'),
    retainRciEdgeIps
  };
}
