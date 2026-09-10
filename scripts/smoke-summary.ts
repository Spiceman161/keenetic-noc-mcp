import type { LogEntry } from '../src/tools/logs.js';
import type { ConfigCapabilities, ConfigCapabilityProbe } from '../src/router/config-capabilities.js';

interface FilterOutcome {
  available: boolean;
  matched: number | null;
}

function outcome(value: FilterOutcome, reason: string): Record<string, unknown> {
  return value.available
    ? { status: 'passed', matched: value.matched ?? 0 }
    : { status: 'skipped', reason };
}

/** Converts live log results into a summary that cannot contain router values. */
export function createLogSmokeSummary(
  entries: readonly LogEntry[],
  filters: { interface: FilterOutcome; timeRange: FilterOutcome; deviceAlias: FilterOutcome }
): Record<string, unknown> {
  const timestampKinds = { iso: 0, epoch: 0, other: 0, missing: 0 };
  for (const entry of entries) {
    if (entry.timestamp === null) timestampKinds.missing += 1;
    else if (/^\d{4}-\d{2}-\d{2}(?:T| )/.test(entry.timestamp)) timestampKinds.iso += 1;
    else if (/^\d{10}(?:\d{3})?$/.test(entry.timestamp)) timestampKinds.epoch += 1;
    else timestampKinds.other += 1;
  }
  return {
    dispatcher: 'passed', total: entries.length,
    fields: ['timestamp', 'ident', 'level', 'label', 'line'],
    timestampShape: entries.length === 0 ? { status: 'skipped', reason: 'no-log-rows', counts: timestampKinds } : {
      status: 'passed', counts: timestampKinds
    },
    interfaceFilter: outcome(filters.interface, 'no-candidate'),
    timeRange: outcome(filters.timeRange, 'no-candidate'),
    deviceAlias: outcome(filters.deviceAlias, 'no-candidate')
  };
}

function safeConfigProbe(probe: ConfigCapabilityProbe): ConfigCapabilityProbe {
  return {
    available: probe.available,
    transport: probe.transport,
    httpStatus: probe.httpStatus,
    contentTypeClass: probe.contentTypeClass,
    shape: probe.shape,
    items: probe.items,
    bytes: probe.bytes,
    payloadShape: probe.payloadShape,
    payloadItems: probe.payloadItems,
    payloadItemShape: probe.payloadItemShape,
    wrapperDepth: probe.wrapperDepth,
    reason: probe.reason
  };
}

/** Whitelists anonymous config probe fields at the live-output boundary. */
export function createConfigSmokeSummary(capabilities: ConfigCapabilities): ConfigCapabilities {
  return {
    runningConfig: safeConfigProbe(capabilities.runningConfig),
    startupConfig: safeConfigProbe(capabilities.startupConfig)
  };
}
