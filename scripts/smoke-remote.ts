import { createRemoteClient } from '../src/router/client.js';
import { normalizeRemoteUrl } from '../src/config/load.js';
import { probeConfigCapabilities } from '../src/router/config-capabilities.js';
import { AuthError, TransportError } from '../src/router/errors.js';
import { filterLogEntries, resolveDeviceAliases, unwrapLogEntries } from '../src/tools/logs.js';
import { loadRemoteSmokeCredentials } from './smoke-credentials.js';
import { createConfigSmokeSummary, createDnsShapeSummary, createLogSmokeSummary } from './smoke-summary.js';

async function main(): Promise<void> {
  const credentials = await loadRemoteSmokeCredentials(process.argv.slice(2), process.env);
  const client = createRemoteClient({ endpoint: normalizeRemoteUrl(credentials.endpoint), login: credentials.login,
    password: credentials.password, routerId: credentials.routerId, timeoutMs: 30_000 });
  const summary: Record<string, unknown> = { source: credentials.source, reads: {}, logs: {} };
  const reads = summary['reads'] as Record<string, string>;
  const capabilities = await client.capabilities();
  reads['show/version'] = 'passed';
  summary['router'] = { model: capabilities.model, firmware: capabilities.firmware };
  let dnsRuntime: unknown;
  for (const path of ['show/system', 'show/interface', 'show/internet/status', 'show/ip/route', 'show/dns-proxy']) {
    const value = await client.rci.get(path, path === 'show/dns-proxy' ? 128_000 : 256_000);
    if (path === 'show/dns-proxy') dnsRuntime = value;
    reads[path] = 'passed';
  }
  const dnsConfigShape = async (path: string): Promise<Record<string, unknown>> => {
    try {
      return createDnsShapeSummary((await client.rci.getConfig(path, 128_000)).value);
    } catch (error) {
      if (error instanceof AuthError || error instanceof TransportError) throw error;
      const code = typeof error === 'object' && error !== null && 'code' in error &&
        typeof error.code === 'string' ? error.code : null;
      return { status: 'unavailable', errorClass: error instanceof Error ? error.name : 'UnknownError', code };
    }
  };
  summary['dnsEvidence'] = {
    runtime: createDnsShapeSummary(dnsRuntime),
    dnsProxyConfig: await dnsConfigShape('dns-proxy'),
    nameServerConfig: await dnsConfigShape('ip/name-server')
  };

  function records(value: unknown): Array<Record<string, unknown>> {
    if (Array.isArray(value)) return value.flatMap(records);
    if (!value || typeof value !== 'object') return [];
    const item = value as Record<string, unknown>;
    return [item, ...Object.values(item).flatMap(records)];
  }
  function scalar(record: Record<string, unknown>, keys: readonly string[]): string | null {
    for (const key of keys) if (typeof record[key] === 'string' && record[key]) return record[key] as string;
    return null;
  }

  const rawLogs = await client.rci.post({ show: { log: {} } });
  const entries = unwrapLogEntries(rawLogs);
  const interfaceRaw = await client.rci.get('show/interface');
  const interfaceName = records(interfaceRaw).map(item => scalar(item, ['name', 'interface', 'id'])).find(Boolean) ?? null;
  const timestamp = entries.find(entry => entry.timestamp !== null)?.timestamp ?? null;
  const hotspotRaw = await client.rci.get('show/ip/hotspot');
  const hotspotRoot = hotspotRaw && typeof hotspotRaw === 'object' ? hotspotRaw as Record<string, unknown> : {};
  const device = records(hotspotRoot['host']).map(item => scalar(item, ['name', 'hostname', 'mac', 'ip'])).find(Boolean) ?? null;
  let deviceMatched: number | null = null;
  if (device !== null) {
    const aliases = await resolveDeviceAliases(client.rci, device);
    deviceMatched = filterLogEntries(entries, { aliases }).length;
  }

  summary['logs'] = createLogSmokeSummary(entries, {
    interface: { available: interfaceName !== null, matched: interfaceName === null ? null : filterLogEntries(entries, { interface: interfaceName }).length },
    timeRange: { available: timestamp !== null, matched: timestamp === null ? null : filterLogEntries(entries, { since: timestamp, until: timestamp }).length },
    deviceAlias: { available: device !== null, matched: deviceMatched }
  });
  const configCapabilities = createConfigSmokeSummary(await probeConfigCapabilities(client.rci));
  summary['runningConfig'] = configCapabilities.runningConfig;
  summary['startupConfig'] = configCapabilities.startupConfig;
  process.stderr.write(`${JSON.stringify(summary)}\n`);
}

void main().catch(error => {
  process.stderr.write(`${JSON.stringify({ status: 'failed', errorClass: error instanceof Error ? error.name : 'UnknownError' })}\n`);
  process.exitCode = 2;
});
