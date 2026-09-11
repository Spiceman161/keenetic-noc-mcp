import type { KeeneticClient } from './client.js';

export const DNS_CONFIG_INPUT_BYTES = 256_000;

export interface DnsConfigBranchRead {
  path: 'dns-proxy' | 'ip/name-server';
  value: unknown;
}

export async function readDnsConfigBranch(
  client: KeeneticClient,
  path: DnsConfigBranchRead['path']
): Promise<DnsConfigBranchRead> {
  const result = await client.rci.getConfig(path, DNS_CONFIG_INPUT_BYTES / 2);
  return { path, value: result.value };
}

/**
 * DNS configuration is split across two independent RCI branches. Read both
 * under one aggregate ceiling so an unavailable optional branch cannot hide
 * useful evidence from its sibling.
 */
