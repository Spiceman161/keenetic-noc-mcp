import type { KeeneticClient } from './client.js';
import type { CapabilityAccess, CapabilityReason } from './config-capabilities.js';
import { RciError, ValidationError } from './errors.js';
import { STARTUP_CONFIG } from './config-state.js';

export const CONFIG_INPUT_BYTES = 256_000;

export type ConfigSource = 'running' | 'startup';
export type ConfigMethod = 'rci-show' | 'rci-more' | 'ci-file' | 'rci-branch' | 'rci-root';
export type StructuredSection = 'system' | 'users' | 'dns' | 'routing' | 'interfaces' | 'all';

export interface ConfigUnavailable {
  available: false;
  state: 'unknown' | 'unavailable';
  method: null;
  reason: CapabilityReason;
}

export interface CliConfigRead {
  available: true;
  method: 'rci-show' | 'rci-more' | 'ci-file';
  lines: string[];
}

export interface StructuredConfigRead {
  available: true;
  method: 'rci-branch' | 'rci-root';
  data: unknown;
  omittedBranches: Array<{ path: string; reason: 'not-found' }>;
}

function unavailable(access: CapabilityAccess<string>): ConfigUnavailable {
  if (access.state === 'unknown') {
    throw new RciError('configuration capability could not be established', {
      path: 'configuration', code: access.reason ?? 'unknown', ident: 'capability'
    });
  }
  return { available: false, state: access.state === 'available' ? 'unknown' : access.state,
    method: null, reason: access.reason };
}

function splitLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

function unwrapLines(value: unknown): string[] {
  let current = value;
  let depth = 0;
  while (typeof current === 'object' && current !== null && !Array.isArray(current)) {
    const values = Object.values(current as Record<string, unknown>);
    if (values.length !== 1 || depth >= 16) {
      throw new RciError('the configuration response has an unexpected wrapper shape', {
        path: 'configuration', code: 'unexpected-response', ident: 'rci'
      });
    }
    current = values[0];
    depth += 1;
  }
  if (typeof current === 'string') return splitLines(current);
  if (Array.isArray(current) && current.length > 0 && current.every(line => typeof line === 'string')) {
    return current.flatMap(line => splitLines(line as string));
  }
  throw new RciError('the configuration response is not a string or an array of strings', {
    path: 'configuration', code: 'unexpected-response', ident: 'rci'
  });
}

export async function readCliConfig(
  client: KeeneticClient,
  source: ConfigSource
): Promise<CliConfigRead | ConfigUnavailable> {
  const measured = await client.probedCapabilities();
  const access = source === 'running' ? measured.config.runningCli : measured.config.startup;
  if (access.state !== 'available' || access.method === null) return unavailable(access);

  if (source === 'running') {
    const result = await client.rci.getConfig('show/running-config', CONFIG_INPUT_BYTES);
    return { available: true, method: 'rci-show', lines: unwrapLines(result.value) };
  }
  if (access.method === 'rci-more') {
    const result = await client.rci.getConfig('more?filename=startup-config', CONFIG_INPUT_BYTES);
    return { available: true, method: 'rci-more', lines: unwrapLines(result.value) };
  }
  const text = await client.rci.getText(STARTUP_CONFIG, CONFIG_INPUT_BYTES);
  return { available: true, method: 'ci-file', lines: splitLines(text) };
}

const STRUCTURED_PATHS: Record<Exclude<StructuredSection, 'all'>, string[]> = {
  system: ['system'],
  users: ['user'],
  dns: ['dns-proxy', 'ip/name-server'],
  routing: ['ip/policy', 'ip/static'],
  interfaces: ['interface']
};

export async function readStructuredRunningConfig(
  client: KeeneticClient,
  section: StructuredSection
): Promise<StructuredConfigRead> {
  const paths = section === 'all' ? [''] : STRUCTURED_PATHS[section];
  const data: Record<string, unknown> = {};
  const omittedBranches: Array<{ path: string; reason: 'not-found' }> = [];
  let remaining = CONFIG_INPUT_BYTES;

  for (const [index, path] of paths.entries()) {
    try {
      // A failed optional branch can still consume its entire response limit.
      // Divide the remaining aggregate allowance between outstanding reads.
      const requestLimit = Math.floor(remaining / (paths.length - index));
      remaining -= requestLimit;
      const result = await client.rci.getConfig(path, requestLimit);
      const structured = typeof result.value === 'object' && result.value !== null &&
        !Array.isArray(result.value);
      if (!structured) {
        throw new RciError('the structured configuration response has an unexpected shape', {
          path: path === '' ? '/' : path, code: 'unexpected-response', ident: 'rci'
        });
      }
      if (section === 'all') {
        client.markRunningStructured?.('rci-root');
        return { available: true, method: 'rci-root', data: result.value, omittedBranches };
      }
      data[path] = result.value;
    } catch (error) {
      if (error instanceof RciError && error.code === '404' && paths.length > 1) {
        omittedBranches.push({ path, reason: 'not-found' });
        continue;
      }
      throw error;
    }
  }
  if (Object.keys(data).length === 0) {
    throw new RciError('no supported configuration branch was available', {
      path: section, code: '404', ident: 'rci'
    });
  }
  client.markRunningStructured?.('rci-branch');
  return { available: true, method: 'rci-branch', data, omittedBranches };
}

export function assertStructuredSection(section: string): asserts section is StructuredSection {
  if (section === 'wifi' || section === 'vpn') {
    throw new ValidationError(`Structured format is unavailable for section "${section}"; use format=cli.`);
  }
}
