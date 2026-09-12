import { describe, expect, it } from 'vitest';
import { loadTelemetryConfig } from '../../src/telemetry/config.js';

describe('telemetry configuration', () => {
  it('is disabled by default and accepts explicit false', () => {
    expect(loadTelemetryConfig('linux', {})).toEqual({ enabled: false });
    expect(loadTelemetryConfig('linux', { KEENETIC_TELEMETRY_ENABLED: 'FALSE' }))
      .toEqual({ enabled: false });
  });

  it('uses the existing state root when enabled', () => {
    expect(loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_STATE_DIR: '/tmp/keenetic-state-test'
    })).toEqual({
      enabled: true,
      path: '/tmp/keenetic-state-test/mcp-calls.jsonl'
    });
  });

  it('accepts only absolute custom paths and strict booleans', () => {
    expect(loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_PATH: '/tmp/keenetic-calls-test.jsonl'
    })).toEqual({
      enabled: true,
      path: '/tmp/keenetic-calls-test.jsonl'
    });
    expect(() => loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'yes'
    })).toThrow(/must be "true" or "false"/);
    expect(() => loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_PATH: 'relative.jsonl'
    })).toThrow(/must be absolute/);
  });
});
