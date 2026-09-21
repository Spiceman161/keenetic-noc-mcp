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
      path: '/tmp/keenetic-state-test/mcp-calls.jsonl',
      retainRciEdgeIps: false
    });
  });

  it('accepts only absolute custom paths and strict booleans', () => {
    expect(loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_PATH: '/tmp/keenetic-calls-test.jsonl'
    })).toEqual({
      enabled: true,
      path: '/tmp/keenetic-calls-test.jsonl',
      retainRciEdgeIps: false
    });
    expect(() => loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'yes'
    })).toThrow(/must be "true" or "false"/);
    expect(() => loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_PATH: 'relative.jsonl'
    })).toThrow(/must be absolute/);
  });

  it('retains Cloud edge IPs only for the exact opt-in spelling', () => {
    expect(loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_RCI_EDGE_IPS: 'true',
      KEENETIC_STATE_DIR: '/tmp/keenetic-state-test'
    })).toMatchObject({ enabled: true, retainRciEdgeIps: true });
    expect(loadTelemetryConfig('linux', {
      KEENETIC_TELEMETRY_ENABLED: 'true',
      KEENETIC_TELEMETRY_RCI_EDGE_IPS: 'TRUE',
      KEENETIC_STATE_DIR: '/tmp/keenetic-state-test'
    })).toMatchObject({ enabled: true, retainRciEdgeIps: false });
  });
});
