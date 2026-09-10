import { describe, expect, it, vi } from 'vitest';
import { probeConfigCapabilities } from '../../src/router/config-capabilities.js';
import { AuthError, RemoteCapabilityError } from '../../src/router/errors.js';
import type { RciProbeMetadata } from '../../src/router/rci.js';

function metadata(overrides: Partial<RciProbeMetadata> = {}): RciProbeMetadata {
  return {
    httpStatus: 200,
    contentTypeClass: 'json',
    shape: 'array',
    items: 3,
    bytes: 48,
    ...overrides
  };
}

describe('configuration capability probes', () => {
  it('reports successful JSON and text-like configuration surfaces independently', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockResolvedValueOnce(metadata({
        contentTypeClass: 'text', shape: 'string', items: 7, bytes: 120
      }));

    const result = await probeConfigCapabilities({ probeGet });

    expect(probeGet.mock.calls.map(call => call[0])).toEqual([
      'show/running-config',
      'more?filename=startup-config'
    ]);
    expect(result.runningConfig).toMatchObject({ available: true, shape: 'array', items: 3 });
    expect(result.startupConfig).toMatchObject({ available: true, shape: 'string', items: 7 });
  });

  it.each([
    [404, 'not-found'],
    [403, 'capability-denied']
  ] as const)('turns HTTP %s into an unavailable capability result', async (httpStatus, reason) => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockResolvedValueOnce(metadata({
        httpStatus, contentTypeClass: 'unknown', shape: 'unknown', items: null, bytes: 0
      }));

    const result = await probeConfigCapabilities({ probeGet });

    expect(result.startupConfig).toEqual({
      available: false,
      transport: 'rci',
      httpStatus,
      contentTypeClass: 'unknown',
      shape: 'unknown',
      items: null,
      bytes: 0,
      reason
    });
  });

  it('turns a remote proxy denial into a capability result', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockRejectedValueOnce(new RemoteCapabilityError('candidate path denied'));

    const result = await probeConfigCapabilities({ probeGet });

    expect(result.startupConfig).toMatchObject({
      available: false, httpStatus: 403, reason: 'capability-denied'
    });
  });

  it('does not disguise authentication failure as a missing capability', async () => {
    const probeGet = vi.fn().mockRejectedValue(new AuthError('bad credentials'));

    await expect(probeConfigCapabilities({ probeGet })).rejects.toBeInstanceOf(AuthError);
  });

  it('rejects a successful response with an unexpected scalar shape', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata({ shape: 'unknown', items: null, bytes: 4 }))
      .mockResolvedValueOnce(metadata());

    const result = await probeConfigCapabilities({ probeGet });

    expect(result.runningConfig).toMatchObject({
      available: false, httpStatus: 200, reason: 'unexpected-shape'
    });
  });
});
