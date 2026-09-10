import { describe, expect, it, vi } from 'vitest';
import {
  probeConfigCapabilities,
  probeOperationalCapabilities
} from '../../src/router/config-capabilities.js';
import { AuthError, RemoteCapabilityError, TransportError } from '../../src/router/errors.js';
import type { RciProbeMetadata } from '../../src/router/rci.js';

function metadata(overrides: Partial<RciProbeMetadata> = {}): RciProbeMetadata {
  return {
    httpStatus: 200,
    contentTypeClass: 'json',
    shape: 'array',
    items: 3,
    bytes: 48,
    payloadShape: 'array',
    payloadItems: 3,
    payloadItemShape: 'string',
    wrapperDepth: 0,
    ...overrides
  };
}

describe('configuration capability probes', () => {
  it('reports successful JSON and text-like configuration surfaces independently', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockResolvedValueOnce(metadata({
        contentTypeClass: 'text', shape: 'string', items: 7, bytes: 120,
        payloadShape: 'string', payloadItems: 7, payloadItemShape: 'unknown'
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
        httpStatus, contentTypeClass: 'unknown', shape: 'unknown', items: null, bytes: 0,
        payloadShape: 'unknown', payloadItems: null, payloadItemShape: 'unknown'
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
      payloadShape: 'unknown',
      payloadItems: null,
      payloadItemShape: 'unknown',
      wrapperDepth: 0,
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
      .mockResolvedValueOnce(metadata({
        shape: 'unknown', items: null, bytes: 4, payloadShape: 'unknown', payloadItems: null,
        payloadItemShape: 'unknown'
      }))
      .mockResolvedValueOnce(metadata());

    const result = await probeConfigCapabilities({ probeGet });

    expect(result.runningConfig).toMatchObject({
      available: false, httpStatus: 200, reason: 'unexpected-shape'
    });
  });
});

describe('operational capability model', () => {
  it('reports remote RCI startup independently from the unprobed backup path', async () => {
    const probeStartupFile = vi.fn();
    const result = await probeOperationalCapabilities({
      probeGet: vi.fn(async () => metadata()),
      probeStartupFile
    }, 'remote');

    expect(result.config).toEqual({
      runningCli: { state: 'available', method: 'rci-show', reason: null },
      runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
      startup: { state: 'available', method: 'rci-more', reason: null },
      backup: { state: 'unknown', method: null, reason: 'not-probed' }
    });
    expect(probeStartupFile).not.toHaveBeenCalled();
  });

  it('falls back to the LAN startup file and measures it separately for backup', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockResolvedValueOnce(metadata({ httpStatus: 404, shape: 'unknown', items: null,
        payloadShape: 'unknown', payloadItems: null, payloadItemShape: 'unknown' }));
    const result = await probeOperationalCapabilities({
      probeGet,
      probeStartupFile: vi.fn(async () => metadata({ contentTypeClass: 'text', shape: 'string',
        payloadShape: 'string', payloadItemShape: 'unknown' }))
    }, 'lan');

    expect(result.config.startup).toEqual({ state: 'available', method: 'ci-file', reason: null });
    expect(result.config.backup).toEqual({ state: 'available', method: 'ci-file', reason: null });
  });

  it('keeps unexpected successful responses unknown', async () => {
    const unexpected = metadata({ shape: 'unknown', items: null, payloadShape: 'unknown',
      payloadItems: null, payloadItemShape: 'unknown' });
    const result = await probeOperationalCapabilities({
      probeGet: vi.fn(async () => unexpected),
      probeStartupFile: vi.fn(async () => unexpected)
    }, 'lan');
    expect(result.config.runningCli).toEqual({
      state: 'unknown', method: null, reason: 'unexpected-response'
    });
    expect(result.config.startup.state).toBe('unknown');
  });

  it('rejects nonempty object payloads that are not CLI configuration', async () => {
    const object = metadata({ shape: 'object', payloadShape: 'object',
      payloadItemShape: 'object' });
    const result = await probeOperationalCapabilities({
      probeGet: vi.fn(async () => object),
      probeStartupFile: vi.fn(async () => object)
    }, 'lan');
    expect(result.config.runningCli.reason).toBe('unexpected-response');
    expect(result.config.startup.reason).toBe('unexpected-response');
    expect(result.config.backup.reason).toBe('unexpected-response');
  });

  it('does not mistake a text or HTML response from an RCI path for configuration', async () => {
    const textResponse = metadata({ contentTypeClass: 'text', shape: 'string', items: 1,
      payloadShape: 'string', payloadItems: 1, payloadItemShape: 'unknown' });
    const result = await probeOperationalCapabilities({
      probeGet: vi.fn(async () => textResponse),
      probeStartupFile: vi.fn()
    }, 'remote');
    expect(result.config.runningCli.reason).toBe('unexpected-response');
    expect(result.config.startup.reason).toBe('unexpected-response');
  });

  it('preserves denial when the other LAN startup path is merely missing', async () => {
    const probeGet = vi.fn()
      .mockResolvedValueOnce(metadata())
      .mockResolvedValueOnce(metadata({ httpStatus: 403, shape: 'unknown', items: null,
        payloadShape: 'unknown', payloadItems: null, payloadItemShape: 'unknown' }));
    const result = await probeOperationalCapabilities({
      probeGet,
      probeStartupFile: vi.fn(async () => metadata({ httpStatus: 404, shape: 'unknown',
        items: null, payloadShape: 'unknown', payloadItems: null,
        payloadItemShape: 'unknown' }))
    }, 'lan');
    expect(result.config.startup).toEqual({ state: 'unavailable', method: null, reason: 'denied' });
  });

  it.each([new AuthError('rejected'), new TransportError('offline')])(
    'propagates %s rather than describing it as unsupported',
    async error => {
      await expect(probeOperationalCapabilities({
        probeGet: vi.fn(async () => { throw error; }),
        probeStartupFile: vi.fn()
      }, 'remote')).rejects.toBe(error);
    }
  );
});
