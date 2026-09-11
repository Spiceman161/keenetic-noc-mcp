import { describe, expect, it, vi } from 'vitest';
import { collectRouterSnapshot } from '../../src/router/snapshot-collector.js';
import { AuthError, RciError, RemoteCapabilityError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';

function client(fail?: { path: string; error: Error }): KeeneticClient {
  const get = vi.fn(async (path: string, maxBytes?: number) => {
    if (fail?.path === path) throw fail.error;
    if (path === 'show/system') return { uptime: 10, cpuload: 2, memfree: 1000 };
    if (path === 'show/last-change') return { checksum: 'a'.repeat(32) };
    if (path === 'show/interface') return { Provider0: { role: 'inet', state: 'up' } };
    if (path === 'show/ip/route') return [{ destination: '0.0.0.0/0', interface: 'Provider0' }];
    if (path === 'show/dns-proxy') return { 'proxy-status': { status: 'running' } };
    if (path === 'show/associations') return { station: [{ mac: '02:00:00:00:00:01' }] };
    if (path === 'show/ip/hotspot') return { host: [{ mac: '02:00:00:00:00:01', active: true }] };
    throw new Error(`unexpected ${path} ${maxBytes}`);
  });
  return {
    capabilities: vi.fn(async () => {
      if (fail?.path === 'capabilities') throw fail.error;
      return { model: '', hwId: '', firmware: '5.1.4', components: new Set(), features: new Set() };
    }),
    probedCapabilities: vi.fn(async () => ({ config: {
      runningCli: { state: 'available', method: 'rci-show', reason: null },
      runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
      startup: { state: 'available', method: 'rci-more', reason: null },
      backup: { state: 'unavailable', method: null, reason: 'remote-unsupported' }
    } })),
    rci: { get, getConfig: vi.fn(async () => ({ value: [`! $$$ Md5 checksum: ${'b'.repeat(32)}`],
      bytes: 64 })) }
  } as unknown as KeeneticClient;
}

describe('snapshot collector', () => {
  it('collects bounded sources sequentially and persists no identifiers', async () => {
    const instance = client();
    const result = await collectRouterSnapshot(instance, () => new Date('2026-09-11T10:00:00Z'));
    expect(result.complete).toBe(true);
    expect(result.sources.configuration.data).toMatchObject({
      runningChecksum: 'a'.repeat(32), savedChecksum: 'b'.repeat(32), unsavedChanges: true
    });
    expect(instance.rci.get).toHaveBeenCalledWith('show/system', 64_000);
    expect(instance.rci.get).toHaveBeenCalledWith('show/interface', 256_000);
    expect(JSON.stringify(result)).not.toMatch(/Provider0|02:00/);
  });

  it('keeps a partial snapshot and latches later reads after a session failure', async () => {
    const instance = client({ path: 'show/interface', error: new TransportError('offline') });
    const result = await collectRouterSnapshot(instance, () => new Date());
    expect(result.complete).toBe(false);
    expect(result.sources.interfaces).toMatchObject({ status: 'unavailable', reason: 'transport-error' });
    expect(instance.rci.get).not.toHaveBeenCalledWith('show/ip/route', 256_000);
  });

  it.each([new AuthError('bad'), new TransportError('offline')])(
    'does not create a snapshot when the base capability check fails', async error => {
      await expect(collectRouterSnapshot(client({ path: 'capabilities', error }), () => new Date()))
        .rejects.toBe(error);
    });

  it('records an RCI source failure without latching later reads', async () => {
    const instance = client({ path: 'show/dns-proxy', error: new RciError('missing', {
      path: 'show/dns-proxy', code: '404', ident: 'rci'
    }) });
    const result = await collectRouterSnapshot(instance, () => new Date());
    expect(result.sources.dns.status).toBe('unavailable');
    expect(instance.rci.get).toHaveBeenCalledWith('show/associations', 256_000);
  });

  it('classifies a remote startup denial after probing as not supported', async () => {
    const instance = client();
    vi.mocked(instance.rci.getConfig).mockRejectedValue(new RemoteCapabilityError('denied'));
    const result = await collectRouterSnapshot(instance, () => new Date());
    expect(result.sources.configuration.data).toMatchObject({
      savedState: 'unknown', savedReason: 'not-supported', savedChecksum: null
    });
    expect(instance.rci.get).toHaveBeenCalledWith('show/interface', 256_000);
  });

  it('does not call a malformed running checksum complete', async () => {
    const instance = client();
    vi.mocked(instance.rci.get).mockImplementation(async (path: string) =>
      path === 'show/last-change' ? { checksum: 'malformed' }
        : path === 'show/system' ? { uptime: 10 }
          : path === 'show/interface' ? { Provider0: { role: 'inet', state: 'up' } }
            : path === 'show/ip/route' ? []
              : path === 'show/dns-proxy' ? { 'proxy-status': { status: 'up' } }
                : path === 'show/associations' ? { station: [] }
                  : { host: [] });
    const result = await collectRouterSnapshot(instance, () => new Date());
    expect(result.sources.configuration).toMatchObject({ status: 'unavailable', reason: 'unexpected-response' });
    expect(result.complete).toBe(false);
  });
});
