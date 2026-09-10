import { describe, expect, it, vi } from 'vitest';
import type { KeeneticClient } from '../../src/router/client.js';
import { readCliConfig, readStructuredRunningConfig } from '../../src/router/config-reader.js';
import { RciError, TransportError } from '../../src/router/errors.js';

function client(options: {
  startup?: { state: 'available' | 'unavailable' | 'unknown'; method: 'rci-more' | 'ci-file' | null;
    reason: 'not-found' | 'not-probed' | null };
  value?: unknown;
} = {}) {
  const getConfig = vi.fn(async (_path: string, _limit: number) => ({
    value: Object.hasOwn(options, 'value') ? options.value :
      { outer: { inner: ['system\r\n', '    hostname test'] } },
    bytes: 100
  }));
  const getText = vi.fn(async () => 'system\r\n    hostname test\r\n');
  const markRunningStructured = vi.fn();
  const result = {
    rci: { getConfig, getText },
    capabilities: vi.fn(),
    probedCapabilities: vi.fn(async () => ({ config: {
      runningCli: { state: 'available', method: 'rci-show', reason: null },
      runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
      startup: options.startup ?? { state: 'available', method: 'rci-more', reason: null },
      backup: { state: 'available', method: 'ci-file', reason: null }
    } })),
    markRunningStructured
  } as unknown as KeeneticClient;
  return { result, getConfig, getText, markRunningStructured };
}

describe('configuration reader', () => {
  it('unwraps nested RCI CLI payloads and normalizes CRLF', async () => {
    const fixture = client();
    await expect(readCliConfig(fixture.result, 'running')).resolves.toEqual({
      available: true,
      method: 'rci-show',
      lines: ['system', '    hostname test']
    });
    expect(fixture.getConfig).toHaveBeenCalledWith('show/running-config', 256_000);
  });

  it('selects the measured LAN startup file without trying RCI', async () => {
    const fixture = client({ startup: { state: 'available', method: 'ci-file', reason: null } });
    const read = await readCliConfig(fixture.result, 'startup');
    expect(read).toMatchObject({ available: true, method: 'ci-file' });
    expect(fixture.getText).toHaveBeenCalledWith('/ci/startup-config.txt', 256_000);
    expect(fixture.getConfig).not.toHaveBeenCalled();
  });

  it('returns unavailable metadata without reading another source', async () => {
    const fixture = client({ startup: { state: 'unavailable', method: null, reason: 'not-found' } });
    await expect(readCliConfig(fixture.result, 'startup')).resolves.toEqual({
      available: false, state: 'unavailable', method: null, reason: 'not-found'
    });
    expect(fixture.getConfig).not.toHaveBeenCalled();
    expect(fixture.getText).not.toHaveBeenCalled();
  });

  it.each(['unexpected-response', 'rci-error', 'http-error'] as const)(
    'keeps unknown capability reason %s as an error',
    async reason => {
      const fixture = client({ startup: { state: 'unknown', method: null,
        reason: reason as 'not-probed' } });
      await expect(readCliConfig(fixture.result, 'startup')).rejects.toMatchObject({ code: reason });
      expect(fixture.getConfig).not.toHaveBeenCalled();
      expect(fixture.getText).not.toHaveBeenCalled();
    }
  );

  it.each([[], ['system', 3], { a: ['system'], b: ['user'] }])(
    'rejects unsafe CLI payload shape %# without echoing it',
    async value => {
      const fixture = client({ value });
      await expect(readCliConfig(fixture.result, 'running')).rejects.toMatchObject({
        code: 'unexpected-response'
      });
    }
  );

  it('rejects wrappers deeper than the bounded singleton shape', async () => {
    let value: unknown = ['system'];
    for (let depth = 0; depth < 17; depth += 1) value = { nested: value };
    const fixture = client({ value });
    await expect(readCliConfig(fixture.result, 'running')).rejects.toMatchObject({
      code: 'unexpected-response'
    });
  });

  it('reads structured branches within one cumulative input budget', async () => {
    const fixture = client({ value: { configured: true } });
    const read = await readStructuredRunningConfig(fixture.result, 'dns');
    expect(read.method).toBe('rci-branch');
    expect(fixture.getConfig.mock.calls).toEqual([
      ['dns-proxy', 128_000],
      ['ip/name-server', 128_000]
    ]);
    expect(fixture.markRunningStructured).toHaveBeenCalledWith('rci-branch');
  });

  it('uses root only for explicit structured all', async () => {
    const fixture = client({ value: { system: {} } });
    const read = await readStructuredRunningConfig(fixture.result, 'all');
    expect(read.method).toBe('rci-root');
    expect(fixture.getConfig).toHaveBeenCalledWith('', 256_000);
    expect(fixture.markRunningStructured).toHaveBeenCalledWith('rci-root');
  });

  it('reports a missing optional branch without hiding available structured data', async () => {
    const fixture = client({ value: { configured: true } });
    fixture.getConfig
      .mockResolvedValueOnce({ value: { configured: true }, bytes: 100 })
      .mockRejectedValueOnce(new RciError('missing', { path: 'ip/name-server',
        code: '404', ident: 'http' }));
    const read = await readStructuredRunningConfig(fixture.result, 'dns');
    expect(read.omittedBranches).toEqual([{ path: 'ip/name-server', reason: 'not-found' }]);
    expect(read.data).toEqual({ 'dns-proxy': { configured: true } });
  });

  it('reserves failed branch bytes inside the aggregate input ceiling', async () => {
    const fixture = client({ value: { configured: true } });
    fixture.getConfig
      .mockRejectedValueOnce(new RciError('missing', { path: 'dns-proxy',
        code: '404', ident: 'http' }))
      .mockResolvedValueOnce({ value: { configured: true }, bytes: 100 });
    const read = await readStructuredRunningConfig(fixture.result, 'dns');
    expect(read.omittedBranches).toEqual([{ path: 'dns-proxy', reason: 'not-found' }]);
    expect(fixture.getConfig.mock.calls).toEqual([
      ['dns-proxy', 128_000],
      ['ip/name-server', 128_000]
    ]);
  });

  it('propagates transport failures without changing capability state', async () => {
    const fixture = client();
    fixture.getConfig.mockRejectedValueOnce(new TransportError('offline'));
    await expect(readStructuredRunningConfig(fixture.result, 'system')).rejects.toBeInstanceOf(TransportError);
    expect(fixture.markRunningStructured).not.toHaveBeenCalled();
  });

  it.each([[], ['unexpected'], 'unexpected', null])(
    'rejects non-record structured branch shape %#',
    async value => {
      const fixture = client({ value });
      await expect(readStructuredRunningConfig(fixture.result, 'system')).rejects.toMatchObject({
        code: 'unexpected-response'
      });
      expect(fixture.markRunningStructured).not.toHaveBeenCalled();
    }
  );
});
