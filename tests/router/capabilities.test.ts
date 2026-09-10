import { describe, expect, it, vi } from 'vitest';
import { parseCapabilities } from '../../src/router/capabilities.js';
import { loadConfig } from '../../src/config/load.js';
import { createClient, createRemoteClient } from '../../src/router/client.js';
import { AuthError, TransportError } from '../../src/router/errors.js';

const VERSION = {
  title: '5.1.3',
  model: 'Keenetic Model (KN-0000)',
  hw_id: 'KN-0000',
  ndw: {
    features: 'wifi5ghz,hwnat,wpa3',
    components: 'base,dhcpd,wireguard,dns-tls'
  }
};

describe('parseCapabilities', () => {
  it('splits the comma-separated component and feature strings', () => {
    const caps = parseCapabilities(VERSION);
    expect(caps.components.has('wireguard')).toBe(true);
    expect(caps.components.has('torrent')).toBe(false);
    expect(caps.features.has('hwnat')).toBe(true);
    expect(caps.model).toBe('Keenetic Model (KN-0000)');
    expect(caps.hwId).toBe('KN-0000');
    expect(caps.firmware).toBe('5.1.3');
  });

  it('tolerates a router that omits the ndw block', () => {
    const caps = parseCapabilities({ title: '2.16', model: 'Old' });
    expect(caps.components.size).toBe(0);
    expect(caps.features.size).toBe(0);
    expect(caps.firmware).toBe('2.16');
  });
});

describe('client capability caching', () => {
  it('fetches the version once no matter how often capabilities are asked for', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    const spy = vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);

    const a = await client.capabilities();
    const b = await client.capabilities();

    expect(spy).toHaveBeenCalledTimes(1);
    expect(a).toBe(b);
  });

  it('retries after a transient capability failure instead of caching rejection', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    const spy = vi.spyOn(client.rci, 'get')
      .mockRejectedValueOnce(new Error('temporary'))
      .mockResolvedValueOnce(VERSION);
    await expect(client.capabilities()).rejects.toThrow('temporary');
    await expect(client.capabilities()).resolves.toMatchObject({ firmware: '5.1.3' });
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('shares and retains a successful operational capability probe', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);
    const probeGet = vi.spyOn(client.rci, 'probeGet').mockResolvedValue({
      httpStatus: 200, contentTypeClass: 'json', shape: 'array', items: 2, bytes: 20,
      payloadShape: 'array', payloadItems: 2, payloadItemShape: 'string', wrapperDepth: 0
    });
    const probeFile = vi.spyOn(client.rci, 'probeStartupFile').mockResolvedValue({
      httpStatus: 200, contentTypeClass: 'text', shape: 'string', items: 2, bytes: 20,
      payloadShape: 'string', payloadItems: 2, payloadItemShape: 'unknown', wrapperDepth: 0
    });

    const [first, second] = await Promise.all([
      client.probedCapabilities(), client.probedCapabilities()
    ]);
    expect(first).toBe(second);
    await expect(client.probedCapabilities()).resolves.toBe(first);
    expect(probeGet).toHaveBeenCalledTimes(2);
    expect(probeFile).toHaveBeenCalledTimes(1);
  });

  it('records a successful structured read without retaining its content', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);
    vi.spyOn(client.rci, 'probeGet').mockResolvedValue({
      httpStatus: 200, contentTypeClass: 'json', shape: 'array', items: 1, bytes: 10,
      payloadShape: 'array', payloadItems: 1, payloadItemShape: 'string', wrapperDepth: 0
    });
    vi.spyOn(client.rci, 'probeStartupFile').mockResolvedValue({
      httpStatus: 200, contentTypeClass: 'text', shape: 'string', items: 1, bytes: 10,
      payloadShape: 'string', payloadItems: 1, payloadItemShape: 'unknown', wrapperDepth: 0
    });
    const before = await client.probedCapabilities();
    expect(before.config.runningStructured.reason).toBe('not-probed');
    client.markRunningStructured?.('rci-branch');
    const after = await client.probedCapabilities();
    expect(after.config.runningStructured).toEqual({
      state: 'available', method: 'rci-branch', reason: null
    });
    expect(JSON.stringify(after)).not.toContain('password');
  });

  it('retries operational probes after an unexpected response', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);
    const expected = {
      httpStatus: 200, contentTypeClass: 'json' as const, shape: 'array' as const, items: 1,
      bytes: 10, payloadShape: 'array' as const, payloadItems: 1,
      payloadItemShape: 'string' as const, wrapperDepth: 0
    };
    const unexpected = { ...expected, shape: 'unknown' as const, items: null,
      payloadShape: 'unknown' as const, payloadItems: null, payloadItemShape: 'unknown' as const };
    const probeGet = vi.spyOn(client.rci, 'probeGet')
      .mockResolvedValueOnce(unexpected)
      .mockResolvedValue(expected);
    vi.spyOn(client.rci, 'probeStartupFile').mockResolvedValue(expected);

    expect((await client.probedCapabilities()).config.runningCli.state).toBe('unknown');
    expect((await client.probedCapabilities()).config.runningCli.state).toBe('available');
    expect(probeGet).toHaveBeenCalledTimes(4);
  });

  it('retries the preferred RCI startup path after a recoverable LAN fallback', async () => {
    const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
    vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);
    const expected = {
      httpStatus: 200, contentTypeClass: 'json' as const, shape: 'array' as const, items: 1,
      bytes: 10, payloadShape: 'array' as const, payloadItems: 1,
      payloadItemShape: 'string' as const, wrapperDepth: 0
    };
    const unexpected = { ...expected, shape: 'object' as const, payloadShape: 'object' as const,
      payloadItemShape: 'object' as const };
    vi.spyOn(client.rci, 'probeGet')
      .mockResolvedValueOnce(expected)
      .mockResolvedValueOnce(unexpected)
      .mockResolvedValue(expected);
    vi.spyOn(client.rci, 'probeStartupFile').mockResolvedValue({
      ...expected, contentTypeClass: 'text', shape: 'string', payloadShape: 'string',
      payloadItemShape: 'unknown'
    });

    expect((await client.probedCapabilities()).config.startup.method).toBe('ci-file');
    expect((await client.probedCapabilities()).config.startup.method).toBe('rci-more');
  });

  it.each([new AuthError('rejected'), new TransportError('offline')])(
    'does not cache an operational %s rejection',
    async error => {
      const client = createClient({ host: '192.0.2.1', login: 'admin', password: 'x' });
      vi.spyOn(client.rci, 'get').mockResolvedValue(VERSION);
      const expected = {
        httpStatus: 200, contentTypeClass: 'json' as const, shape: 'array' as const, items: 1,
        bytes: 10, payloadShape: 'array' as const, payloadItems: 1,
        payloadItemShape: 'string' as const, wrapperDepth: 0
      };
      const probeGet = vi.spyOn(client.rci, 'probeGet')
        .mockRejectedValueOnce(error)
        .mockResolvedValue(expected);
      vi.spyOn(client.rci, 'probeStartupFile').mockResolvedValue({
        ...expected, shape: 'string', payloadShape: 'string', payloadItemShape: 'unknown'
      });
      await expect(client.probedCapabilities()).rejects.toBe(error);
      await expect(client.probedCapabilities()).resolves.toBeDefined();
      expect(probeGet).toHaveBeenCalledTimes(3);
    }
  );

  it('uses the same cache model remotely, proves RCI first, and never probes CI', async () => {
    const client = createRemoteClient({ endpoint: 'https://rci.example.test/rci/', login: 'agent',
      password: 'x', routerId: 'test' });
    const order: string[] = [];
    vi.spyOn(client.rci, 'get').mockImplementation(async () => { order.push('version'); return VERSION; });
    const probeGet = vi.spyOn(client.rci, 'probeGet').mockImplementation(async path => {
      order.push(path);
      return {
        httpStatus: path.startsWith('more?') ? 403 : 200,
        contentTypeClass: 'json', shape: path.startsWith('more?') ? 'unknown' : 'array',
        items: path.startsWith('more?') ? null : 1, bytes: 10,
        payloadShape: path.startsWith('more?') ? 'unknown' : 'array',
        payloadItems: path.startsWith('more?') ? null : 1,
        payloadItemShape: path.startsWith('more?') ? 'unknown' : 'string', wrapperDepth: 0
      };
    });
    const probeFile = vi.spyOn(client.rci, 'probeStartupFile');

    const result = await client.probedCapabilities();
    expect(order).toEqual(['version', 'show/running-config', 'more?filename=startup-config']);
    expect(result.config.startup.reason).toBe('denied');
    expect(probeGet).toHaveBeenCalledTimes(2);
    expect(probeFile).not.toHaveBeenCalled();
  });
});

describe('loadConfig', () => {
  it('reads host, login and password from the environment', async () => {
    const cfg = await loadConfig([], {
      KEENETIC_HOST: '192.0.2.1',
      KEENETIC_USER: 'root',
      KEENETIC_PASSWORD: 'secret'
    } as NodeJS.ProcessEnv);
    expect(cfg).toMatchObject({ host: '192.0.2.1', login: 'root', password: 'secret' });
  });

  it('defaults the login to admin and read-only to false', async () => {
    const cfg = await loadConfig([], {
      KEENETIC_HOST: '192.0.2.1',
      KEENETIC_PASSWORD: 'secret'
    } as NodeJS.ProcessEnv);
    expect(cfg.login).toBe('admin');
    expect(cfg.readOnly).toBe(false);
    expect(cfg.maxResponseBytes).toBe(25_000);
  });

  it('honours --read-only and --max-response-bytes', async () => {
    const cfg = await loadConfig(['--read-only', '--max-response-bytes', '4096'], {
      KEENETIC_HOST: '192.0.2.1',
      KEENETIC_PASSWORD: 'secret'
    } as NodeJS.ProcessEnv);
    expect(cfg.readOnly).toBe(true);
    expect(cfg.maxResponseBytes).toBe(4096);
  });

  it('points at the wizard when the password is absent', async () => {
    await expect(
      loadConfig([], { KEENETIC_HOST: '192.0.2.1' } as NodeJS.ProcessEnv)
    ).rejects.toThrow(/keenetic-noc-mcp router add/);
  });
});
