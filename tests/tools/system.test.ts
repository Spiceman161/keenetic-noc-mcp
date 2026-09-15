import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { parseCapabilities, type Capabilities } from '../../src/router/capabilities.js';
import { registerSystemTools } from '../../src/tools/system.js';
import { fail, getToolResultTelemetry, guard, ok, type ToolContext, type ToolResult } from '../../src/tools/registry.js';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;
interface Captured {
  handlers: Record<string, Handler>;
  configs: Record<string, { annotations?: { readOnlyHint?: boolean }; description?: string }>;
}

const CAPS: Capabilities = {
  model: 'Keenetic Model (KN-0000)',
  hwId: 'KN-0000',
  firmware: '5.1.3',
  components: new Set(['base', 'wireguard']),
  features: new Set(['hwnat'])
};

const PROBED = {
  config: {
    runningCli: { state: 'available' as const, method: 'rci-show' as const, reason: null },
    runningStructured: { state: 'unknown' as const, method: null, reason: 'not-probed' as const },
    startup: { state: 'available' as const, method: 'rci-more' as const, reason: null },
    backup: { state: 'available' as const, method: 'ci-file' as const, reason: null }
  }
};

function contextWith(
  get: (path: string) => Promise<unknown>,
  getText: (path: string) => Promise<string> = async () => '',
  getConfig: (path: string, maxBytes: number) => Promise<unknown> = async () => ({
    value: { result: [await getText('more?filename=startup-config')] }, bytes: 100
  }),
  caps: Capabilities = CAPS
): ToolContext {
  const client = {
    rci: { get, post: vi.fn(), getText: vi.fn(getText), getConfig: vi.fn(getConfig) },
    capabilities: async () => caps,
    probedCapabilities: async () => PROBED
  } as unknown as KeeneticClient;
  return { client, maxResponseBytes: 25_000, readOnly: false, backup: stubBackup() };
}

/** Registers the tools against a real McpServer with registerTool intercepted. */
function capture(ctx: ToolContext): Captured {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, { annotations?: { readOnlyHint?: boolean }; description?: string }> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((
    name: string,
    config: { annotations?: { readOnlyHint?: boolean }; description?: string },
    handler: Handler
  ) => {
    handlers[name] = handler;
    configs[name] = config;
    return {} as never;
  }) as never);

  registerSystemTools(server, ctx);
  return { handlers, configs };
}

function textOf(result: ToolResult): string {
  return result.content.map(part => part.text).join('');
}

describe('result helpers', () => {
  it('ok serialises the payload as JSON text', () => {
    expect(JSON.parse(textOf(ok({ a: 1 })))).toEqual({ a: 1 });
  });

  it('fail marks isError and includes the guidance', () => {
    const result = fail(new AuthError('bad credentials'));
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('keenetic-noc-mcp router test');
  });

  it('fail handles a non-Error value without crashing', () => {
    const result = fail('something odd');
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('something odd');
  });

  it('bounds guarded errors to the configured response ceiling', async () => {
    const handler = guard({ maxResponseBytes: 512 }, async () => {
      throw new Error(`router failure ${'x '.repeat(5_000)}`);
    });
    const result = await handler({}, {} as never);
    expect(Buffer.byteLength(textOf(result), 'utf8')).toBeLessThanOrEqual(512);
    expect(textOf(result)).toContain('truncated');
    expect(getToolResultTelemetry(result)?.outputTruncated).toBe(true);
  });
});

describe('get_system_info', () => {
  const system = async () => ({ hostname: 'router', cpuload: 6, memtotal: 524_288,
    memfree: 300_728, uptime: '94683' });

  it('reports model, firmware and the component list', async () => {
    const { handlers } = capture(
      contextWith(async path => path === 'show/system'
        ? system()
        : Promise.reject(new Error(`unexpected path ${path}`)))
    );

    const payload = JSON.parse(textOf(await handlers['get_system_info']!({})));
    expect(payload.model).toBe('Keenetic Model (KN-0000)');
    expect(payload.firmware).toBe('5.1.3');
    expect(payload.components).toContain('wireguard');
    expect(payload.cpuLoad).toBe(6);
  });

  it('preserves firmware while exposing valid optional metadata peers and sorted arrays', async () => {
    const caps: Capabilities = {
      ...CAPS,
      firmware: '5.1.5',
      release: 'synthetic-release',
      sandbox: 'synthetic-sandbox',
      components: new Set(['wireguard', 'base']),
      features: new Set(['wpa3', 'hwnat'])
    };
    const { handlers } = capture(contextWith(async () => system(), async () => '', undefined, caps));

    const payload = JSON.parse(textOf(await handlers['get_system_info']!({})));
    expect(payload.firmware).toBe('5.1.5');
    expect(typeof payload.firmware).toBe('string');
    expect(payload.release).toBe('synthetic-release');
    expect(payload.sandbox).toBe('synthetic-sandbox');
    expect(payload.components).toEqual(['base', 'wireguard']);
    expect(payload.features).toEqual(['hwnat', 'wpa3']);
  });

  it('omits independently absent optional metadata peers', async () => {
    const withSandbox = capture(contextWith(async () => system(), async () => '', undefined,
      { ...CAPS, sandbox: 'synthetic-sandbox' }));
    const withRelease = capture(contextWith(async () => system(), async () => '', undefined,
      { ...CAPS, release: 'synthetic-release' }));

    const sandboxPayload = JSON.parse(textOf(await withSandbox.handlers['get_system_info']!({})));
    const releasePayload = JSON.parse(textOf(await withRelease.handlers['get_system_info']!({})));
    expect(sandboxPayload).not.toHaveProperty('release');
    expect(sandboxPayload.sandbox).toBe('synthetic-sandbox');
    expect(releasePayload.release).toBe('synthetic-release');
    expect(releasePayload).not.toHaveProperty('sandbox');
  });

  it.each(['release', 'sandbox'] as const)(
    'omits every malformed %s value after capability parsing without failing the tool', async field => {
      for (const value of [null, 42, { value: 'synthetic' }, ['synthetic']]) {
        const raw: Record<string, unknown> = {
          title: '5.1.5', model: 'Keenetic Model (KN-0000)', hw_id: 'KN-0000',
          release: 'synthetic-release', sandbox: 'synthetic-sandbox'
        };
        raw[field] = value;
        const { handlers } = capture(contextWith(async () => system(), async () => '', undefined,
          parseCapabilities(raw)));
        const payload = JSON.parse(textOf(await handlers['get_system_info']!({})));
        expect(payload.firmware).toBe('5.1.5');
        expect(payload).not.toHaveProperty(field);
        expect(payload[field === 'release' ? 'sandbox' : 'release']).toBe(
          field === 'release' ? 'synthetic-sandbox' : 'synthetic-release'
        );
      }
    }
  );

  it.each(['stable', 'main', 'preview', 'dev', 'lts', 'experimental', 'unknown-value'])(
    'keeps adversarial sandbox vocabulary raw at public output: %s', async sandbox => {
      const caps = parseCapabilities({
        title: '5.1.5', model: 'Keenetic Model (KN-0000)', hw_id: 'KN-0000', sandbox
      });
      const { handlers } = capture(contextWith(async () => system(), async () => '', undefined, caps));
      const payload = JSON.parse(textOf(await handlers['get_system_info']!({})));

      expect(payload).toMatchObject({ firmware: '5.1.5', sandbox });
      expect(payload).not.toHaveProperty('channel');
      expect(payload).not.toHaveProperty('updateChannel');
      expect(payload).not.toHaveProperty('releaseChannel');
      expect(payload).not.toHaveProperty('track');
      expect(payload).not.toHaveProperty('branch');
    }
  );

  it('returns isError instead of throwing when the router is unreachable', async () => {
    const { handlers } = capture(
      contextWith(async () => {
        throw new AuthError('the router rejected credentials for user "admin"');
      })
    );

    const result = await handlers['get_system_info']!({});
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('keenetic-noc-mcp router test');
  });

  it('registers read tools with readOnlyHint', () => {
    const { configs } = capture(contextWith(async () => ({})));
    expect(configs['get_system_info']?.annotations?.readOnlyHint).toBe(true);
    expect(configs['get_config_state']?.annotations?.readOnlyHint).toBe(true);
  });

  it('describes raw metadata and capability lists without operational inference', () => {
    const { configs } = capture(contextWith(async () => ({})));
    const description = configs['get_system_info']?.description ?? '';
    expect(description).toContain('router-reported KeeneticOS metadata exposed without interpretation');
    expect(description).toContain('installed software/component modules');
    expect(description).toContain('hardware/platform capabilities');
    expect(description).toContain('not that a related service is configured, enabled, reachable, healthy, active, or operational');
    expect(description).not.toMatch(/channel/i);
  });

  it('continues to apply the existing response ceiling to oversized metadata', async () => {
    const ctx = contextWith(async () => system(), async () => '', undefined,
      { ...CAPS, release: 'x '.repeat(5_000) });
    ctx.maxResponseBytes = 512;
    const { handlers } = capture(ctx);
    const result = await handlers['get_system_info']!({});
    expect(Buffer.byteLength(textOf(result), 'utf8')).toBeLessThanOrEqual(512);
    expect(JSON.parse(textOf(result))).toMatchObject({ truncated: true });
  });
});

describe('get_connection_status', () => {
  it('keeps its existing firmware-only consumer behavior when metadata is available', async () => {
    const caps: Capabilities = { ...CAPS, release: 'synthetic-release', sandbox: 'synthetic-sandbox' };
    const { handlers } = capture(contextWith(async () => ({}), async () => '', undefined, caps));
    const payload = JSON.parse(textOf(await handlers['get_connection_status']!({})));
    expect(payload.firmware).toBe('5.1.3');
    expect(typeof payload.firmware).toBe('string');
    expect(payload).not.toHaveProperty('release');
    expect(payload).not.toHaveProperty('sandbox');
  });

  it('reports measured remote startup config while preserving LAN-only backup policy', async () => {
    const ctx = contextWith(async () => ({}));
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };
    const { handlers } = capture(ctx);
    const payload = JSON.parse(textOf(await handlers['get_connection_status']!({})));
    expect(payload.startupConfigCapability).toBe('rci-more');
    expect(payload.backupPathCapability).toBe('unsupported-remotely');
    expect(payload.backupBeforeWrite).toBe('requires-lan-profile');
    expect(payload.configCapabilities.startup).toEqual({
      state: 'available', method: 'rci-more', reason: null
    });
    expect(ctx.client.rci.getText).not.toHaveBeenCalled();
  });

  it('reports a metadata-verified LAN backup path', async () => {
    const ctx = contextWith(async () => ({}));
    ctx.connection = { mode: 'lan', endpoint: 'http://192.0.2.1/rci/' };
    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_connection_status']!({})));
    expect(payload.startupConfigCapability).toBe('rci-more');
    expect(payload.backupPathCapability).toBe('verified');
    expect(payload.backupBeforeWrite).toBe('available-when-verified');
  });

  it('keeps unavailable startup and backup states distinct from unknown', async () => {
    const ctx = contextWith(async () => ({}));
    ctx.connection = { mode: 'lan', endpoint: 'http://192.0.2.1/rci/' };
    ctx.client.probedCapabilities = async () => ({
      config: {
        runningCli: { state: 'available', method: 'rci-show', reason: null },
        runningStructured: { state: 'unknown', method: null, reason: 'not-probed' },
        startup: { state: 'unavailable', method: null, reason: 'denied' },
        backup: { state: 'unavailable', method: null, reason: 'not-found' }
      }
    });
    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_connection_status']!({})));
    expect(payload.startupConfigCapability).toBe('unavailable');
    expect(payload.backupPathCapability).toBe('unavailable');
    expect(payload.backupBeforeWrite).toBe('unavailable');
    expect(payload.configCapabilities.startup.reason).toBe('denied');
  });
});

describe('get_config_state', () => {
  const RUNNING = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const STALE = '0f9e8d7c6b5a49382716f5e4d3c2b1a0';

  /**
   * `fail-safe.unsaved` is false in every case here on purpose. A real 5.1.1
   * router reports it that way even with a change pending, so any answer that
   * comes from that flag rather than from the checksums is wrong.
   */
  const lastChange = async () => ({
    date: 'Thu, 6 Aug 2026 10:46:01 GMT',
    agent: 'http/rci',
    user: 'admin',
    checksum: RUNNING,
    'fail-safe': { unsaved: false, rollback: false, 'time-left': 0 }
  });

  const startupWith = (checksum: string) => async () =>
    `! $$$ Md5 checksum: ${checksum}\nip hotspot\n`;

  it('reports unsaved changes when flash still holds an older checksum', async () => {
    const { handlers } = capture(contextWith(lastChange, startupWith(STALE)));

    const payload = JSON.parse(textOf(await handlers['get_config_state']!({})));
    expect(payload.unsavedChanges).toBe(true);
    expect(payload.runningChecksum).toBe(RUNNING);
    expect(payload.savedChecksum).toBe(STALE);
    expect(payload.lastChangedBy).toBe('admin');
    expect(payload.failSafe.rollbackPending).toBe(false);
  });

  it('reports saved once the checksums agree', async () => {
    const { handlers } = capture(contextWith(lastChange, startupWith(RUNNING)));

    const payload = JSON.parse(textOf(await handlers['get_config_state']!({})));
    expect(payload.unsavedChanges).toBe(false);
  });

  it('surfaces the fail-safe flag separately from the saved state', async () => {
    const { handlers } = capture(contextWith(lastChange, startupWith(STALE)));

    const payload = JSON.parse(textOf(await handlers['get_config_state']!({})));
    expect(payload.failSafe.unsaved).toBe(false);
    expect(payload.unsavedChanges).toBe(true);
  });

  it('answers unknown rather than saved when the startup config cannot be read', async () => {
    const { handlers } = capture(
      contextWith(lastChange, async () => {
        throw new Error('404');
      })
    );

    const payload = JSON.parse(textOf(await handlers['get_config_state']!({})));
    expect(payload.unsavedChanges).toBeNull();
    expect(payload.savedChecksum).toBeNull();
  });

  it('uses measured remote rci-more input when the LAN-only startup file is unavailable', async () => {
    const getText = vi.fn(async () => {
      throw new Error('the LAN startup path must not be read');
    });
    const getConfig = vi.fn(async (path: string, maxBytes: number) => {
      expect(path).toBe('more?filename=startup-config');
      expect(maxBytes).toBe(256_000);
      return { value: { result: [`! $$$ Md5 checksum: ${RUNNING}`, 'system synthetic'] }, bytes: 100 };
    });
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };
    ctx.client.probedCapabilities = async () => ({ config: {
      ...PROBED.config,
      backup: { state: 'unavailable', method: null, reason: 'not-found' }
    } });

    const registered = capture(ctx);
    const payload = JSON.parse(textOf(await registered.handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: RUNNING, unsavedChanges: false });
    expect(JSON.stringify(payload)).not.toContain('system synthetic');
    expect(getConfig).toHaveBeenCalledOnce();
    expect(getText).not.toHaveBeenCalled();
    expect(ctx.backup.ensure).not.toHaveBeenCalled();
    expect(ctx.client.rci.post).not.toHaveBeenCalled();
    expect(registered.configs['get_config_state']?.annotations?.readOnlyHint).toBe(true);

    const status = JSON.parse(textOf(await capture(ctx).handlers['get_connection_status']!({})));
    expect(status.startupConfigCapability).toBe('rci-more');
    expect(status.backupBeforeWrite).toBe('requires-lan-profile');
  });

  it('reports unsaved changes from a measured remote rci-more checksum mismatch', async () => {
    const getText = vi.fn(async () => {
      throw new Error('the LAN startup path must not be read');
    });
    const getConfig = vi.fn(async () => ({
      value: { result: [`! $$$ Md5 checksum: ${STALE}`] }, bytes: 100
    }));
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ runningChecksum: RUNNING, savedChecksum: STALE, unsavedChanges: true });
    expect(getText).not.toHaveBeenCalled();
  });

  it('normalizes uppercase hexadecimal digits under the canonical label', async () => {
    const getText = vi.fn(async () => {
      throw new Error('the LAN startup path must not be read');
    });
    const getConfig = vi.fn(async () => ({
      value: { result: [`! $$$ Md5 checksum: ${RUNNING.toUpperCase()}`] }, bytes: 100
    }));
    const ctx = contextWith(lastChange, getText, getConfig);

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: RUNNING, unsavedChanges: false });
    expect(getConfig).toHaveBeenCalledWith('more?filename=startup-config', 256_000);
    expect(getText).not.toHaveBeenCalled();
  });

  it('reports a LAN ci-file checksum mismatch without consulting rci-more', async () => {
    const getText = vi.fn(startupWith(STALE));
    const getConfig = vi.fn(async () => {
      throw new Error('rci-more must not be read for a measured ci-file source');
    });
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.client.probedCapabilities = async () => ({ config: {
      ...PROBED.config,
      startup: { state: 'available', method: 'ci-file', reason: null }
    } });

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({
      runningChecksum: RUNNING,
      savedChecksum: STALE,
      unsavedChanges: true
    });
    expect(getText).toHaveBeenCalledWith('/ci/startup-config.txt', 256_000);
    expect(getConfig).not.toHaveBeenCalled();
  });

  it.each([
    ['missing', undefined],
    ['non-string', 42],
    ['short', 'abc'],
    ['non-hex', 'not-a-checksum']
  ])('keeps a %s running checksum unknown even when startup input is valid', async (_name, checksum) => {
    const malformedLastChange = async () => {
      const current = await lastChange();
      if (checksum === undefined) {
        const { checksum: _ignored, ...withoutChecksum } = current;
        return withoutChecksum;
      }
      return { ...current, checksum };
    };
    const { handlers } = capture(contextWith(malformedLastChange, startupWith(RUNNING)));

    const payload = JSON.parse(textOf(await handlers['get_config_state']!({})));
    expect(payload.runningChecksum).toBeNull();
    expect(payload.savedChecksum).toBe(RUNNING);
    expect(payload.unsavedChanges).toBeNull();
  });

  it.each([
    ['unavailable', { state: 'unavailable', method: null, reason: 'denied' }],
    ['unknown', { state: 'unknown', method: null, reason: 'not-probed' }]
  ] as const)('keeps %s startup capability evidence unknown without a fallback', async (_name, startup) => {
    const getText = vi.fn(async () => {
      throw new Error('startup input must not be read');
    });
    const getConfig = vi.fn(async () => {
      throw new Error('startup input must not be read');
    });
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.client.probedCapabilities = async () => ({ config: { ...PROBED.config, startup } });

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: null, unsavedChanges: null });
    expect(getText).not.toHaveBeenCalled();
    expect(getConfig).not.toHaveBeenCalled();
  });

  it('keeps an unrecognized available startup method unknown without a fallback', async () => {
    const getText = vi.fn(async () => {
      throw new Error('startup input must not be read');
    });
    const getConfig = vi.fn(async () => {
      throw new Error('startup input must not be read');
    });
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.client.probedCapabilities = async () => ({ config: {
      ...PROBED.config,
      startup: { state: 'available', method: 'future-method', reason: null }
    } }) as never;

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: null, unsavedChanges: null });
    expect(getText).not.toHaveBeenCalled();
    expect(getConfig).not.toHaveBeenCalled();
  });

  it.each([
    ['missing generated header', ['system synthetic']],
    ['malformed generated header', ['! $$$ Md5 checksum: short', 'system synthetic']],
    ['extra hexadecimal checksum suffix', [`! $$$ Md5 checksum: ${RUNNING}a`, 'system synthetic']],
    ['non-whitespace checksum suffix', [`! $$$ Md5 checksum: ${RUNNING}!`, 'system synthetic']],
    ['one-dollar marker', [`! $ Md5 checksum: ${RUNNING}`, 'system synthetic']],
    ['two-dollar marker', [`! $$ Md5 checksum: ${RUNNING}`, 'system synthetic']],
    ['four-dollar marker', [`! $$$$ Md5 checksum: ${RUNNING}`, 'system synthetic']],
    ['bare carriage-return suffix', [`! $$$ Md5 checksum: ${RUNNING}\runexpected`, 'system synthetic']],
    ['Unicode line-separator suffix', [`! $$$ Md5 checksum: ${RUNNING}\u2028unexpected`, 'system synthetic']],
    ['Unicode paragraph-separator suffix', [`! $$$ Md5 checksum: ${RUNNING}\u2029unexpected`, 'system synthetic']],
    ['header split after the exclamation mark', ['!', `$$$ Md5 checksum: ${RUNNING}`]],
    ['header split after the dollar marker', ['! $$$', `Md5 checksum: ${RUNNING}`]],
    ['header split after the label', ['! $$$ Md5 checksum:', RUNNING]],
    ['lowercase Md5 label', [`! $$$ md5 checksum: ${RUNNING}`]],
    ['uppercase Md5 label', [`! $$$ MD5 checksum: ${RUNNING}`]],
    ['uppercase checksum label', [`! $$$ Md5 CHECKSUM: ${RUNNING}`]],
    ['identical duplicate strict headers', [
      `! $$$ Md5 checksum: ${RUNNING}`,
      `! $$$ Md5 checksum: ${RUNNING}`
    ]],
    ['conflicting duplicate strict headers', [
      `! $$$ Md5 checksum: ${RUNNING}`,
      `! $$$ Md5 checksum: ${STALE}`
    ]]
  ])('keeps %s unknown without returning startup lines', async (_name, lines) => {
    const getConfig = vi.fn(async () => ({ value: { result: lines }, bytes: 100 }));
    const ctx = contextWith(lastChange, async () => {
      throw new Error('the LAN startup path must not be read');
    }, getConfig);
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: null, unsavedChanges: null });
    expect(JSON.stringify(payload)).not.toContain('system synthetic');
    expect(getConfig).toHaveBeenCalledWith('more?filename=startup-config', 256_000);
    expect(ctx.client.rci.getText).not.toHaveBeenCalled();
  });

  it.each([
    new AuthError('credentials rejected'),
    new TransportError('connection lost'),
    new RciError('response exceeds limit', { path: 'configuration', code: 'response-too-large', ident: 'rci' })
  ])('keeps startup read failures unknown at the MCP boundary', async error => {
    const getText = vi.fn(async () => {
      throw new Error('the LAN startup path must not be read');
    });
    const getConfig = vi.fn(async () => {
      throw error;
    });
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: null, unsavedChanges: null });
    expect(getText).not.toHaveBeenCalled();
  });

  it('keeps an unexpected bounded rci-more shape unknown without a /ci fallback', async () => {
    const getText = vi.fn(async () => {
      throw new Error('the LAN startup path must not be read');
    });
    const getConfig = vi.fn(async () => ({ value: { first: ['system'], second: ['synthetic'] }, bytes: 100 }));
    const ctx = contextWith(lastChange, getText, getConfig);
    ctx.connection = { mode: 'remote', endpoint: 'https://rci.example.test/rci/' };

    const payload = JSON.parse(textOf(await capture(ctx).handlers['get_config_state']!({})));
    expect(payload).toMatchObject({ savedChecksum: null, unsavedChanges: null });
    expect(getText).not.toHaveBeenCalled();
  });
});
