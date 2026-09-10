import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { registerSystemTools } from '../../src/tools/system.js';
import { fail, ok, type ToolContext, type ToolResult } from '../../src/tools/registry.js';
import { AuthError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import { stubBackup } from '../helpers/backup.js';

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;
interface Captured {
  handlers: Record<string, Handler>;
  configs: Record<string, { annotations?: { readOnlyHint?: boolean } }>;
}

const CAPS = {
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
  getText: (path: string) => Promise<string> = async () => ''
): ToolContext {
  const client = {
    rci: { get, post: vi.fn(), getText: vi.fn(getText) },
    capabilities: async () => CAPS,
    probedCapabilities: async () => PROBED
  } as unknown as KeeneticClient;
  return { client, maxResponseBytes: 25_000, readOnly: false, backup: stubBackup() };
}

/** Registers the tools against a real McpServer with registerTool intercepted. */
function capture(ctx: ToolContext): Captured {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  const handlers: Record<string, Handler> = {};
  const configs: Record<string, { annotations?: { readOnlyHint?: boolean } }> = {};
  vi.spyOn(server, 'registerTool').mockImplementation(((
    name: string,
    config: { annotations?: { readOnlyHint?: boolean } },
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
});

describe('get_system_info', () => {
  it('reports model, firmware and the component list', async () => {
    const { handlers } = capture(
      contextWith(async path => {
        if (path === 'show/system') {
          return {
            hostname: 'router',
            cpuload: 6,
            memtotal: 524_288,
            memfree: 300_728,
            uptime: '94683'
          };
        }
        throw new Error(`unexpected path ${path}`);
      })
    );

    const payload = JSON.parse(textOf(await handlers['get_system_info']!({})));
    expect(payload.model).toBe('Keenetic Model (KN-0000)');
    expect(payload.firmware).toBe('5.1.3');
    expect(payload.components).toContain('wireguard');
    expect(payload.cpuLoad).toBe(6);
  });

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
});

describe('get_connection_status', () => {
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
});
