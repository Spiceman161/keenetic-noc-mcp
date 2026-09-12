import { performance } from 'node:perf_hooks';
import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import {
  getToolResultTelemetry,
  type ToolResult
} from '../tools/registry.js';
import {
  newCallId,
  normalizeErrorCode,
  safeIdentifier,
  safeRequestId,
  summarizeArguments,
  type TelemetryRecord,
  type ToolAttributes
} from './record.js';
import type { TelemetryWriter } from './writer.js';

export type ToolRegistrar = Pick<McpServer, 'registerTool'>;

export interface InstrumentationOptions {
  writer: TelemetryWriter;
  routerProfile: string;
  serverVersion: string;
  now?: () => Date;
  monotonicNow?: () => number;
  onWriteError?: () => void;
}

type RegistrationCallback = (
  args: unknown,
  context: ServerContext
) => ToolResult | Promise<ToolResult>;

type RegistrationFunction = (
  name: string,
  config: Record<string, unknown>,
  callback: RegistrationCallback
) => unknown;

const CALL_ID_META_KEY = 'io.github.spiceman161/telemetry';

function attributes(config: Record<string, unknown>): ToolAttributes {
  const annotations = config['annotations'];
  if (!annotations || typeof annotations !== 'object') return {};
  const source = annotations as Record<string, unknown>;
  const result: ToolAttributes = {};
  if (typeof source['readOnlyHint'] === 'boolean') result.read_only = source['readOnlyHint'];
  if (typeof source['destructiveHint'] === 'boolean') result.destructive = source['destructiveHint'];
  if (typeof source['openWorldHint'] === 'boolean') result.open_world = source['openWorldHint'];
  return result;
}

function registeredArgumentFields(config: Record<string, unknown>): ReadonlySet<string> {
  const schema = config['inputSchema'];
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return new Set();
  return new Set(Object.keys(schema));
}

function attachCallId(result: ToolResult, callId: string): ToolResult {
  const previous = result['_meta'];
  const meta = previous && typeof previous === 'object' && !Array.isArray(previous)
    ? previous as Record<string, unknown>
    : {};
  return {
    ...result,
    _meta: { ...meta, [CALL_ID_META_KEY]: { call_id: callId } }
  };
}

function resultBytes(result: ToolResult): number {
  return Buffer.byteLength(JSON.stringify(result), 'utf8');
}

/**
 * Wraps the public registration seam. SDK input validation occurs before this
 * callback, so pre-handler validation failures are intentionally out of scope.
 */
export function instrumentToolRegistration(
  server: McpServer,
  options?: InstrumentationOptions
): ToolRegistrar {
  if (options === undefined) {
    return { registerTool: server.registerTool.bind(server) };
  }

  const register = server.registerTool.bind(server) as unknown as RegistrationFunction;
  const now = options.now ?? (() => new Date());
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const routerProfile = safeIdentifier(options.routerProfile, 'unknown');
  const serverVersion = safeIdentifier(options.serverVersion, 'unknown');

  const wrapped: RegistrationFunction = (name, config, callback) => register(
    name,
    config,
    async (args, context) => {
      const started = now();
      const startedMonotonic = monotonicNow();
      let result: ToolResult | undefined;
      let thrown: unknown;
      let didThrow = false;

      try {
        result = await callback(args, context);
      } catch (error) {
        thrown = error;
        didThrow = true;
      }

      const finished = now();
      const duration = Math.max(0, Math.round(monotonicNow() - startedMonotonic));
      const reportWriteFailure = (): void => {
        try {
          options.onWriteError?.();
        } catch {
          // Telemetry reporting must not become a second failure path.
        }
      };

      let returned = result;
      try {
        const callId = newCallId();
        const telemetry = result === undefined ? undefined : getToolResultTelemetry(result);
        const status = didThrow || result?.isError === true ? 'error' : 'success';
        const errorCode = didThrow
          ? normalizeErrorCode(thrown)
          : telemetry?.errorCode ?? (status === 'error' ? 'internal' : null);
        const candidate = result === undefined ? undefined : attachCallId(result, callId);
        const requestId = safeRequestId(context.mcpReq.id);
        const record: TelemetryRecord = {
          schema_version: 1,
          timestamp: started.toISOString(),
          finished_at: finished.toISOString(),
          call_id: callId,
          ...(requestId === undefined ? {} : { mcp_request_id: requestId }),
          router_profile: routerProfile,
          tool: name,
          tool_attributes: attributes(config),
          duration_ms: duration,
          status,
          error_code: errorCode,
          args_summary: summarizeArguments(args, registeredArgumentFields(config)),
          result_size_bytes: candidate === undefined ? 0 : resultBytes(candidate),
          output_truncated: telemetry?.outputTruncated ?? false,
          server_version: serverVersion
        };
        returned = candidate;
        try {
          void options.writer.write(record).catch(reportWriteFailure);
        } catch {
          reportWriteFailure();
        }
      } catch {
        reportWriteFailure();
      }

      if (didThrow) throw thrown;
      return returned as ToolResult;
    }
  );

  return { registerTool: wrapped as McpServer['registerTool'] };
}
