import { randomUUID } from 'node:crypto';
import {
  ActiveDiagnosticUncertainError,
  AuthError,
  GuardError,
  NotSupportedError,
  RciError,
  RemoteCapabilityError,
  ResourceError,
  TransportError,
  ValidationError,
  VerificationError
} from '../router/errors.js';

export type TelemetryStatus = 'success' | 'error';

export interface ArgumentDescriptor {
  type: 'array' | 'bigint' | 'boolean' | 'function' | 'null' | 'number' | 'object' |
    'string' | 'symbol' | 'undefined';
  length?: number;
  fields?: number;
}

export interface ArgumentsSummary {
  fields: Record<string, ArgumentDescriptor>;
  total_fields: number;
  truncated: boolean;
}

export interface ToolAttributes {
  read_only?: boolean;
  destructive?: boolean;
  open_world?: boolean;
}

export interface TelemetryRecord {
  schema_version: 1;
  timestamp: string;
  finished_at: string;
  call_id: string;
  mcp_request_id?: number;
  router_profile: string;
  tool: string;
  tool_attributes: ToolAttributes;
  duration_ms: number;
  status: TelemetryStatus;
  error_code: string | null;
  args_summary: ArgumentsSummary;
  result_size_bytes: number;
  output_truncated: boolean;
  server_version: string;
}

const MAX_ARGUMENT_FIELDS = 32;
const SAFE_FIELD = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function descriptor(value: unknown): ArgumentDescriptor {
  if (value === null) return { type: 'null' };
  if (Array.isArray(value)) return { type: 'array', length: value.length };
  if (typeof value === 'string') return { type: 'string', length: value.length };
  if (typeof value === 'object') return { type: 'object', fields: Object.keys(value).length };
  return { type: typeof value };
}

/** Values are deliberately excluded: even harmless-looking selectors can contain secrets. */
export function summarizeArguments(
  args: unknown,
  registeredFields: ReadonlySet<string> = new Set()
): ArgumentsSummary {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return { fields: {}, total_fields: 0, truncated: false };
  }
  const entries = Object.entries(args);
  const selected = entries.slice(0, MAX_ARGUMENT_FIELDS);
  const fields: Record<string, ArgumentDescriptor> = {};
  selected.forEach(([key, value], index) => {
    fields[SAFE_FIELD.test(key) && registeredFields.has(key) ? key : `unknown_${index + 1}`] =
      descriptor(value);
  });
  return { fields, total_fields: entries.length, truncated: selected.length < entries.length };
}

export function safeIdentifier(value: string | undefined, fallback: string): string {
  return value !== undefined && SAFE_IDENTIFIER.test(value) ? value : fallback;
}

export function safeRequestId(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  return undefined;
}

export function normalizeErrorCode(error: unknown): string {
  if (error instanceof ActiveDiagnosticUncertainError) return 'active_diagnostic_uncertain';
  if (error instanceof ResourceError) return error.code;
  if (error instanceof AuthError) return 'authentication';
  if (error instanceof TransportError) return 'transport';
  if (error instanceof RemoteCapabilityError || error instanceof NotSupportedError) {
    return 'unsupported_capability';
  }
  if (error instanceof ValidationError) return 'validation';
  if (error instanceof GuardError) return 'guard_refusal';
  if (error instanceof VerificationError) return 'verification';
  if (error instanceof RciError) {
    return error.code === 'response-too-large' ? 'response_too_large' : 'upstream_router_error';
  }
  return 'internal';
}

export const newCallId = (): string => randomUUID();
