import { setTimeout as delay } from 'node:timers/promises';
import { ActiveDiagnosticUncertainError, AuthError, RciError, TransportError } from './errors.js';

export interface RciRequestControls {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface RciSession {
  request(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
    controls?: RciRequestControls
  ): Promise<Response>;
  /** Returns the operator/session ceiling applied to a requested job timeout. */
  effectiveTimeoutMs?(requestedMs: number): number;
}

async function readBounded(res: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    if (res.body) {
      const reader = res.body.getReader();
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
    throw new RciError(`response exceeds ${maxBytes} byte safety limit`, {
      path: 'response', code: 'response-too-large', ident: 'rci'
    });
  }
  if (!res.body) {
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.byteLength > maxBytes) throw new RciError(`response exceeds ${maxBytes} byte safety limit`, { path: 'response', code: 'response-too-large', ident: 'rci' });
    return bytes;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new RciError(`response exceeds ${maxBytes} byte safety limit`, { path: 'response', code: 'response-too-large', ident: 'rci' });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

async function readResponse(res: Response, maxBytes?: number): Promise<Uint8Array> {
  return readBounded(res, maxBytes ?? DEFAULT_RESPONSE_MAX_BYTES);
}

/** Safety ceiling used when a caller has no narrower, endpoint-specific bound. */
export const DEFAULT_RESPONSE_MAX_BYTES = 2_000_000;

export interface RciStatus {
  status: string;
  code?: string;
  ident?: string;
  message?: string;
}

export type RciContentTypeClass = 'json' | 'text' | 'binary' | 'unknown';
export type RciResponseShape = 'array' | 'string' | 'object' | 'unknown';
export type RciPayloadItemShape = 'array' | 'string' | 'object' | 'scalar' | 'mixed' | 'empty' | 'unknown';

/** Sanitized response facts safe to retain after discarding a probe body. */
export interface RciProbeMetadata {
  httpStatus: number;
  contentTypeClass: RciContentTypeClass;
  shape: RciResponseShape;
  items: number | null;
  bytes: number;
  payloadShape: RciResponseShape;
  payloadItems: number | null;
  payloadItemShape: RciPayloadItemShape;
  wrapperDepth: number;
}

export interface BoundedRciValue<T = unknown> {
  value: T;
  bytes: number;
}

export interface ContinuedRciResult {
  messages: string[];
  bytes: number;
  polls: number;
  termination: 'completed' | 'timeout';
  effectiveTimeoutMs: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function cancellationConfirmed(response: Response): Promise<boolean> {
  if (!response.ok) return false;
  try {
    const body = await readBounded(response, 4_096);
    const value: unknown = JSON.parse(new TextDecoder().decode(body));
    // The only live-proven successful DELETE acknowledgement is `{}`. Do not
    // infer cancellation from an unknown 2xx payload shape.
    return isRecord(value) && Object.keys(value).length === 0;
  } catch {
    return false;
  }
}

/**
 * Walks the whole response looking for `status` arrays. The router answers
 * HTTP 200 with the failure inside the body, sometimes several levels deep.
 * The `status` key is consumed here and skipped in the generic descent so a
 * block is never counted twice.
 */
export function collectStatuses(value: unknown): RciStatus[] {
  const found: RciStatus[] = [];
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const node = pending.pop();
    if (Array.isArray(node)) {
      for (let index = node.length - 1; index >= 0; index -= 1) pending.push(node[index]);
      continue;
    }
    if (!isRecord(node)) continue;

    const block = node['status'];
    if (Array.isArray(block)) {
      for (const entry of block) {
        if (isRecord(entry) && typeof entry['status'] === 'string') {
          found.push(entry as unknown as RciStatus);
        }
      }
    }

    const children = Object.entries(node);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const entry = children[index];
      if (entry?.[0] !== 'status') pending.push(entry?.[1]);
    }
  }
  return found;
}

export class Rci {
  constructor(private readonly session: RciSession) {}

  async get<T = unknown>(path: string, maxBytes?: number): Promise<T> {
    const clean = path.replace(/^\/+/, '');
    const res = await this.session.request('GET', `/rci/${clean}`);
    return this.parse<T>(res, clean, maxBytes);
  }

  /**
   * Reads configuration JSON without ever copying response content into an
   * error. Configuration can contain credentials even when an HTTP request
   * fails, so the generic diagnostic parser is deliberately not used here.
   */
  async getConfig<T = unknown>(path: string, maxBytes: number): Promise<BoundedRciValue<T>> {
    const clean = path.replace(/^\/+/, '');
    const displayPath = clean === '' ? '/' : clean;
    const res = await this.session.request('GET', `/rci/${clean}`);
    const bytes = await readResponse(res, maxBytes);
    if (!res.ok) {
      throw new RciError(`HTTP ${res.status} while reading configuration`, {
        path: displayPath, code: String(res.status), ident: 'http'
      });
    }
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new RciError('the configuration response is not valid JSON', {
        path: displayPath, code: 'parse', ident: 'rci'
      });
    }
    const firstError = collectStatuses(value).find(status => status.status === 'error');
    if (firstError) {
      throw new RciError('the router reported an error while reading configuration', {
        path: displayPath,
        code: 'router-error',
        ident: 'rci'
      });
    }
    return { value: value as T, bytes: bytes.byteLength };
  }

  async post<T = unknown>(body: unknown, maxBytes?: number): Promise<T> {
    const res = await this.session.request('POST', '/rci/', body);
    return this.parse<T>(res, 'POST /rci/', maxBytes);
  }

  /**
   * Runs one of Keenetic's finite `/rci/tools/*` jobs. These endpoints return
   * message chunks plus `continued=true`; GET polls retrieve later chunks and
   * DELETE is the router-native cancellation mechanism.
   */
  async runContinued(
    path: 'tools/ping' | 'tools/ping6' | 'tools/traceroute',
    body: Record<string, unknown>,
    maxBytes: number,
    controls: RciRequestControls = {}
  ): Promise<ContinuedRciResult> {
    const requestedTimeoutMs = controls.timeoutMs ?? 10_000;
    const timeoutMs = this.session.effectiveTimeoutMs?.(requestedTimeoutMs) ?? requestedTimeoutMs;
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = controls.signal === undefined
      ? timeout
      : AbortSignal.any([controls.signal, timeout]);
    const endpoint = `/rci/${path}`;
    const messages: string[] = [];
    let bytes = 0;
    let polls = 0;
    let continued = false;
    let started = false;
    let method: 'POST' | 'GET' = 'POST';

    try {
      while (true) {
        if (signal.aborted) throw new TransportError('Active diagnostic was cancelled or exceeded its deadline.');
        if (method === 'GET' && maxBytes - bytes <= 0) {
          throw new RciError(`response exceeds ${maxBytes} byte safety limit`, {
            path, code: 'response-too-large', ident: 'rci'
          });
        }
        if (method === 'POST') started = true;
        const res = await this.session.request(method, endpoint, method === 'POST' ? body : undefined, {
          signal,
          timeoutMs
        });
        if (method === 'POST' && !res.ok) started = false;
        const remaining = maxBytes - bytes;
        if (remaining <= 0) throw new RciError(`response exceeds ${maxBytes} byte safety limit`, {
          path, code: 'response-too-large', ident: 'rci'
        });
        const chunk = await readBounded(res, remaining);
        bytes += chunk.byteLength;
        if (!res.ok) throw new RciError(`HTTP ${res.status}`, {
          path, code: String(res.status), ident: 'http'
        });
        let value: unknown;
        try {
          value = JSON.parse(new TextDecoder().decode(chunk));
        } catch {
          throw new RciError('the active diagnostic response is not valid JSON', {
            path, code: 'parse', ident: 'rci'
          });
        }
        if (!isRecord(value)) throw new RciError('the active diagnostic response has an unexpected shape', {
          path, code: 'unexpected-response', ident: 'rci'
        });
        const directStatus = value['status'];
        if (directStatus === 'error') {
          if (method === 'POST') started = false;
          throw new RciError('the router rejected the active diagnostic', {
            path,
            code: typeof value['code'] === 'string' ? value['code'] : 'router-error',
            ident: typeof value['ident'] === 'string' ? value['ident'] : 'rci'
          });
        }
        const statusError = collectStatuses(value).find(item => item.status === 'error');
        if (statusError) {
          if (method === 'POST') started = false;
          throw new RciError('the router rejected the active diagnostic', {
            path, code: statusError.code ?? 'router-error', ident: statusError.ident ?? 'rci'
          });
        }
        const chunkMessages = value['message'];
        if (chunkMessages !== undefined &&
            (!Array.isArray(chunkMessages) || !chunkMessages.every(item => typeof item === 'string'))) {
          throw new RciError('the active diagnostic response has an unexpected message shape', {
            path, code: 'unexpected-response', ident: 'rci'
          });
        }
        if (Array.isArray(chunkMessages)) messages.push(...chunkMessages);
        if (value['continued'] !== undefined && typeof value['continued'] !== 'boolean') {
          throw new RciError('the active diagnostic response has an invalid continuation marker', {
            path, code: 'unexpected-response', ident: 'rci'
          });
        }
        continued = value['continued'] === true;
        if (!continued) {
          const keys = Object.keys(value);
          const validTerminal = keys.length === 0 ||
            (chunkMessages !== undefined && keys.every(key => key === 'message' || key === 'continued'));
          if (!validTerminal) throw new RciError(
            'the active diagnostic response has an unexpected terminal shape', {
              path, code: 'unexpected-response', ident: 'rci'
            }
          );
          return { messages, bytes, polls, termination: 'completed', effectiveTimeoutMs: timeoutMs };
        }
        polls += 1;
        await delay(500, undefined, { signal });
        method = 'GET';
      }
    } catch (error) {
      // Authentication rejection is deterministic: the active POST did not
      // reach an authenticated router command and needs no native cleanup.
      if (error instanceof AuthError && method === 'POST') started = false;
      if (started) {
        const cancelled = await this.session.request('DELETE', endpoint, undefined, { timeoutMs: 3_000 })
          .then(cancellationConfirmed).catch(() => false);
        if (!cancelled) throw new ActiveDiagnosticUncertainError();
      }
      if (timeout.aborted && !controls.signal?.aborted) {
        return { messages, bytes, polls, termination: 'timeout', effectiveTimeoutMs: timeoutMs };
      }
      if (signal.aborted && !(error instanceof RciError)) {
        throw new TransportError('Active diagnostic was cancelled or exceeded its deadline.');
      }
      throw error;
    }
  }

  /** Plain-text endpoints such as /ci/startup-config.txt. */
  async getText(path: string, maxBytes?: number): Promise<string> {
    const res = await this.session.request('GET', path);
    if (!res.ok) {
      throw new RciError(`HTTP ${res.status}`, { path, code: String(res.status), ident: 'http' });
    }
    return new TextDecoder().decode(await readResponse(res, maxBytes));
  }

  /**
   * Reads a GET surface for capability discovery and returns metadata only.
   * The response body is inspected in memory, never returned to the caller.
   */
  async probeGet(path: string, maxBytes?: number): Promise<RciProbeMetadata> {
    const clean = path.replace(/^\/+/, '');
    const res = await this.session.request('GET', `/rci/${clean}`);
    return this.probeResponse(res, clean, maxBytes);
  }

  /** Metadata-only probe for the one auxiliary file used by the safety model. */
  async probeStartupFile(maxBytes?: number): Promise<RciProbeMetadata> {
    const path = '/ci/startup-config.txt';
    const res = await this.session.request('GET', path);
    return this.probeResponse(res, path, maxBytes);
  }

  private async probeResponse(
    res: Response,
    path: string,
    maxBytes?: number
  ): Promise<RciProbeMetadata> {
    const bytes = await readResponse(res, maxBytes);
    const contentTypeClass = classifyContentType(res.headers.get('content-type'));
    if (!res.ok) {
      return {
        httpStatus: res.status,
        contentTypeClass,
        shape: 'unknown',
        items: null,
        bytes: bytes.byteLength,
        payloadShape: 'unknown',
        payloadItems: null,
        payloadItemShape: 'unknown',
        wrapperDepth: 0
      };
    }

    const text = new TextDecoder().decode(bytes);
    let value: unknown = contentTypeClass === 'json' ? undefined : text;
    try {
      value = JSON.parse(text);
    } catch {
      // Text and octet-stream config exports are valid; malformed JSON is not.
    }

    const firstError = collectStatuses(value).find(status => status.status === 'error');
    if (firstError) {
      throw new RciError('the router reported an error during the capability probe', {
        path,
        code: firstError.code ?? 'unknown',
        ident: firstError.ident ?? 'unknown'
      });
    }

    const shape = responseShape(value);
    const payload = describePayload(value);
    return {
      httpStatus: res.status,
      contentTypeClass,
      shape,
      items: countItems(value, shape),
      bytes: bytes.byteLength,
      ...payload
    };
  }

  private async parse<T>(res: Response, path: string, maxBytes?: number): Promise<T> {
    if (res.status === 404) {
      throw new RciError(`this path does not exist on this firmware`, {
        path,
        code: '404',
        ident: 'http'
      });
    }
    const text = new TextDecoder().decode(await readResponse(res, maxBytes));
    if (!res.ok) {
      throw new RciError(`HTTP ${res.status}: ${text.slice(0, 200)}`, {
        path,
        code: String(res.status),
        ident: 'http'
      });
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new RciError(
        `the response is not JSON (${text.length} bytes). Some endpoints such as ` +
          `show/netfilter return plain text; read them with a text-aware caller`,
        { path, code: 'parse', ident: 'rci' }
      );
    }

    const errors = collectStatuses(parsed).filter(s => s.status === 'error');
    const first = errors[0];
    if (first) {
      throw new RciError(first.message ?? 'the router reported an error', {
        path,
        code: first.code ?? 'unknown',
        ident: first.ident ?? 'unknown'
      });
    }

    return parsed as T;
  }
}

function classifyContentType(value: string | null): RciContentTypeClass {
  const mime = value?.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  if (mime === 'application/json' || mime.endsWith('+json')) return 'json';
  if (mime.startsWith('text/')) return 'text';
  if (mime === 'application/octet-stream' || mime.startsWith('image/') || mime.startsWith('audio/') ||
      mime.startsWith('video/')) return 'binary';
  return 'unknown';
}

function responseShape(value: unknown): RciResponseShape {
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'string') return 'string';
  if (isRecord(value)) return 'object';
  return 'unknown';
}

function countItems(value: unknown, shape: RciResponseShape): number | null {
  if (shape === 'array') return (value as unknown[]).length;
  if (shape === 'object') return Object.keys(value as Record<string, unknown>).length;
  if (shape !== 'string') return null;
  if (value === '') return 0;
  const lines = (value as string).split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  return lines.length;
}

function describePayload(value: unknown): Pick<
  RciProbeMetadata,
  'payloadShape' | 'payloadItems' | 'payloadItemShape' | 'wrapperDepth'
> {
  let payload = value;
  let wrapperDepth = 0;
  while (isRecord(payload) && Object.keys(payload).length === 1 && wrapperDepth < 16) {
    payload = Object.values(payload)[0];
    wrapperDepth += 1;
  }
  const payloadShape = responseShape(payload);
  return {
    payloadShape,
    payloadItems: countItems(payload, payloadShape),
    payloadItemShape: arrayItemShape(payload),
    wrapperDepth
  };
}

function arrayItemShape(value: unknown): RciPayloadItemShape {
  if (!Array.isArray(value)) return 'unknown';
  if (value.length === 0) return 'empty';
  const shapes = new Set(value.map(item => {
    const shape = responseShape(item);
    return shape === 'unknown' ? 'scalar' : shape;
  }));
  return shapes.size === 1 ? [...shapes][0]! : 'mixed';
}
