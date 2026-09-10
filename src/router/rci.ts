import { RciError } from './errors.js';
export interface RciSession { request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response>; }

export interface RciStatus {
  status: string;
  code?: string;
  ident?: string;
  message?: string;
}

export type RciContentTypeClass = 'json' | 'text' | 'binary' | 'unknown';
export type RciResponseShape = 'array' | 'string' | 'object' | 'unknown';

/** Sanitized response facts safe to retain after discarding a probe body. */
export interface RciProbeMetadata {
  httpStatus: number;
  contentTypeClass: RciContentTypeClass;
  shape: RciResponseShape;
  items: number | null;
  bytes: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Walks the whole response looking for `status` arrays. The router answers
 * HTTP 200 with the failure inside the body, sometimes several levels deep.
 * The `status` key is consumed here and skipped in the generic descent so a
 * block is never counted twice.
 */
export function collectStatuses(value: unknown): RciStatus[] {
  const found: RciStatus[] = [];

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (!isRecord(node)) return;

    const block = node['status'];
    if (Array.isArray(block)) {
      for (const entry of block) {
        if (isRecord(entry) && typeof entry['status'] === 'string') {
          found.push(entry as unknown as RciStatus);
        }
      }
    }

    for (const [key, child] of Object.entries(node)) {
      if (key === 'status') continue;
      walk(child);
    }
  };

  walk(value);
  return found;
}

export class Rci {
  constructor(private readonly session: RciSession) {}

  async get<T = unknown>(path: string): Promise<T> {
    const clean = path.replace(/^\/+/, '');
    const res = await this.session.request('GET', `/rci/${clean}`);
    return this.parse<T>(res, clean);
  }

  async post<T = unknown>(body: unknown): Promise<T> {
    const res = await this.session.request('POST', '/rci/', body);
    return this.parse<T>(res, 'POST /rci/');
  }

  /** Plain-text endpoints such as /ci/startup-config.txt. */
  async getText(path: string): Promise<string> {
    const res = await this.session.request('GET', path);
    if (!res.ok) {
      throw new RciError(`HTTP ${res.status}`, { path, code: String(res.status), ident: 'http' });
    }
    return res.text();
  }

  /**
   * Reads a GET surface for capability discovery and returns metadata only.
   * The response body is inspected in memory, never returned to the caller.
   */
  async probeGet(path: string): Promise<RciProbeMetadata> {
    const clean = path.replace(/^\/+/, '');
    const res = await this.session.request('GET', `/rci/${clean}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    const contentTypeClass = classifyContentType(res.headers.get('content-type'));
    if (!res.ok) {
      return { httpStatus: res.status, contentTypeClass, shape: 'unknown', items: null, bytes: bytes.byteLength };
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
        path: clean,
        code: firstError.code ?? 'unknown',
        ident: firstError.ident ?? 'unknown'
      });
    }

    const shape = responseShape(value);
    return {
      httpStatus: res.status,
      contentTypeClass,
      shape,
      items: countItems(value, shape),
      bytes: bytes.byteLength
    };
  }

  private async parse<T>(res: Response, path: string): Promise<T> {
    if (res.status === 404) {
      throw new RciError(`this path does not exist on this firmware`, {
        path,
        code: '404',
        ident: 'http'
      });
    }
    const text = await res.text();
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
