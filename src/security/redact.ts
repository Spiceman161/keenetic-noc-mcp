const SENSITIVE_KEY = /^(authorization|cookie|password|passwd|private[-_]?key|preshared[-_]?key|psk|token|secret)$/i;
const LONG_KEY = /\b[A-Za-z0-9+/]{40,}={0,2}\b/g;

export function redact<T>(value: T): T {
  const seen = new WeakSet<object>();
  const visit = (node: unknown): unknown => {
    if (typeof node === 'string') {
      return node
        .replace(/\b(authorization|cookie|password|passwd|psk|token|secret)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
        .replace(LONG_KEY, '[REDACTED_KEY]');
    }
    if (!node || typeof node !== 'object') return node;
    if (seen.has(node)) return '[CIRCULAR]';
    seen.add(node);
    if (Array.isArray(node)) return node.map(visit);
    return Object.fromEntries(Object.entries(node).map(([key, child]) => [key, SENSITIVE_KEY.test(key) ? '[REDACTED]' : visit(child)]));
  };
  return visit(value) as T;
}

export const redactText = (value: string): string => redact(value);
