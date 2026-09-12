const SENSITIVE_KEY_PART = /(?:^|[-_])(?:authorization|cookie|password|passwd|passphrase|private[-_]?key|preshared[-_]?key|shared[-_]?secret|auth[-_]?key|wpa[-_]?psk|psk|token|secret|community|key)(?:$|[-_])/i;
const PUBLIC_KEY = /(?:^|[-_])public[-_]?key$/i;

function sensitiveKey(key: string): boolean {
  const normalized = key
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  if (PUBLIC_KEY.test(normalized)) {
    const prefix = normalized.replace(/(?:^|[-_])public[-_]?key$/i, '');
    if (!SENSITIVE_KEY_PART.test(prefix)) return false;
  }
  return SENSITIVE_KEY_PART.test(normalized);
}
const LONG_KEY = /\b[A-Za-z0-9+/]{40,}={0,2}\b/g;
const LABELLED_VALUE = /\b([A-Za-z][A-Za-z0-9_-]*)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/g;

export function redact<T>(value: T): T {
  const seen = new WeakSet<object>();
  const visit = (node: unknown): unknown => {
    if (typeof node === 'string') {
      return node
        .replace(LABELLED_VALUE, (match, label: string) =>
          sensitiveKey(label) ? `${label}=[REDACTED]` : match)
        .replace(LONG_KEY, '[REDACTED_KEY]');
    }
    if (!node || typeof node !== 'object') return node;
    if (seen.has(node)) return '[CIRCULAR]';
    seen.add(node);
    if (Array.isArray(node)) return node.map(visit);
    return Object.fromEntries(Object.entries(node).map(([key, child]) => [key,
      sensitiveKey(key) ? '[REDACTED]' : visit(child)]));
  };
  return visit(value) as T;
}

const URL_TOKEN = /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s<>'"]+/gi;

function sanitizeUrl(token: string): string {
  try {
    const url = new URL(token);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return '[REDACTED_URL]';
  }
}

/** Redacts free-form router/error text, including complete authorization values and URL secrets. */
export const redactText = (value: string): string => redact(value
  .replace(/\bauthorization\s*[:=]\s*[^\r\n]*/gi, 'authorization: [REDACTED]')
  .replace(URL_TOKEN, sanitizeUrl));

const CLI_SECRET = /\b(password|passwd|passphrase|psk|wpa-psk|private-key|preshared-key|secret|token|key)(\s+)(.+)$/i;
/** Redacts positional secrets used by Keenetic's saved CLI syntax. */
export function redactConfigLines(lines: readonly string[]): string[] {
  let privateBlock = false;
  let continuedQuote: '"' | "'" | null = null;
  return lines.map(line => {
    const indent = /^\s*/.exec(line)?.[0] ?? '';
    if (/-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/i.test(line)) {
      privateBlock = true;
      return `${indent}[REDACTED_PRIVATE_KEY_BLOCK]`;
    }
    if (privateBlock) {
      if (/-----END (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/i.test(line)) {
        privateBlock = false;
      }
      return `${indent}[REDACTED_PRIVATE_KEY_BLOCK]`;
    }
    if (continuedQuote !== null) {
      const closes = new RegExp(`(?:^|[^\\\\])\\${continuedQuote}`).test(line);
      if (closes) continuedQuote = null;
      return `${indent}[REDACTED_CONTINUATION]`;
    }
    const match = CLI_SECRET.exec(line);
    if (match) {
      const value = match[3] ?? '';
      const quote = value[0];
      if ((quote === '"' || quote === "'") && !new RegExp(`(?:^|[^\\\\])\\${quote}`, 'g')
        .test(value.slice(1))) continuedQuote = quote;
      return redactText(line.replace(CLI_SECRET, '$1$2[REDACTED]'));
    }
    return redactText(line);
  });
}

/** Stronger object-key policy for configuration trees than diagnostic data. */
export function redactStructuredConfig<T>(value: T): T {
  const seen = new WeakSet<object>();
  const visit = (node: unknown): unknown => {
    if (typeof node === 'string') return redactText(node);
    if (!node || typeof node !== 'object') return node;
    if (seen.has(node)) return '[CIRCULAR]';
    seen.add(node);
    if (Array.isArray(node)) return node.map(visit);
    return Object.fromEntries(Object.entries(node).map(([key, child]) =>
      [key, sensitiveKey(key) ? '[REDACTED]' : visit(child)]));
  };
  return visit(value) as T;
}
