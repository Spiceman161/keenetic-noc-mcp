export type ConfigSection = 'dns' | 'interfaces' | 'routing' | 'wifi' | 'vpn' | 'users' | 'system' | 'all';
export type ClassifiedConfigSection = Exclude<ConfigSection, 'all'> | 'other';

export interface NumberedConfigLine {
  lineNumber: number;
  text: string;
}

function normalized(value: string): string {
  return value.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
}

function blocks(lines: readonly string[]): NumberedConfigLine[][] {
  const found: NumberedConfigLine[][] = [];
  let current: NumberedConfigLine[] | null = null;
  lines.forEach((text, index) => {
    const line = { lineNumber: index + 1, text };
    if (/^\S/.test(text) && !/^\s*[!#]/.test(text)) {
      current = [line];
      found.push(current);
    } else if (current) {
      current.push(line);
    }
  });
  return found;
}

function blockMatches(block: readonly NumberedConfigLine[], section: ConfigSection): boolean {
  if (section === 'all') return true;
  const opening = normalized(block[0]?.text ?? '');
  const content = normalized(block.map(line => line.text).join('\n'));
  switch (section) {
    case 'system': return /^(system|clock|schedule|components|cloud)\b/.test(opening);
    case 'users': return /^user\b/.test(opening);
    case 'dns': return /^(dns-proxy|mdns|ip name-server)\b/.test(opening);
    case 'routing': return /^(ip route|ip policy|ip static|ipv6 route)\b/.test(opening);
    case 'interfaces': return /^interface\b/.test(opening);
    case 'wifi':
      return /^(mws|easyconfig)\b/.test(opening) ||
        (/^interface\b/.test(opening) && /(wifimaster|accesspoint|\bssid\b|\bwpa|\bwifi)/i.test(content));
    case 'vpn':
      return /^interface\b/.test(opening) &&
        /(wireguard|ipsec|openvpn|l2tp|pptp|sstp|openconnect|vpn)/i.test(content);
  }
}

/** Assigns one stable owner to a CLI block for summaries such as config diffs. */
export function classifyConfigBlock(
  block: readonly NumberedConfigLine[]
): ClassifiedConfigSection {
  // Interface blocks can also be Wi-Fi or VPN. Prefer the more useful,
  // specific category while keeping broad section filtering unchanged.
  for (const section of ['vpn', 'wifi', 'system', 'users', 'dns', 'routing', 'interfaces'] as const) {
    if (blockMatches(block, section)) return section;
  }
  return 'other';
}

export function selectConfigSection(
  lines: readonly string[],
  section: ConfigSection
): NumberedConfigLine[] {
  if (section === 'all') return lines.map((text, index) => ({ lineNumber: index + 1, text }));
  return blocks(lines).filter(block => blockMatches(block, section)).flat();
}

export function filterConfigLines(
  lines: readonly NumberedConfigLine[],
  filter: string | undefined
): NumberedConfigLine[] {
  if (filter === undefined || filter.trim() === '') return [...lines];
  const needle = normalized(filter);
  return lines.filter(line => normalized(line.text).includes(needle));
}

export interface ConfigSearchGroup {
  startLine: number;
  endLine: number;
  lines: Array<NumberedConfigLine & { match: boolean }>;
}

export function searchConfigLines(
  corpus: readonly NumberedConfigLine[],
  query: string,
  limit: number,
  context: number
): { groups: ConfigSearchGroup[]; shownMatches: number; totalMatches: number } {
  const needle = normalized(query);
  if (needle === '') return { groups: [], shownMatches: 0, totalMatches: 0 };
  const matching = corpus.filter(line => normalized(line.text).includes(needle));
  const selected = matching.slice(0, limit);
  const selectedNumbers = new Set(selected.map(line => line.lineNumber));
  const indexByNumber = new Map(corpus.map((line, index) => [line.lineNumber, index]));
  const intervals = selected.map(line => {
    const index = indexByNumber.get(line.lineNumber) ?? 0;
    let start = index;
    let end = index;
    while (start > 0 && index - start < context &&
      corpus[start - 1]!.lineNumber === corpus[start]!.lineNumber - 1) start -= 1;
    while (end < corpus.length - 1 && end - index < context &&
      corpus[end + 1]!.lineNumber === corpus[end]!.lineNumber + 1) end += 1;
    return { start, end };
  });
  const merged: Array<{ start: number; end: number }> = [];
  for (const interval of intervals) {
    const previous = merged.at(-1);
    if (previous && interval.start <= previous.end + 1 &&
      corpus[interval.start]!.lineNumber <= corpus[previous.end]!.lineNumber + 1) {
      previous.end = Math.max(previous.end, interval.end);
    }
    else merged.push({ ...interval });
  }
  return {
    totalMatches: matching.length,
    shownMatches: selected.length,
    groups: merged.map(interval => ({
      startLine: corpus[interval.start]?.lineNumber ?? 0,
      endLine: corpus[interval.end]?.lineNumber ?? 0,
      lines: corpus.slice(interval.start, interval.end + 1).map(line => ({
        ...line, match: selectedNumbers.has(line.lineNumber)
      }))
    }))
  };
}

function jsonBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value, null, 2), 'utf8');
}

export function boundedArrayEnvelope<T>(
  base: Record<string, unknown>,
  key: string,
  items: readonly T[],
  maxBytes: number,
  total = items.length,
  forceTruncated = false
): Record<string, unknown> {
  let low = 0;
  let high = items.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    const truncated = forceTruncated || middle < items.length || items.length < total;
    const candidate: Record<string, unknown> = { ...base, [key]: items.slice(0, middle),
      shown: middle, total, truncated };
    if (truncated) candidate['note'] = `Showing ${middle} of ${total} entries. Narrow the query.`;
    if (jsonBytes(candidate) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  const result: Record<string, unknown> = {
    ...base,
    [key]: items.slice(0, low),
    shown: low,
    total,
    truncated: forceTruncated || low < items.length || items.length < total
  };
  if (forceTruncated || low < total) result['note'] = `Showing ${low} of ${total} entries. Narrow the query.`;
  return result;
}

export function boundedStructuredEnvelope(
  base: Record<string, unknown>,
  data: Record<string, unknown>,
  limit: number,
  maxBytes: number
): Record<string, unknown> {
  const entries = Object.entries(data);
  const total = entries.length;
  const limited = entries.slice(0, limit);
  let low = 0;
  let high = limited.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    const truncated = middle < total;
    const candidate: Record<string, unknown> = { ...base,
      data: Object.fromEntries(limited.slice(0, middle)), shown: middle, total, truncated };
    if (truncated) candidate['note'] = 'Request a narrower section.';
    if (jsonBytes(candidate) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  const result: Record<string, unknown> = { ...base,
    data: Object.fromEntries(limited.slice(0, low)), shown: low, total, truncated: low < total };
  if (low < total) {
    const withNote = { ...result, note: 'Request a narrower section.' };
    if (jsonBytes(withNote) <= maxBytes) return withNote;
  }
  return result;
}
