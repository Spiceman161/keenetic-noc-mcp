export interface CappedList<T> {
  items: T[];
  shown: number;
  total: number;
  truncated: boolean;
  note?: string;
}

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
}

/**
 * Trims a list to the item limit, then shrinks further until it fits the byte
 * ceiling. A single over-sized item is omitted: the configured ceiling is a
 * security boundary, not a best-effort target.
 */
export function capList<T>(items: readonly T[], limit: number, maxBytes: number): CappedList<T> {
  const total = items.length;
  let kept = items.slice(0, Math.max(0, limit));

  while (kept.length > 0 && byteLength(kept) > maxBytes) {
    // Halve rather than step down one at a time: a 455-row NAT table would
    // otherwise re-serialise hundreds of times.
    kept = kept.slice(0, Math.floor(kept.length / 2));
  }

  const truncated = kept.length < total || (kept.length > 0 && byteLength(kept) > maxBytes);

  const result: CappedList<T> = {
    items: kept,
    shown: kept.length,
    total,
    truncated
  };
  if (kept.length < total) {
    result.note =
      `Showing ${kept.length} of ${total} entries. Narrow the query with the ` +
      `filter, sort or limit parameters to see the rest.`;
  }
  return result;
}

export function capText(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const suffix = '\n\n[truncated]';
  const suffixBytes = Buffer.byteLength(suffix, 'utf8');
  if (maxBytes <= suffixBytes) return Buffer.from(text).subarray(0, maxBytes).toString('utf8').replace(/\uFFFD$/u, '');
  let head = Buffer.from(text).subarray(0, maxBytes - suffixBytes).toString('utf8').replace(/\uFFFD$/u, '');
  while (Buffer.byteLength(`${head}${suffix}`, 'utf8') > maxBytes) head = head.slice(0, -1);
  return `${head}${suffix}`;
}
