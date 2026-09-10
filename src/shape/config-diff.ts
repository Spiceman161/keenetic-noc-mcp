import { createHash } from 'node:crypto';
import {
  classifyConfigBlock,
  type ClassifiedConfigSection,
  type NumberedConfigLine
} from './config.js';

export const MAX_DIFF_CELLS = 2_000_000;
export const MAX_DIFF_LINES = 10_000;

const SAVED_CHECKSUM_HEADER = /^!\s*(?:\$){3}\s*Md5 checksum:\s*[0-9a-f]{32}\s*$/i;
const SECTION_ORDER: readonly ClassifiedConfigSection[] = [
  'system', 'users', 'dns', 'routing', 'interfaces', 'wifi', 'vpn', 'other'
];

interface DiffLine {
  identity: string;
  text: string;
  section: ClassifiedConfigSection;
  redacted: boolean;
}

export interface ConfigDiffOperation {
  kind: 'added' | 'removed';
  text: string;
  section: ClassifiedConfigSection;
  redacted: boolean;
  group: number;
}

export interface ConfigDiffSummary {
  comparable: true;
  unsavedChanges: boolean;
  changedSections: ClassifiedConfigSection[];
  added: number;
  removed: number;
  redactedChanges: number;
  operations: ConfigDiffOperation[];
}

export interface ConfigDiffLimitExceeded {
  comparable: false;
  reason: 'comparison-limit-exceeded';
  requiredCells: number | null;
  maxCells: number;
  inputLines: number;
  maxLines: number;
}

function identity(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function sectionOwners(lines: readonly string[]): ClassifiedConfigSection[] {
  const owners = Array<ClassifiedConfigSection>(lines.length).fill('other');
  let start: number | null = null;

  const assign = (from: number, to: number): void => {
    const block: NumberedConfigLine[] = [];
    for (let index = from; index < to; index += 1) {
      block.push({ lineNumber: index + 1, text: lines[index]! });
    }
    const section = classifyConfigBlock(block);
    for (let index = from; index < to; index += 1) owners[index] = section;
  };

  lines.forEach((line, index) => {
    if (/^\S/.test(line) && !/^\s*[!#]/.test(line)) {
      if (start !== null) assign(start, index);
      start = index;
    }
  });
  if (start !== null) assign(start, lines.length);
  return owners;
}

function prepare(raw: readonly string[], redacted: readonly string[]): DiffLine[] {
  if (raw.length !== redacted.length) {
    throw new Error('Raw and redacted configuration line counts differ.');
  }
  const owners = sectionOwners(redacted);
  return raw.flatMap((line, index) => SAVED_CHECKSUM_HEADER.test(line) ? [] : [{
    identity: identity(line),
    text: redacted[index]!,
    section: owners[index]!,
    redacted: line !== redacted[index]!
  }]);
}

function cell(matrix: Uint32Array, width: number, row: number, column: number): number {
  return matrix[row * width + column] ?? 0;
}

/**
 * Produces an exact, order-sensitive line edit script. Inputs are compared by
 * transient fingerprints while every renderable value comes from redacted input.
 */
export function diffConfigLines(
  startupRaw: readonly string[],
  runningRaw: readonly string[],
  redactLines: (lines: readonly string[]) => string[],
  limits: { maxCells?: number; maxLines?: number } = {}
): ConfigDiffSummary | ConfigDiffLimitExceeded {
  const maxCells = limits.maxCells ?? MAX_DIFF_CELLS;
  const maxLines = limits.maxLines ?? MAX_DIFF_LINES;
  const inputLines = Math.max(startupRaw.length, runningRaw.length);
  // Reject newline-heavy documents before redaction, hashing, or per-line
  // object allocation. The byte limit alone does not bound the line count.
  if (inputLines > maxLines) {
    return { comparable: false, reason: 'comparison-limit-exceeded', requiredCells: null,
      maxCells, inputLines, maxLines };
  }
  const startupRedacted = redactLines(startupRaw);
  const runningRedacted = redactLines(runningRaw);
  const before = prepare(startupRaw, startupRedacted);
  const after = prepare(runningRaw, runningRedacted);
  let prefix = 0;
  while (prefix < before.length && prefix < after.length &&
    before[prefix]!.identity === after[prefix]!.identity) prefix += 1;

  let beforeEnd = before.length;
  let afterEnd = after.length;
  while (beforeEnd > prefix && afterEnd > prefix &&
    before[beforeEnd - 1]!.identity === after[afterEnd - 1]!.identity) {
    beforeEnd -= 1;
    afterEnd -= 1;
  }

  const beforeLength = beforeEnd - prefix;
  const afterLength = afterEnd - prefix;
  const requiredCells = (beforeLength + 1) * (afterLength + 1);
  if (!Number.isSafeInteger(requiredCells) || requiredCells > maxCells) {
    return { comparable: false, reason: 'comparison-limit-exceeded', requiredCells, maxCells,
      inputLines, maxLines };
  }

  const width = afterLength + 1;
  const matrix = new Uint32Array(requiredCells);
  for (let row = beforeLength - 1; row >= 0; row -= 1) {
    for (let column = afterLength - 1; column >= 0; column -= 1) {
      const same = before[prefix + row]!.identity === after[prefix + column]!.identity;
      matrix[row * width + column] = same
        ? cell(matrix, width, row + 1, column + 1) + 1
        : Math.max(cell(matrix, width, row + 1, column), cell(matrix, width, row, column + 1));
    }
  }

  const operations: ConfigDiffOperation[] = [];
  let row = 0;
  let column = 0;
  let group = 0;
  let editing = false;
  const push = (kind: ConfigDiffOperation['kind'], line: DiffLine): void => {
    if (!editing) {
      group += 1;
      editing = true;
    }
    operations.push({ kind, text: line.text, section: line.section,
      redacted: line.redacted, group });
  };

  while (row < beforeLength && column < afterLength) {
    const oldLine = before[prefix + row]!;
    const newLine = after[prefix + column]!;
    if (oldLine.identity === newLine.identity) {
      row += 1;
      column += 1;
      editing = false;
    } else if (cell(matrix, width, row + 1, column) >= cell(matrix, width, row, column + 1)) {
      push('removed', oldLine);
      row += 1;
    } else {
      push('added', newLine);
      column += 1;
    }
  }
  while (row < beforeLength) push('removed', before[prefix + row++]!);
  while (column < afterLength) push('added', after[prefix + column++]!);

  const sections = new Set(operations.map(operation => operation.section));
  const redactedByGroup = new Map<number, { added: number; removed: number }>();
  for (const operation of operations) {
    if (!operation.redacted) continue;
    const counts = redactedByGroup.get(operation.group) ?? { added: 0, removed: 0 };
    counts[operation.kind] += 1;
    redactedByGroup.set(operation.group, counts);
  }
  return {
    comparable: true,
    unsavedChanges: operations.length > 0,
    changedSections: SECTION_ORDER.filter(section => sections.has(section)),
    added: operations.filter(operation => operation.kind === 'added').length,
    removed: operations.filter(operation => operation.kind === 'removed').length,
    redactedChanges: [...redactedByGroup.values()].reduce((total, counts) =>
      total + Math.max(counts.added, counts.removed), 0),
    operations
  };
}

function jsonBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value, null, 2), 'utf8');
}

export function boundedConfigDiffEnvelope(
  base: Record<string, unknown>,
  operations: readonly ConfigDiffOperation[],
  limit: number,
  maxBytes: number
): Record<string, unknown> {
  const limited = operations.slice(0, limit);
  let low = 0;
  let high = limited.length;
  const candidate = (shown: number): Record<string, unknown> => {
    const retained = limited.slice(0, shown);
    const truncated = shown < operations.length;
    const result: Record<string, unknown> = {
      ...base,
      diffIncluded: true,
      diff: retained.map(operation => `${operation.kind === 'added' ? '+' : '-'} ${operation.text}`),
      shown,
      total: operations.length,
      shownAdded: retained.filter(operation => operation.kind === 'added').length,
      shownRemoved: retained.filter(operation => operation.kind === 'removed').length,
      truncated
    };
    return result;
  };
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (jsonBytes(candidate(middle)) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  const result = candidate(low);
  if (result['truncated'] === true) {
    const withNote = { ...result,
      note: `Showing ${low} of ${operations.length} changed lines. Increase limit or narrow the request.` };
    if (jsonBytes(withNote) <= maxBytes) return withNote;
  }
  return result;
}
