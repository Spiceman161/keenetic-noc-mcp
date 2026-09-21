import { isIP } from 'node:net';

export interface EdgeEntry {
  readonly ip: string;
  readonly firstObservedAt: number;
  lastObservedAt: number;
  lastSuccessAt?: number;
  lastFailureAt?: number;
}

export interface EdgePoolOptions {
  now?: () => number;
  maxEntries?: number;
  staleThresholdMs?: number;
}

export interface EdgePoolCandidate {
  readonly ip: string;
  readonly prior: 'healthy' | 'unknown' | 'failed';
}

export interface EdgePoolCandidates {
  readonly poolSize: number;
  readonly totalCandidates: number;
  readonly candidates: readonly EdgePoolCandidate[];
}

const DEFAULT_MAX_ENTRIES = 10;
const DEFAULT_STALE_THRESHOLD_MS = 2 * 60 * 60 * 1000;

export function canonicalIp(value: string): string | null {
  const family = isIP(value);
  if (family === 4) return value;
  if (family !== 6) return null;
  try {
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

export class EdgePool {
  private readonly entries = new Map<string, EdgeEntry>();
  private readonly now: () => number;
  private readonly maxEntries: number;
  private readonly staleThresholdMs: number;

  constructor(opts: EdgePoolOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.staleThresholdMs = opts.staleThresholdMs ?? DEFAULT_STALE_THRESHOLD_MS;
  }

  observe(value: string): void {
    const ip = canonicalIp(value);
    if (ip === null) return;
    const observedAt = this.now();
    const existing = this.entries.get(ip);
    if (existing) {
      existing.lastObservedAt = observedAt;
      return;
    }

    if (this.maxEntries <= 0) return;
    if (this.entries.size >= this.maxEntries) this.evictOldest();
    this.entries.set(ip, {
      ip,
      firstObservedAt: observedAt,
      lastObservedAt: observedAt
    });
  }

  recordSuccess(value: string): void {
    const ip = canonicalIp(value);
    if (ip === null) return;
    const entry = this.entries.get(ip);
    if (entry) entry.lastSuccessAt = this.now();
  }

  recordFailure(value: string): void {
    const ip = canonicalIp(value);
    if (ip === null) return;
    const entry = this.entries.get(ip);
    if (entry) entry.lastFailureAt = this.now();
  }

  candidates(excluded: ReadonlySet<string> | readonly string[] = [], limit = 2): string[] {
    return this.candidateDetails(excluded, limit).candidates.map(candidate => candidate.ip);
  }

  /** Read-only bounded projection for transport evidence; it cannot mutate pool ranking. */
  candidateDetails(excluded: ReadonlySet<string> | readonly string[] = [],
    limit = 2): EdgePoolCandidates {
    const excludedCanonical = new Set<string>();
    for (const value of excluded) {
      const ip = canonicalIp(value);
      if (ip !== null) excludedCanonical.add(ip);
    }
    const now = this.now();
    const healthy: EdgeEntry[] = [];
    const unknown: EdgeEntry[] = [];
    const failed: EdgeEntry[] = [];

    for (const entry of this.entries.values()) {
      if (excludedCanonical.has(entry.ip)) continue;
      if (now - entry.lastObservedAt > this.staleThresholdMs) continue;
      if (entry.lastSuccessAt !== undefined &&
          (entry.lastFailureAt === undefined || entry.lastSuccessAt > entry.lastFailureAt)) {
        healthy.push(entry);
      } else if (entry.lastSuccessAt === undefined && entry.lastFailureAt === undefined) {
        unknown.push(entry);
      } else {
        failed.push(entry);
      }
    }

    healthy.sort((left, right) =>
      right.lastSuccessAt! - left.lastSuccessAt! || left.ip.localeCompare(right.ip));
    unknown.sort((left, right) =>
      right.lastObservedAt - left.lastObservedAt || left.ip.localeCompare(right.ip));
    failed.sort((left, right) =>
      left.lastFailureAt! - right.lastFailureAt! || left.ip.localeCompare(right.ip));

    const ranked = [
      ...healthy.map(entry => ({ ip: entry.ip, prior: 'healthy' as const })),
      ...unknown.map(entry => ({ ip: entry.ip, prior: 'unknown' as const })),
      ...failed.map(entry => ({ ip: entry.ip, prior: 'failed' as const }))
    ];
    return {
      poolSize: this.entries.size,
      totalCandidates: ranked.length,
      candidates: ranked.slice(0, Math.max(0, Math.min(2, limit)))
    };
  }

  size(): number {
    return this.entries.size;
  }

  getEntry(value: string): Readonly<EdgeEntry> | undefined {
    const ip = canonicalIp(value);
    return ip === null ? undefined : this.entries.get(ip);
  }

  private evictOldest(): void {
    let oldest: EdgeEntry | undefined;
    for (const entry of this.entries.values()) {
      if (oldest === undefined || entry.lastObservedAt < oldest.lastObservedAt ||
          (entry.lastObservedAt === oldest.lastObservedAt && entry.ip.localeCompare(oldest.ip) < 0)) {
        oldest = entry;
      }
    }
    if (oldest !== undefined) this.entries.delete(oldest.ip);
  }
}
