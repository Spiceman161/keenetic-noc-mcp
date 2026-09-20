export interface EdgeEntry {
  readonly ip: string;
  readonly firstSeen: number;
  lastSeen: number;
  lastSuccess?: number;
  lastFailure?: number;
}

export interface EdgePoolOptions {
  now?: () => number;
  maxEntries?: number;
  staleThresholdMs?: number;
}

const DEFAULT_MAX_ENTRIES = 10;
const DEFAULT_STALE_THRESHOLD_MS = 2 * 60 * 60 * 1000; // 2 hours

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

  observe(ip: string): void {
    const timestamp = this.now();
    const existing = this.entries.get(ip);
    if (existing) {
      existing.lastSeen = timestamp;
      return;
    }

    if (this.entries.size >= this.maxEntries) {
      this.evictOldest();
    }

    this.entries.set(ip, {
      ip,
      firstSeen: timestamp,
      lastSeen: timestamp
    });
  }

  recordSuccess(ip: string): void {
    const timestamp = this.now();
    let entry = this.entries.get(ip);
    if (!entry) {
      this.observe(ip);
      entry = this.entries.get(ip);
    }
    if (entry) {
      entry.lastSuccess = timestamp;
      entry.lastSeen = timestamp;
    }
  }

  recordFailure(ip: string): void {
    const timestamp = this.now();
    let entry = this.entries.get(ip);
    if (!entry) {
      this.observe(ip);
      entry = this.entries.get(ip);
    }
    if (entry) {
      entry.lastFailure = timestamp;
      entry.lastSeen = timestamp;
    }
  }

  candidates(exclude?: ReadonlySet<string> | readonly string[], limit = 2): string[] {
    const excludeSet = exclude instanceof Set ? exclude : new Set(exclude ?? []);
    const currentTime = this.now();

    const eligible: EdgeEntry[] = [];
    for (const entry of this.entries.values()) {
      if (excludeSet.has(entry.ip)) continue;
      if (currentTime - entry.lastSeen > this.staleThresholdMs) continue;
      eligible.push(entry);
    }

    // Tier 1 (Recent success): lastSuccess > lastFailure, or lastSuccess present with no failure.
    // Tier 2 (Unknown / untried): neither lastSuccess nor lastFailure.
    // Tier 3 (Recent failure): lastFailure >= lastSuccess, or lastFailure present with no success.
    const tier1: EdgeEntry[] = [];
    const tier2: EdgeEntry[] = [];
    const tier3: EdgeEntry[] = [];

    for (const entry of eligible) {
      const hasSuccess = entry.lastSuccess !== undefined;
      const hasFailure = entry.lastFailure !== undefined;

      if (hasSuccess && (!hasFailure || entry.lastSuccess! > entry.lastFailure!)) {
        tier1.push(entry);
      } else if (!hasSuccess && !hasFailure) {
        tier2.push(entry);
      } else {
        tier3.push(entry);
      }
    }

    tier1.sort((a, b) => {
      const diff = b.lastSuccess! - a.lastSuccess!;
      if (diff !== 0) return diff;
      return a.ip.localeCompare(b.ip);
    });

    tier2.sort((a, b) => {
      const diff = b.lastSeen - a.lastSeen;
      if (diff !== 0) return diff;
      return a.ip.localeCompare(b.ip);
    });

    tier3.sort((a, b) => {
      const diff = a.lastFailure! - b.lastFailure!;
      if (diff !== 0) return diff;
      return a.ip.localeCompare(b.ip);
    });

    return [...tier1, ...tier2, ...tier3].slice(0, Math.max(0, limit)).map(e => e.ip);
  }

  size(): number {
    return this.entries.size;
  }

  getEntry(ip: string): Readonly<EdgeEntry> | undefined {
    return this.entries.get(ip);
  }

  private evictOldest(): void {
    let oldest: EdgeEntry | null = null;
    for (const entry of this.entries.values()) {
      if (!oldest || entry.lastSeen < oldest.lastSeen ||
          (entry.lastSeen === oldest.lastSeen && entry.ip.localeCompare(oldest.ip) < 0)) {
        oldest = entry;
      }
    }
    if (oldest) {
      this.entries.delete(oldest.ip);
    }
  }
}
