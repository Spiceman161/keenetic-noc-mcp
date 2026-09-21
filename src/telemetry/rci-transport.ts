import { AsyncLocalStorage } from 'node:async_hooks';
import { canonicalIp } from '../router/edge-pool.js';

export type RciTransportApplicability = 'remote' | 'not_applicable' | 'unknown';
export type TerminalReason = 'normal_response' | 'fallback_recovered' |
  'fallback_exhausted' | 'fallback_no_candidates' | 'fallback_replay_unsafe' |
  'fallback_correlation_incomplete' | 'cancelled' | 'deadline_exceeded' | 'transport_failure';
export type FallbackOutcome = 'recovered' | 'exhausted' | 'no_candidates' |
  'cancelled' | 'deadline_exceeded';
export type EdgeHealth = 'healthy' | 'unknown' | 'failed';

export interface RciTransportSnapshot {
  applicability: RciTransportApplicability;
  remote_requests: number | null;
  shared_auth_waits: number | null;
  normal_attempts: number | null;
  fallback_considered: number | null;
  fallback_activations: number | null;
  fallback_attempts: number | null;
  fallback_recoveries: number | null;
  fallback_exhaustions: number | null;
  correlation_complete: boolean | null;
  finalized_after_handler: boolean | null;
  observed_edge_ips: string[] | null;
  selected_normal_edge_ips: string[] | null;
  edge_ips_truncated: boolean | null;
  terminal_reasons: Record<TerminalReason, number> | null;
  fallback_events: RciFallbackEvent[] | null;
  fallback_events_total: number | null;
  fallback_events_truncated: boolean | null;
}

export interface RciFallbackCandidate {
  edge_ip: string | null;
  prior: EdgeHealth;
  attempted: boolean;
  outcome: 'recovered' | 'failed' | null;
}

export interface RciFallbackEvent {
  pool_size: number;
  total_candidates: number;
  candidates: RciFallbackCandidate[];
  outcome: FallbackOutcome;
}

export interface RciTransportCollectorOptions {
  connection?: { mode: 'lan' | 'remote'; endpoint?: string };
}

export interface FallbackCandidateInput {
  ip: string;
  prior: EdgeHealth;
}

export interface RciTransportOperation {
  normalAttempt(): void;
  observedEdge(ip: string): void;
  selectedNormalEdge(ip: string): void;
  correlationComplete(complete: boolean): void;
  fallbackConsidered(): void;
  fallbackReplayUnsafe(): void;
  fallbackCorrelationIncomplete(): void;
  beginFallback(poolSize: number, totalCandidates: number,
    candidates: readonly FallbackCandidateInput[]): RciFallbackEventHandle;
  terminal(reason: TerminalReason): void;
  acquireLease(): () => void;
}

export interface RciFallbackEventHandle {
  attempted(candidateIndex: number): void;
  outcome(candidateIndex: number, outcome: 'recovered' | 'failed'): void;
  finish(outcome: FallbackOutcome): void;
}

const MAX_EDGE_IPS = 16;
const MAX_FALLBACK_EVENTS = 8;
const MAX_EVENT_CANDIDATES = 2;
const terminals: readonly TerminalReason[] = [
  'normal_response', 'fallback_recovered', 'fallback_exhausted', 'fallback_no_candidates',
  'fallback_replay_unsafe', 'fallback_correlation_incomplete', 'cancelled',
  'deadline_exceeded', 'transport_failure'
];

const storage = new AsyncLocalStorage<RciTransportCollector>();

function zeroTerminals(): Record<TerminalReason, number> {
  return Object.fromEntries(terminals.map(reason => [reason, 0])) as Record<TerminalReason, number>;
}

function copyEvent(event: RciFallbackEvent): RciFallbackEvent {
  return {
    pool_size: event.pool_size,
    total_candidates: event.total_candidates,
    candidates: event.candidates.map(candidate => ({ ...candidate })),
    outcome: event.outcome
  };
}

/**
 * This is deliberately a call-local collector, not a transport observer. The
 * RemoteSession passes its already-correlated attempt evidence directly to an
 * operation acquired at request entry, so late Undici events cannot join a
 * different MCP call.
 */
export class RciTransportCollector {
  private readonly applicability: RciTransportApplicability;
  private sealed = false;
  private leases = 0;
  private delayedResolver: ((snapshot: RciTransportSnapshot) => void) | undefined;
  private remoteRequests = 0;
  private sharedAuthWaits = 0;
  private normalAttempts = 0;
  private fallbackConsideredCount = 0;
  private fallbackActivations = 0;
  private fallbackAttempts = 0;
  private fallbackRecoveries = 0;
  private fallbackExhaustions = 0;
  private correlationComplete = true;
  private readonly observed = new Set<string>();
  private readonly selected = new Set<string>();
  private edgeIpsTruncated = false;
  private readonly terminalReasons = zeroTerminals();
  private readonly fallbackEvents: RciFallbackEvent[] = [];
  private fallbackEventsTotal = 0;

  constructor(options: RciTransportCollectorOptions = {}) {
    const mode = options.connection?.mode;
    this.applicability = mode === 'remote' ? 'remote' : mode === 'lan' ? 'not_applicable' : 'unknown';
  }

  beginOperation(): RciTransportOperation | undefined {
    if (this.sealed || this.applicability !== 'remote') return undefined;
    this.remoteRequests += 1;
    let terminalRecorded = false;
    const terminal = (reason: TerminalReason): void => {
      if (terminalRecorded) return;
      terminalRecorded = true;
      this.terminal(reason);
    };
    return {
      normalAttempt: () => { this.normalAttempts += 1; },
      observedEdge: ip => this.addIp(this.observed, ip),
      selectedNormalEdge: ip => this.addIp(this.selected, ip),
      correlationComplete: complete => { this.correlationComplete &&= complete; },
      fallbackConsidered: () => { this.fallbackConsideredCount += 1; },
      fallbackReplayUnsafe: () => terminal('fallback_replay_unsafe'),
      fallbackCorrelationIncomplete: () => terminal('fallback_correlation_incomplete'),
      beginFallback: (poolSize, totalCandidates, candidates) => this.beginFallback(
        poolSize, totalCandidates, candidates
      ),
      terminal,
      acquireLease: () => this.acquireLease()
    };
  }

  sharedAuthWait(): void {
    if (!this.sealed && this.applicability === 'remote') this.sharedAuthWaits += 1;
  }

  seal(): RciTransportSnapshot | Promise<RciTransportSnapshot> {
    this.sealed = true;
    if (this.leases === 0) return this.snapshot(false);
    return new Promise(resolve => { this.delayedResolver = resolve; });
  }

  private addIp(target: Set<string>, value: string): void {
    try {
      const ip = canonicalIp(value);
      if (ip === null || target.has(ip)) return;
      if (target.size >= MAX_EDGE_IPS) {
        this.edgeIpsTruncated = true;
        return;
      }
      target.add(ip);
    } catch {
      // Telemetry is never allowed to affect the causal transport operation.
    }
  }

  private beginFallback(poolSize: number, totalCandidates: number,
    candidates: readonly FallbackCandidateInput[]): RciFallbackEventHandle {
    this.fallbackActivations += candidates.length > 0 ? 1 : 0;
    this.fallbackEventsTotal += 1;
    const captured: RciFallbackCandidate[] = candidates.slice(0, MAX_EVENT_CANDIDATES).map(candidate => ({
      edge_ip: this.safeIp(candidate.ip),
      prior: candidate.prior,
      attempted: false,
      outcome: null
    }));
    const event: RciFallbackEvent = {
      pool_size: Math.max(0, Math.floor(poolSize)),
      total_candidates: Math.max(0, Math.floor(totalCandidates)),
      candidates: captured,
      outcome: candidates.length === 0 ? 'no_candidates' : 'exhausted'
    };
    const stored = this.fallbackEvents.length < MAX_FALLBACK_EVENTS ? event : undefined;
    if (stored !== undefined) this.fallbackEvents.push(stored);
    return {
      attempted: candidateIndex => {
        this.fallbackAttempts += 1;
        const candidate = stored?.candidates[candidateIndex];
        if (candidate !== undefined) {
          candidate.attempted = true;
        }
      },
      outcome: (candidateIndex, outcome) => {
        const candidate = stored?.candidates[candidateIndex];
        if (candidate !== undefined) {
          candidate.outcome = outcome;
        }
      },
      finish: outcome => {
        if (stored !== undefined) stored.outcome = outcome;
        if (outcome === 'recovered') this.fallbackRecoveries += 1;
        if (outcome === 'exhausted') this.fallbackExhaustions += 1;
      }
    };
  }

  private safeIp(value: string): string | null {
    try { return canonicalIp(value); } catch { return null; }
  }

  private terminal(reason: TerminalReason): void {
    this.terminalReasons[reason] += 1;
  }

  private acquireLease(): () => void {
    this.leases += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.leases -= 1;
      if (this.sealed && this.leases === 0 && this.delayedResolver !== undefined) {
        const resolve = this.delayedResolver;
        this.delayedResolver = undefined;
        resolve(this.snapshot(true));
      }
    };
  }

  private snapshot(finalizedAfterHandler: boolean): RciTransportSnapshot {
    if (this.applicability !== 'remote') {
      return {
        applicability: this.applicability,
        remote_requests: null, shared_auth_waits: null, normal_attempts: null,
        fallback_considered: null, fallback_activations: null, fallback_attempts: null,
        fallback_recoveries: null, fallback_exhaustions: null, correlation_complete: null,
        finalized_after_handler: null, observed_edge_ips: null, selected_normal_edge_ips: null,
        edge_ips_truncated: null, terminal_reasons: null, fallback_events: null,
        fallback_events_total: null, fallback_events_truncated: null
      };
    }
    return {
      applicability: 'remote',
      remote_requests: this.remoteRequests,
      shared_auth_waits: this.sharedAuthWaits,
      normal_attempts: this.normalAttempts,
      fallback_considered: this.fallbackConsideredCount,
      fallback_activations: this.fallbackActivations,
      fallback_attempts: this.fallbackAttempts,
      fallback_recoveries: this.fallbackRecoveries,
      fallback_exhaustions: this.fallbackExhaustions,
      correlation_complete: this.normalAttempts === 0 ? null : this.correlationComplete,
      finalized_after_handler: finalizedAfterHandler,
      observed_edge_ips: [...this.observed],
      selected_normal_edge_ips: [...this.selected],
      edge_ips_truncated: this.edgeIpsTruncated,
      terminal_reasons: { ...this.terminalReasons },
      fallback_events: this.fallbackEvents.map(copyEvent),
      fallback_events_total: this.fallbackEventsTotal,
      fallback_events_truncated: this.fallbackEventsTotal > MAX_FALLBACK_EVENTS
    };
  }
}

export function runWithRciTransportCollector<T>(collector: RciTransportCollector,
  callback: () => T): T {
  return storage.run(collector, callback);
}

export function currentRciTransportCollector(): RciTransportCollector | undefined {
  return storage.getStore();
}
