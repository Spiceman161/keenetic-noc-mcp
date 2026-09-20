import { fetchCapabilities, type Capabilities } from './capabilities.js';
import { Rci } from './rci.js';
import { Session, type SessionOptions } from './session.js';
import { RemoteSession, type RemoteSessionOptions } from './remote-session.js';
import {
  hasRecoverableCapabilityFailure,
  probeOperationalCapabilities,
  type ProbedCapabilities
} from './config-capabilities.js';

/** The seam the tool layer depends on. Tests substitute a plain object. */
export interface KeeneticClient {
  readonly rci: Rci;
  capabilities(): Promise<Capabilities>;
  probedCapabilities(): Promise<ProbedCapabilities>;
  /** Records only a successful measured read, never configuration content. */
  markRunningStructured?(method: 'rci-branch' | 'rci-root'): void;
}

function clientFor(rci: Rci, mode: 'lan' | 'remote'): KeeneticClient {
  // Cached as a promise, not a value, so concurrent first callers share one fetch.
  let pending: Promise<Capabilities> | null = null;
  let probedPending: Promise<ProbedCapabilities> | null = null;
  let runningStructured: ProbedCapabilities['config']['runningStructured'] = {
    state: 'unknown', method: null, reason: 'not-probed'
  };

  return {
    rci,
    capabilities(): Promise<Capabilities> {
      pending ??= fetchCapabilities(rci).catch(error => {
        pending = null;
        throw error;
      });
      return pending;
    },
    probedCapabilities(): Promise<ProbedCapabilities> {
      probedPending ??= (async () => {
        // Establish ordinary RCI access first. Remote 403 classification for the
        // candidate startup path depends on a prior successful RCI request.
        await this.capabilities();
        const result = await probeOperationalCapabilities(rci, mode);
        result.config.runningStructured = runningStructured;
        if (hasRecoverableCapabilityFailure(result)) probedPending = null;
        return result;
      })().catch(error => {
        probedPending = null;
        throw error;
      });
      return probedPending;
    },
    markRunningStructured(method): void {
      runningStructured = { state: 'available', method, reason: null };
      void probedPending?.then(result => { result.config.runningStructured = runningStructured; })
        .catch(() => undefined);
    }
  };
}

export function createClient(opts: SessionOptions): KeeneticClient {
  return clientFor(new Rci(new Session(opts)), 'lan');
}

export function createRemoteClient(opts: RemoteSessionOptions): KeeneticClient {
  return clientFor(new Rci(new RemoteSession(opts)), 'remote');
}
