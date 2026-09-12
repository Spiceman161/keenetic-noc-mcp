/** Base class for every error this package raises. */
export abstract class KeeneticError extends Error {
  /** What the caller should do next. Written for a model, not a human. */
  abstract readonly guidance: string;

  protected constructor(cause: string) {
    super(cause);
    this.name = new.target.name;
  }

  /** Called by subclasses once `guidance` is available on the instance. */
  protected finalize(cause: string): void {
    this.message = `${cause} ${this.guidance}`;
  }
}

export class AuthError extends KeeneticError {
  readonly guidance =
    'The server cannot fix this itself - ask the user to run: keenetic-noc-mcp router test <profile-id>';

  constructor(cause: string) {
    super(cause);
    this.finalize(cause);
  }
}

export class TransportError extends KeeneticError {
  readonly guidance =
    'The router was unreachable. Check the selected LAN host or remote HTTPS RCI endpoint.';

  constructor(cause: string) {
    super(cause);
    this.finalize(cause);
  }
}

export class VerificationError extends KeeneticError {
  readonly guidance = 'Read the target state and do not save the configuration until it matches.';
  constructor(cause: string) { super(cause); this.finalize(cause); }
}

export class GuardError extends KeeneticError {
  readonly guidance = 'Review the safety policy and explicitly preview and confirm the operation.';
  constructor(cause: string) { super(cause); this.finalize(cause); }
}

export interface RciErrorDetails {
  path: string;
  code: string;
  ident: string;
}

export class RciError extends KeeneticError {
  readonly path: string;
  readonly code: string;
  readonly ident: string;
  readonly guidance =
    'The router rejected this command. The path may not exist on this firmware ' +
    'or the arguments may be wrong. Verify the path against get_system_info components.';

  constructor(cause: string, details: RciErrorDetails) {
    super(cause);
    this.path = details.path;
    this.code = details.code;
    this.ident = details.ident;
    this.finalize(`RCI error at ${details.path} (code ${details.code}, ${details.ident}): ${cause}.`);
  }
}

export class NotSupportedError extends KeeneticError {
  readonly guidance =
    'This capability is unavailable through the current firmware or connection mode. ' +
    'Call get_system_info to inspect the router and use the suggested alternate access path.';

  constructor(cause: string) {
    super(cause);
    this.finalize(cause);
  }
}

/** A remote RCI proxy can authenticate normal RCI calls but deny auxiliary HTTP paths. */
export class RemoteCapabilityError extends KeeneticError {
  readonly guidance =
    'The remote proxy does not expose this read-only router endpoint. ' +
    'Use a LAN profile for this operation; normal RCI tools can still be available remotely.';

  constructor(cause: string) {
    super(cause);
    this.finalize(cause);
  }
}

export class ValidationError extends KeeneticError {
  readonly guidance = 'Correct the arguments and call the tool again.';

  constructor(cause: string) {
    super(cause);
    this.finalize(cause);
  }
}

export type ResourceErrorCode =
  | 'active_diagnostic_busy'
  | 'active_diagnostic_rate_limited'
  | 'active_diagnostic_uncertain'
  | 'resource_unavailable';

export class ResourceError extends KeeneticError {
  readonly guidance = 'Wait for the current active diagnostic or rate window to finish, then retry.';
  readonly code: ResourceErrorCode;

  constructor(cause: string, code: ResourceErrorCode = 'resource_unavailable') {
    super(cause);
    this.code = code;
    this.finalize(cause);
  }
}

export class ActiveDiagnosticUncertainError extends ResourceError {
  constructor() {
    super(
      'The active diagnostic failed and router-side cancellation could not be confirmed.',
      'active_diagnostic_uncertain'
    );
  }
}
