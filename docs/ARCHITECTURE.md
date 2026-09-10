# Architecture

## Decisions

`keenetic-noc-mcp` is a Node.js 20+ TypeScript stdio MCP server. The process
loads one `RouterConnectionProfile`, creates one transport, then exposes a
capability-aware tool registry.

```text
MCP stdio -> tool registry -> projections / mutation orchestrator -> RCI client
                                                               -> LAN session
                                                               -> remote HTTP auth transport
```

The tool layer depends on an RCI client interface, not on either authentication
mechanism. LAN mode keeps `/auth` challenge-response and cookie sessions. Remote
mode sends requests to a normalized `https://.../rci/` URL and responds to
Digest or Basic challenges without putting credentials in URLs. Normal traffic
always uses Node's default TLS verification.

Static hardware/software capabilities come from `show/version`. Operational
configuration capabilities are measured separately with bounded, metadata-only
reads and cached only for the lifetime of the client. Concurrent first callers
share the same probe. Authentication and transport failures are never cached,
and every probe still passes through normal session re-authentication. The
cache contains only state, access method, and safe reason enums - never
configuration content or router error text.

Read tools project large, unstable RCI trees into bounded stable results. Raw GET
is a bounded escape hatch. Mutations use a common safety service and are never
saved implicitly:

```text
guard -> startup-config backup once -> apply -> read back -> verify -> audit
```

Configuration reads use a separate 256 KB input-bounded reader whose errors
never contain response bodies. CLI secrets are redacted before sectioning,
filtering, or literal search, and complete configuration documents are never
cached or audited. Running and startup source selection follows the measured
session capability; remote startup reads do not broaden LAN-only write backup.

`save_config` is the sole tool that persists running configuration. Failure to
read startup configuration blocks the first real mutation unless the operator
explicitly enables the documented override. Concurrent first writes share the
same backup promise.

Read access to startup configuration and write-backup readiness are separate.
Remote RCI may expose saved configuration through `rci-more`, but the mutation
guard continues to require the LAN `/ci/startup-config.txt` backup path.

## Error boundary

- `AuthError`: HTTP 401/403 or rejected LAN credentials; never retried.
- `TransportError`: timeout and transient DNS/TCP/TLS failures; bounded retry.
- `RciError`: HTTP/application payload or deterministic RCI status failure.
- `VerificationError`: successful request whose read-back does not match.
- `GuardError`: read-only, confirmation, protected-object or policy refusal.

Every externally visible error is redacted and names router ID, operation,
endpoint hostname and failure class. Secrets and complete configurations never
enter diagnostics or audit records.

## Conservative choices

- Remote mode requires HTTPS; normalization changes only the path/trailing slash,
  never scheme or hostname.
- Digest is preferred when both challenges are offered. Basic is not sent
  pre-emptively.
- Raw POST is omitted unless both server write mode and
  `KEENETIC_ALLOW_RAW_WRITE=true` permit it. A conservative denylist still
  rejects auth, crypto and management-channel payloads.
- Log timestamps are preserved as supplied. They are not treated as trustworthy
  ordering evidence around boot/NTP synchronization.
- No v0.1 implementation guesses VPN write syntax.
