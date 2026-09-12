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

`diagnose_internet` is the first composite read tool. It starts with a fresh
bounded version read; authentication or transport failure stops the call, while
an RCI-level version failure remains partial. It then gathers bounded core
sources sequentially and reads the heavier log source last. This avoids remote
KeenDNS requests starving each other while preserving partial results. The
first transport failure latches the remaining sources unavailable without more
requests, and an authentication failure remains fatal. An individual RCI-level
endpoint failure becomes an unavailable evidence slot and an unknown check
instead of discarding successful siblings. Findings are fixed rules over
explicit state; log text is returned only as bounded untrusted evidence and
cannot create findings. Input bounds are applied to both GET responses and the
known read-only `show log` dispatcher POST. Output trimming preserves checks and
findings before dropping logs, routes, interfaces, DNS upstreams, and VPN rows
in that order.
Remote composite diagnosis does not request `/ci/startup-config.txt`; it keeps
the saved-state comparison unknown without broadening the credentialed request
surface.

`diagnose_dns` follows the same sequential KeenDNS-safe collection model. It
keeps proxy runtime, internet reachability, the `dns-proxy` and
`ip/name-server` configuration branches, route/interface association, and log
context in independent evidence slots. The two configuration branches share a
256 KB ceiling and one failed branch cannot hide a successful sibling. The
known read-only log dispatcher has a 2 MB input ceiling and its 4000-row live
response is reduced to at most 20 matching DNS rows before output. Only an
explicit upstream IP or interface can be associated with routing; hostnames,
policy routing, and ambiguous equal-prefix routes remain unknown. Exact
resolver identifiers are allowlisted output, while endpoint credentials,
queries, fragments, provider-specific intermediate path tokens, and
secret-bearing fields are removed.

`diagnose_device` resolves one hotspot row before collecting any optional
evidence. Device lookup is shared by device and log tools, rejects normalized
ambiguity, and never exposes sibling rows in errors. Bounded DHCP, association,
interface, policy, and router-wide DNS reads are sequential; the large
read-only log dispatcher remains last. Secondary RCI or response-shape failures
produce unavailable evidence or explicit source-availability flags when the
hotspot still supplies useful data; authentication is fatal, and the first
transport failure latches later sources unavailable. DHCP and hotspot
rows are joined only by exact case-insensitive MAC. Wi-Fi metrics are reported
without health thresholds, policy membership is not treated as proof of the
active route, and log text cannot create findings. Output trimming removes
logs and optional context before identity, checks, or findings.

Wi-Fi diagnostics share a stricter topology projection. `diagnose_wifi` reads
fresh `show/version` (64 KB), then `show/interface` and `show/associations`
(256 KB each). Authentication is fatal; the first transport failure stops later
requests, while RCI and malformed-shape failures become unavailable source
evidence. `get_wifi_client_health` first performs the required bounded hotspot
resolution, then associations and interfaces with the same latch. Hotspot and
station rows join only by exact case-insensitive MAC; `station.ap` joins an AP
exactly, and its radio parent is accepted only for the confirmed anchored
`WifiMasterN/AccessPointN` ID form. Aggregate output suppresses client identity,
SSID and BSSID. Selected-client output keeps only its sanitized identity/SSID.
Central redaction and control stripping apply at the output boundary; budget
reduction removes optional AP/client metric detail before checks, findings,
totals, or selected identity. No band, utilization, retry, or event history is
derived from channel numbers, `busy-channels`, `_11`, or `roam`.

Configuration reads use a separate 256 KB input-bounded reader whose errors
never contain response bodies. CLI secrets are redacted before sectioning,
filtering, or literal search, and complete configuration documents are never
cached or audited. Running and startup source selection follows the measured
session capability; remote startup reads do not broaden LAN-only write backup.

Configuration diffing compares transient fingerprints of order-sensitive CLI
lines and renders only separately redacted lines. Only the generated saved MD5
header is ignored. A 10,000-line preprocessing ceiling and fixed LCS matrix
budget bound CPU and memory; the tool returns an explicit comparison-limit
result instead of approximate counts. Reads are bracketed by `show/last-change`
and discarded if the configuration moves during comparison. `get_config_state`
remains separate and does not invoke the diff path.

`save_config` is the sole tool that persists running configuration. Failure to
read startup configuration blocks the first real mutation unless the operator
explicitly enables the documented override. Concurrent first writes share the
same backup promise.

Read access to startup configuration and write-backup readiness are separate.
Remote RCI may expose saved configuration through `rci-more`, but the mutation
guard continues to require the LAN `/ci/startup-config.txt` backup path.

State snapshots are an explicit CLI workflow, not an MCP tool or background
task. The collector first establishes capabilities, then reads bounded sources
sequentially so remote KeenDNS sessions are not flooded. A later session
failure leaves a typed partial snapshot and latches remaining reads. Startup
configuration is held only long enough to parse its generated checksum.

The versioned snapshot schema persists only allowlisted aggregate state. Raw
logs, configuration lines, interface/client identifiers, addresses and
arbitrary router labels are excluded before serialization. Files live below
the platform state root in a path-safe per-router directory. Owner-only modes,
same-directory atomic rename, a cross-process lock, per-file bounds and
count/age/aggregate-byte retention apply to every write. Corrupt and unknown
schema files do not prevent valid history from being read, but still count
toward disk bounds. Profile removal deletes its snapshot directory without
following symlinks.

The MCP comparison tools receive a per-router snapshot reader through their
tool context; embedded or unconfigured contexts never fall back to an ambient
state directory. They compare an explicit allowlist of aggregate fields and do
not perform generic JSON diffs. Checksum equality is evaluated in memory but
the values are never returned. Duplicate timestamps are not ordered
arbitrarily, and uptime is used only to flag possible reboot or wall-clock
discontinuity. Reports describe differences between retained observations,
not continuous history or causality. Response shaping preserves the version,
selection, summary and truncation envelope before the global byte guard.

Active diagnostics use the separate finite `/rci/tools/*` continued-job
surface. One POST starts a native count/hop-bounded job, bounded GET polls read
message chunks, and DELETE cancels an unfinished job. The MCP cancellation
signal and a per-call deadline reach the HTTP transport, but native count and
hop limits remain the primary router-side termination guarantee. The whole-job
deadline is the smaller of the tool request and configured session timeout;
timeouts retain bounded partial chunks after native cancellation. A shared
coordinator permits one active job at a time and ten starts per rolling minute;
it rejects excess work rather than building a queue. Active start POSTs are
never transport-retried. On a cold remote session, a single-attempt read-only
version request discovers authentication before the active POST, so that POST
is never a shared authentication flight. A failed cancellation blocks new
active work until the MCP server process restarts because no router-side
duration is proven. Output is untrusted, redacted, control/format-stripped, and
bounded before reaching the global response ceiling.

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
