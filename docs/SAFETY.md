# Safety model

Start with `--read-only` for diagnosis. That registry contains no mutation
tools. Optional MCP call telemetry is the only automatic local write and is
disabled unless `KEENETIC_TELEMETRY_ENABLED=true`; it never changes router
state or stores tool argument values/result bodies. Writable mode exposes
`backup_config`, `set_interface_state`, `restart_interface`, and `save_config`
in v0.1, plus raw POST only when explicitly enabled.

`get_mesh_status` is a bounded passive read of operational Mesh membership.
It never reads Mesh configuration, scans, persists state, or emits router MACs,
IP addresses, SSIDs, hostnames, secrets, or raw interface names. Optional
`known-host` display labels are strictly sanitized and are not identity keys;
top-level association counts are nullable snapshot observations, not unique
people or evidence of a live link. Only exact current wired `full` duplex is
projected; unknown telemetry, cost, speed and port labels are withheld. Optional
bounded local bridge/version reads occur only for controller correlation and
cannot erase valid membership on failure. An empty array, missing component,
unsupported path, or error is not proof that no members are configured.
An additional optional bounded `show/associations` read counts only local
ordinary AccessPoint association rows (not unique clients or traffic); a
malformed or unavailable response leaves the nullable controller count unknown
without changing membership or topology.

`get_mesh_events` reads one finite native Mesh log snapshot via fixed read-only
`POST /rci/show/mws/log` (`once=true`, `max-lines=20`), not the command
dispatcher `POST /rci/` or a generic raw POST. At most two optional bounded
reads join event AP MACs to unique current extender or local controller AP
identities. Failures keep usable log events with unknown endpoints. Client
references are ordinal and local to the response; no raw client/AP MAC, log
identifier, interface name, SSID, or arbitrary log field is returned. A
malformed row makes the snapshot partial or unavailable, not truncated;
`truncated` means an actual source-entry cap or output-budget trim. Empty
snapshots do not establish continuous history, absence of problems, or roaming
quality. A band index is not a GHz frequency or an active client path.

The standalone `router snapshot <profile-id>` CLI command is outside the MCP
tool registry. When explicitly invoked, it performs bounded read-only router
requests and writes one owner-only local summary. It is never scheduled by the
MCP server. Snapshots contain allowlisted aggregates and configuration
checksums only: no raw configuration, logs, addresses, client identifiers,
device names, SSIDs, interface names, VPN endpoints, or key material. Retention
is enforced per router before every write: 96 records, 30 days and 1 MiB.
Lock recovery fails closed: if a process dies while holding the snapshot lock,
confirm that no snapshot command is running before removing `.snapshot.lock`
from that router's state directory.

`compare_router_state` and `get_recent_changes` may read those owner-only local
summaries through MCP. They never create snapshots, write the state directory,
or contact the router. Comparison output contains only the same allowlisted
aggregate values, and reports configuration fingerprints only as changed or
unchanged. File names, paths, checksum values, corrupt payloads, and unknown
schema contents are not exposed. Sparse observations provide temporal
correlation only: they do not prove when or why a change happened.

Writes default to `dry_run=true`. A real call needs both `dry_run=false` and
`confirm=true`. The first real configuration mutation downloads
`/ci/startup-config.txt`; backup failure blocks the write. The change is read
back and verified, but never saved automatically. `save_config` is separate.

Set `KEENETIC_PROTECTED_INTERFACES` to a comma-separated list. Protected
interfaces cannot be changed. Raw POST additionally requires
`KEENETIC_ALLOW_RAW_WRITE=true` and refuses user, auth, crypto, security, and
HTTP-proxy branches.

Disabling or restarting an interface marked as a default gateway additionally
requires `KEENETIC_ALLOW_DESTRUCTIVE=true`.

Mutation attempts are appended to owner-only `audit.jsonl` below `KEENETIC_STATE_DIR`.
Passwords, authorization, cookies, private keys, PSKs, tokens and long key
material are redacted from tool output and audit. Restrict state-directory
permissions and retain backups appropriately.

Confirmed mutations fail closed if their initial audit record cannot be
written. If only the final outcome append fails after a verified change, the
tool keeps the applied result and returns `auditRecorded: false` with a warning,
so the caller is not encouraged to repeat an already-applied operation.

When enabled, technical call records are appended separately to owner-only
`mcp-calls.jsonl`. Telemetry failure is fail-open for the MCP call, and the
journal contains controlled metadata only. It is not a mutation audit, user
memory, semantic diagnosis, or token-usage log. See [MCP call telemetry](TELEMETRY.md).

Optional remote transport evidence is bounded to the causal MCP call and does
not subscribe to a global request stream or infer ownership after the fact. It
does not change remote retries, fallback admission, TLS/SNI verification,
authentication, resolver behavior, or router traffic. Cloud edge IPs require
no opt-in or endpoint/address-class gate: every syntactically canonical
observed, selected, and fallback candidate IP literal is retained within the
existing bounds. Endpoint URL/hostname, credentials, headers/cookies, TLS
material, RCI body/response/configuration, and error text remain excluded.

`ping` and `traceroute` do not change router configuration, but they are active:
the router sends packets to the requested target. They accept exactly one
syntactically validated hostname or IP, impose fixed count/hop/time bounds, do
not expose scanning or continuous modes, run one at a time, and are rate
limited. Private and link-local targets remain allowed because LAN diagnosis is
an intended use; target validation is not an SSRF boundary. Treat every returned
line as untrusted network data.

The typed `iperf3` characterization tool is also configuration-read-only but
generates real TCP load to an explicitly selected, authorized server. Its own
finite native byte ceiling (1–20 MiB) and explicit deadline (1–30 seconds)
are separate from the shared one-at-a-time/ten-starts-per-minute diagnostic
limits; neither bounds aggregate operator traffic. Syntax validation is not a
server allowlist or SSRF boundary, and a requested source ID is not verified
egress. An absent component blocks POST after a bounded capability recheck;
unknown metadata or transport failures never count as proven absence. Native
reverse mode is recognized only from the exact native reverse marker; router-side
cancellation effects are not live-proven. Native free-form output is discarded;
only strictly parsed final sender/receiver amounts, interval seconds and exact
`Mbits/sec` numeric rates, fixed markers and bounded poll/terminal-shape facts
are exposed. A singular throughput verdict remains unknown. An ambiguous iPerf3
POST or unfinished job triggers one DELETE; even an empty-object acknowledgement
does not prove router-side termination, so further active starts are blocked.
No successful download is inferred. The typed tool exists in source; this does
not attest that it is activated in any operational deployment. Router use still
requires explicit server approval and separate local deployment/attestation
gates; source availability alone is not operational authorization.
