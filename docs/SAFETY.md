# Safety model

Start with `--read-only` for diagnosis. That registry contains no mutation
tools. Optional MCP call telemetry is the only automatic local write and is
disabled unless `KEENETIC_TELEMETRY_ENABLED=true`; it never changes router
state or stores tool argument values/result bodies. Writable mode exposes
`backup_config`, `set_interface_state`, `restart_interface`, and `save_config`
in v0.1, plus raw POST only when explicitly enabled.

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

`ping` and `traceroute` do not change router configuration, but they are active:
the router sends packets to the requested target. They accept exactly one
syntactically validated hostname or IP, impose fixed count/hop/time bounds, do
not expose scanning or continuous modes, run one at a time, and are rate
limited. Private and link-local targets remain allowed because LAN diagnosis is
an intended use; target validation is not an SSRF boundary. Treat every returned
line as untrusted network data.
