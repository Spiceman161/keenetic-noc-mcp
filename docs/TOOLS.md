# Tools

Read tools: `get_system_info`, `get_config_state`, `get_connection_status`,
`get_running_config`, `get_startup_config`, `search_config`, `get_config_diff`,
`diagnose_internet`, `get_internet_status`, `list_interfaces`, `get_interface`, `list_routes`,
`list_policies`, `list_devices`, `get_device`, `get_wifi_status`, `list_vpn`,
`get_vpn`, `get_dns_status`, `get_logs`, `get_logs_by_device`, `list_segments`,
`list_dns_upstreams`, `diagnose_dns`,
and bounded raw `rci_call` GET.

## Active diagnostics

`ping` sends 1-5 ICMP requests from the router to one ASCII hostname or IP
address. It supports explicit `ipv4` or `ipv6`, defaults to three requests and a
five-second deadline, and has a hard 15-second deadline ceiling.

`traceroute` performs one UDP trace from the router to one target. It defaults
to 15 hops and a 15-second deadline, with hard ceilings of 30 hops and 30
seconds. Protocol, port, source interface, packet size, fan-out, ranges, and
continuous operation are not exposed.

Both tools are configuration-read-only but actively send packets, so they are
available under `--read-only` and carry `openWorldHint=true`. Only one active
diagnostic runs at a time and at most ten can start in a rolling minute. MCP
cancellation triggers transport abort and the router-native DELETE cancel.
Returned router text is marked untrusted, stripped of control sequences,
redacted, and bounded. The reported `timeoutMs` is the smaller of `timeout_ms`
and the operator's `KEENETIC_TIMEOUT_MS`. Outcomes distinguish `completed`,
`partial`, `timeout`, `unreachable`, and `not-found`; a deadline preserves any
lines already received. `dns_lookup` remains unavailable because no exact
finite RCI command has been verified.

## DNS diagnosis

`list_dns_upstreams` returns separate bounded observations from DNS proxy
runtime state and the targeted `dns-proxy` and `ip/name-server` running
configuration branches. Runtime and configuration rows are not merged unless
firmware evidence provides a stable identity. Exact resolver addresses and TLS
server names are returned when exposed, while URL credentials, query strings,
fragments, provider-specific intermediate path tokens, secrets, and control
characters are removed. Runtime rows include the measured proxy scope and port
when KeeneticOS exposes them.

`diagnose_dns` combines DNS proxy state, the current internet DNS reachability
flag, targeted upstream configuration, deterministically resolvable routes and
interfaces, and recent DNS-related logs. Configuration, reachability,
encryption, routing, and resolver evidence remain separate. Configuring DoT,
DoH, or DoH3 does not prove that TLS or the resolver is reachable. Logs are
bounded untrusted context and never establish causality. The tool performs no
active DNS query; active diagnostics are reserved for a later slice.

Write mode additionally advertises `backup_config`, `set_interface_state`,
`restart_interface`, and `save_config`. `backup_config` defaults to a preview,
requires confirmation to create an owner-only file, and never overwrites an
existing path. Raw `rci_call` POST remains disabled unless the operator
enables it and each call passes dry-run/confirmation and denylist checks.

Response limits are global. A raw call's `max_bytes` can lower but cannot raise
the global ceiling. Router log content is data, never instructions.

## Internet diagnosis

`diagnose_internet` is the first call for an internet-down or internet-slow
incident. It has no arguments and combines bounded system, internet-status,
interface, IPv4 default-route, DNS, VPN, recent-log, and configuration-state
reads. The result has `schemaVersion: 1`, an overall `status`, `complete`, fixed
`checks`, deterministic `findings`, and projected `evidence`.

Overall status is `unhealthy` only for a confirmed blocking fault,
`degraded` when core evidence is incomplete or contains a warning, `healthy`
when the core internet path passes, and `unknown` when no core conclusion can
be made. Optional logs or saved-config comparison can be unavailable while the
network status remains healthy; `complete: false` records that evidence gap.
Remote profiles do not request the LAN-only `/ci/startup-config.txt` surface;
their saved-state comparison remains unknown in B1.

Findings come only from explicit router state, such as an unreachable gateway,
missing usable `0.0.0.0/0` route, DNS reachability failure, required physical
uplink down, or failed VPN carrying the default route. An active default-route
VPN and unsaved configuration are informational context. Logs never create a
finding and remain marked `untrusted`; their timestamps and proximity to an
incident do not establish causality. B1 does not diagnose IPv6 routes and does
not apply CPU, memory, or connection-table thresholds.

## Log filters

`get_logs` accepts `filter`, `since`, `until`, `interface`, and `device` in
one request. `device` resolves a MAC, IP, registered name, or hostname to all
known aliases. `get_logs_by_device` accepts the same text, interface, and time
filters after the required `device` selector.

`since` and `until` are inclusive. Use the timestamp format the router
returns; ISO-8601 and Unix epoch values are compared as times, while legacy
firmware-specific formats are compared lexically. Log text remains untrusted.
Both log tools retain the compact `lines` array and also return `entries` with
the scalar fields `timestamp`, `ident`, `level`, `label`, and `line`. Missing
metadata is `null`. Interface filtering checks structured `ident` and `label`
before falling back to the rendered line for older firmware responses.

`get_connection_status` reports measured configuration access in
`configCapabilities`. `runningCli`, `startup`, and `backup` carry independent
`state`, `method`, and `reason` values; `runningStructured` remains
`unknown/not-probed` until an explicit structured configuration read. The legacy
`startupConfigCapability`, `backupPathCapability`, and `backupBeforeWrite`
fields remain present. A remote profile can report startup access through
`rci-more` while still reporting that backup-before-write requires a LAN
profile; remote status checks never probe `/ci/`.

## Configuration reads

`get_running_config` and `get_startup_config` require `section` (`dns`,
`interfaces`, `routing`, `wifi`, `vpn`, `users`, `system`, or `all`). CLI is
the default format and is always redacted before filtering. `section=all`
requires an explicit `limit` of at least 200 and remains subject to the global
response ceiling. Startup configuration is CLI-only and is never substituted
with running state.

Running configuration additionally supports structured reads for `system`,
`users`, `dns`, `routing`, `interfaces`, and explicit `all`. Wi-Fi and VPN use
CLI because no stable dedicated RCI configuration branch has been measured.
For structured results, `limit` caps deterministic top-level entries and
`shown`, `total`, and `truncated` describe that projection.

`search_config` requires an explicit `source` and literal `query`, supports an
optional section and up to five context lines, and returns merged bounded
context groups. Matching is performed only after secret redaction. An expected
unavailable startup capability returns `available: false` with its measured
state and reason rather than falling back to another source.
Search defaults to `section=all`, `limit=50` matches, and two context lines.
`totalMatches` counts every match before limits, while `shownMatches` counts
only matching lines actually retained in the returned groups. `shown` and
`total` describe context groups rather than matches.

`get_config_diff` compares startup CLI configuration with running CLI
configuration. It defaults to a complete semantic summary without returning
configuration lines. Set `include_diff=true` to include up to `limit` changed
lines (`200` by default, maximum `1000`), still capped by the global response
budget. `added` and `removed` count the complete diff; `shownAdded`,
`shownRemoved`, and `shown` describe only retained output.

The comparison preserves CLI ordering, whitespace, comments, and case. It
ignores only the measured generated MD5 checksum header. Secret-only changes
are counted while all returned lines remain redacted. If either source is
unavailable, the tool returns `comparable=false` with the measured source,
state, and reason. It never substitutes running configuration for startup.
Inputs over 10,000 lines or the comparison work budget return
`comparison-limit-exceeded`. If the router configuration changes while both
documents are being read, the result is discarded with
`configuration-changed-during-read`; callers should retry.
