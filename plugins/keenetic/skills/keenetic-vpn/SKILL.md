---
name: keenetic-vpn
description: Inspect exactly classified Keenetic VPN interface observations and privacy-safe per-peer runtime evidence without exposing peer identity or configuration data.
---

# Keenetic VPN diagnosis

1. Call `list_vpn` to compare interface state, link, address and uptime.
2. Call `get_vpn` for the affected interface when the exact interface-level
   observations need confirmation.
3. Call `get_wireguard_status` for privacy-safe current WireGuard peer-runtime
   evidence. Its `peerIndex` is response-local only, handshake classification
   is field-presence evidence rather than time/freshness evidence, and RX/TX
   counters are current values of unknown lifetime with no rate or delta.
4. A selected default route establishes only a route association. Do not infer
   tunnel health, peer reachability, handshake freshness, encryption, role, or
   traffic flow from route, state, link, address, or uptime.
5. `diagnose_internet` omits all free-form router log items; use its log-source
   availability/count metadata only, never as peer evidence.
6. Never ask for or expose private keys, preshared keys, peer identifiers,
   endpoints, allowed IPs, raw peer objects, or passwords. Do not treat the
   safe runtime evidence as a health, Internet, reachability, or bidirectional
   traffic verdict. v0.1 has no guessed VPN configuration writes.

## Bounded path characterization

Start with the passive VPN/WireGuard observations above. To check whether
traffic passes through an interface, prefer a small IPv4 `ping` with
`source_interface`; do not use `iperf3` merely to prove reachability when ping
is sufficient. Use `iperf3` only when throughput/data-plane characterization
is explicitly requested (including a speed test) or materially useful, and only
with an explicitly approved reachable iPerf3 server and intended path. Use the
typed tool, not raw RCI or ping as a speed substitute. Prefer a
user-controlled server. Reuse a server the user explicitly supplied or approved
earlier in this conversation when the test still matches that approval; if none
is known, ask for host:port and approval; if the intended path is ambiguous,
clarify it before testing. Use a public third-party server only with the
user's explicit approval for that active test. Never discover servers, keep a
public-server list, hard-code one, or silently substitute a server or port.
The current `server_port` range is 5201–5210; report an unsupported port.

Keep native `byte_limit_bytes` within 1–20 MiB. `timeout_ms` is a local hard
deadline of 1–30 seconds, not a requested test duration or proof of router-side
termination. If unspecified, choose 1048576 bytes and 10000 ms for one
conservative call; these are operator choices, not tool defaults or a promised
duration/rate. Honor tighter valid user bounds; explain when a request falls
below the supported minimum. Neither per-call ceiling bounds aggregate traffic.
For a requested VPN path, get the exact interface ID from `list_interfaces` and
pass `source_interface`; if no exact ID can be identified, do not run unbound
and call the result VPN performance. A continuous
two-minute test is unavailable: offer one bounded byte-limited test instead;
never split a longer test into multiple calls to bypass per-call limits. Use
the direction requested; do not run upload and reverse automatically together.
If a throughput question leaves direction unspecified, choose one bounded
upload (the tool still requires `direction`). Do not turn a bidirectional request
into automatic sequential calls. Reverse requests server-to-router traffic;
only an exact native reverse marker confirms `actualDirection`. `source_interface`
requests native binding, not proof of physical egress. Interpret `status` and
`termination` as lifecycle evidence, not speed success; keep
`nativeRoleObservations` sender and receiver as separate observations and
`throughput: unknown`. Never select
the larger value, average them, or claim a single true speed. Results apply
only to this server, path and time: do not infer WireGuard health, maximum
tunnel capacity, Internet health, server capacity or bottleneck cause.

For explicitly requested throughput across multiple WireGuard/VPN interfaces,
test interfaces sequentially, never in parallel. Before each interface's
`iperf3`, send exactly one small IPv4 `ping` (count 1) to the same authorized
iPerf3 server host with that exact `source_interface`. If this source ping
does not establish reachability, mark that interface not characterized by
iPerf3 and skip its iPerf3 call; continue to the next interface only if no
active diagnostic has uncertain router-side state. A successful ping is only
a preflight, not proof of physical egress, WireGuard health, or expected
throughput. For each completed iPerf3 call, `throughput: unknown` is not a
claim that there is no useful speed evidence: inspect `nativeRoleObservations`
and report observed `sender` and `receiver` `bitrateMbps` separately when
present, without inventing missing rates or a single true speed. Retain the
one-call 1048576-byte/10000-ms conservative choice per interface; no larger
traffic, parallel calls, retries, or automatic server selection.

If `component-not-installed` is reported, the user may manually install the
standard iPerf3 component in Keenetic Web UI (`General System Settings ->
KeeneticOS Update and Component Options -> Component options -> iPerf3`), then
recheck capability; never auto-install or bypass the component gate.
On timeout or error, explain the outcome and do not automatically retry or bypass
the shared active-job coordinator. On `active_diagnostic_uncertain`,
`routerTermination: unknown`, or equivalent uncertain cancellation, stop all
further active diagnostics immediately, including pings for remaining
interfaces. Do not use routes, WireGuard counters, logs, or broad
`show/processes` as indirect proof of termination. Without an exact documented
termination check, return the partial report and require operator intervention
or runtime restart only under the existing documented policy; never assume
DELETE acknowledgement or a successful preflight clears uncertain state.
