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
is requested or materially useful, and only with an explicit server. Prefer a
user-controlled server. Reuse a server the user explicitly supplied or approved
earlier in this conversation when the test still matches that approval; if none
is known, ask for host:port. Use a public third-party server only with the
user's explicit approval for that active test. Never discover servers, keep a
public-server list, hard-code one, or silently substitute a server or port.
The current `server_port` range is 5201–5210; report an unsupported port.

Keep native `byte_limit_bytes` within 1–20 MiB. `timeout_ms` is a local hard
deadline of at most 30 seconds, not a requested test duration. A continuous
two-minute test is unavailable: offer one bounded byte-limited test instead;
never split a longer test into multiple calls to bypass per-call limits. Use
the direction requested; do not run upload and reverse automatically together.
If a throughput question leaves direction unspecified, start with one bounded
upload. Run reverse only for requested download/bidirectional characterization
or when specifically needed and its additional active load fits the user's
intent. `source_interface` requests native binding, not proof of physical
egress. Keep sender and receiver as separate native observations; never select
the larger value, average them, or claim a single true speed. Results apply
only to this server, path and time: do not infer WireGuard health, maximum
tunnel capacity, Internet health, server capacity or bottleneck cause.

If `component-not-installed` is reported, the user may manually install the
standard iPerf3 component in Keenetic Web UI (`General System Settings ->
KeeneticOS Update and Component Options -> Component options -> iPerf3`), then
recheck capability; never auto-install or bypass the component gate.
