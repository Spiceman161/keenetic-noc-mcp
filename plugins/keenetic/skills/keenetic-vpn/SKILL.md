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

Start with the passive VPN/WireGuard observations above; if packet flow needs
testing, use a small IPv4 `ping` with `source_interface` before considering
throughput. Only for a specific diagnostic question and a user-authorized
server and load, consider the provisional typed `iperf3` Stage A operation:
it can generate active TCP load with a finite native byte cap (1-20 MiB) and a
local deadline (1-30 seconds). A requested `source_interface` is not proof of
actual egress. If `component-not-installed` is reported, the user may manually
install the standard iPerf3 component in Keenetic Web UI (`General System
Settings -> KeeneticOS Update and Component Options -> Component options ->
iPerf3`), then recheck capability; never auto-install or bypass the gate.
Reverse transfer semantics, native output units, and the router-side effect
of DELETE remain uncharacterized. Do not infer speed or tunnel/Internet health
from a result, ping, or handshake. Do not activate or use this local candidate
in production without separately authorized operational activation.
