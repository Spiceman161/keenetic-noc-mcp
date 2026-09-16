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
