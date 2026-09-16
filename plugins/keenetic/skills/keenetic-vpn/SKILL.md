---
name: keenetic-vpn
description: Inspect exactly classified Keenetic VPN interface observations without exposing peer data.
---

# Keenetic VPN diagnosis

1. Call `list_vpn` to compare interface state, link, address and uptime.
2. Call `get_vpn` for the affected interface when the exact interface-level
   observations need confirmation.
3. A selected default route establishes only a route association. Do not infer
   tunnel health, peer reachability, handshake freshness, encryption, role, or
   traffic flow from route, state, link, address, or uptime.
4. Do not use protocol-specific VPN log lines: diagnostic output omits them.
5. Never ask for or expose private keys, preshared keys, peer endpoints,
   handshakes, counters, or passwords. v0.1 has
   no guessed VPN configuration writes.
