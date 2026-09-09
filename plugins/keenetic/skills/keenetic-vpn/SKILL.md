---
name: keenetic-vpn
description: Inspect Keenetic VPN interfaces and peers without exposing secrets.
---

# Keenetic VPN diagnosis

1. Call `list_vpn` to compare tunnel state, link, address and uptime.
2. Call `get_vpn` for the affected interface and inspect peer endpoint,
   handshake and counters.
3. Compare routes and policies to distinguish tunnel health from traffic
   selection problems.
4. Correlate with bounded protocol-specific logs.
5. Never ask for or expose private keys, preshared keys, or passwords. v0.1 has
   no guessed VPN configuration writes.
