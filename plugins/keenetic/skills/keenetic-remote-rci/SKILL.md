---
name: keenetic-remote-rci
description: Diagnose a Keenetic connection through a KeenDNS HTTPS RCI proxy.
---

# Remote RCI

1. Call `get_connection_status`; never request credentials in chat.
2. Separate DNS/TCP/TLS transport failures from HTTP 401/403 authentication
   failures and from RCI payload errors.
3. Confirm the endpoint is HTTPS and ends in `/rci/`; the Web application must
   proxy authorized HTTP to local port 79.
4. Use narrow read tools to validate access. Do not use raw POST as a probe.
5. If backup capability has not been verified, test it read-only before any
   proposed configuration change.
