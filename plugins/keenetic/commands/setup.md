---
description: Guide a user through creating and registering a Keenetic router profile
---

The user wants to connect the Keenetic MCP server to their router.

Never ask for a password, endpoint credentials, or secret file path in chat.
Do not run a secret-bearing wizard for the user: it requires their local TTY.
Ask them to run this in their own terminal:

```
keenetic-noc-mcp router add
```

Explain that the wizard creates a named profile, validates LAN discovery or
remote DNS/TLS, generates a dedicated-user password, tests the credentials, and
shows a review before saving. It uses the system keychain automatically; if the
keychain is unavailable, it explains and asks permission for an owner-only file
fallback. For remote access, remind them to use a dedicated router user and a
KeenDNS HTTPS `/rci/` endpoint.

After it completes, have them run:

```
keenetic-noc-mcp router test <profile-id>
keenetic-noc-mcp router register <profile-id>
```

`router test` is read-only and reports connection, authentication, RCI, router,
internet, config-read, and backup capability. `router register` previews and
confirms the Codex or Claude registration, without placing a secret in agent
configuration.

If setup fails, ask them to share the non-secret error text only. A rejected
login means the dedicated router credentials were not accepted; an unreachable
router means the machine cannot reach the selected LAN address or remote RCI
endpoint. Do not ask them to paste a password as troubleshooting evidence.
