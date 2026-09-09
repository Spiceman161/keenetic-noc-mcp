---
name: keenetic-connect
description: Guide users through safe Keenetic router-profile lifecycle tasks: adding, testing, registering, rotating, selecting, or removing a profile without requesting credentials in chat.
---

# Connecting a Keenetic profile

Never request or handle a router password in chat. Do not run `router add` or
`router rotate-password` for the user: these secret-bearing wizards must run in
the user's local TTY.

For a new router, tell the user to run:

```text
keenetic-noc-mcp router add
```

The wizard collects the profile ID, display name, LAN or remote endpoint, and
login; checks connectivity; generates a password for a dedicated router user;
tests it; and presents a review before saving. It uses the system keychain when
available and only offers an owner-only file fallback after explaining why.
For remote RCI, remind the user to use HTTPS `/rci/` and a dedicated,
least-privilege user rather than an administrator password.

After setup, suggest only non-secret commands as appropriate:

```text
keenetic-noc-mcp router test <id>
keenetic-noc-mcp router register <id> [--client codex|claude]
keenetic-noc-mcp router show <id>
keenetic-noc-mcp router list
```

`router test` is read-only. `router register` previews the client command and
requires confirmation; its agent configuration has `--router <id> --read-only`
but no secret. Use `set-default` to choose the fallback profile. Explain that
`rotate-password` and `remove` affect local profile material only after review;
neither deletes the router user or changes router configuration.

If a user reports failure, ask only for redacted error text. Suggest a
connection test for reachability, DNS/TLS, authentication, RCI, and router
health. Treat passwords, secret paths, tokens, logs, and raw router responses
as sensitive unless already redacted.
