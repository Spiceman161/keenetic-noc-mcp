# Security

## What this software can reach

It authenticates to a router as a dedicated operator and can change its
configuration. That is the point of it, and it is also the whole risk: anything
that can talk to this server can reconfigure the network it runs on.

## Router passwords and profiles

Use `keenetic-noc-mcp router add` from a user-owned TTY. The wizard asks for a
dedicated router user, checks the connection before committing anything, and
stores a versioned profile without its password. `init` is the compatible alias.

On macOS, Linux, and Windows it first probes the system keychain (Keychain
Services, Secret Service, or Credential Manager) with a disposable canary. A
working keychain is used automatically. Only when it is unavailable does the
wizard offer an owner-only local-file fallback, after confirmation. That
fallback uses a `0700` directory and `0600` secret file (or equivalent Windows
ACLs), is atomically written, and is forbidden in a Git worktree.

Passwords are never written to profile JSON, agent registration, tool output,
audit, logs, errors, or command previews. Secret-bearing wizard steps refuse
piped or redirected input. For containers, prefer `KEENETIC_PASSWORD_FILE`;
explicit environment configuration is compatible but does not merge with a
saved profile.

## What it does not do

No telemetry. It connects only to the selected router LAN address or KeenDNS
HTTPS endpoint. Verified TLS is never disabled for normal remote requests.

## Reducing what it can do

`--read-only` does not register the write tools at all, rather than registering
them and refusing, so an agent never sees them.

Changes apply to the running configuration and are discarded on reboot until
`save_config` is called, which nothing does on its own.

## Reporting something

Open a [security advisory](https://github.com/Spiceman161/keenetic-noc-mcp/security/advisories/new)
rather than a public issue, and give the model and KeeneticOS version. Expect a
first reply within a week.

Please do not include real MAC addresses, private IP addresses, SSIDs or keys in
a report. A test in this repository scans every file for them precisely because
they are easy to paste in by accident.
