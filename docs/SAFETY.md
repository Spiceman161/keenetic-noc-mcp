# Safety model

Start with `--read-only` for diagnosis. That registry contains no mutation
tools, including local filesystem writes. Writable mode exposes
`backup_config`, `set_interface_state`, `restart_interface`, and `save_config`
in v0.1, plus raw POST only when explicitly enabled.

Writes default to `dry_run=true`. A real call needs both `dry_run=false` and
`confirm=true`. The first real configuration mutation downloads
`/ci/startup-config.txt`; backup failure blocks the write. The change is read
back and verified, but never saved automatically. `save_config` is separate.

Set `KEENETIC_PROTECTED_INTERFACES` to a comma-separated list. Protected
interfaces cannot be changed. Raw POST additionally requires
`KEENETIC_ALLOW_RAW_WRITE=true` and refuses user, auth, crypto, security, and
HTTP-proxy branches.

Disabling or restarting an interface marked as a default gateway additionally
requires `KEENETIC_ALLOW_DESTRUCTIVE=true`.

Mutation attempts are appended to owner-only `audit.jsonl` below `KEENETIC_STATE_DIR`.
Passwords, authorization, cookies, private keys, PSKs, tokens and long key
material are redacted from tool output and audit. Restrict state-directory
permissions and retain backups appropriately.
