# Remote RCI

In Keenetic WebUI enable KeenDNS, then create a Web application named `rci` for
**this Keenetic**, local protocol **HTTP**, TCP port **79**, with **authorized
access**. HTTP describes the local proxy hop; the public client URL is HTTPS:

```text
https://rci.example.net/rci/
```

Create a dedicated, least-privilege Keenetic user. Do not reuse the
administrator password. Then run `keenetic-noc-mcp router add` in your own
terminal, choose remote mode, and enter the endpoint and dedicated login. The
wizard validates DNS/TLS and the credentials before it offers to save the
profile. It stores the password in the system keychain where possible; do not
put credentials in the URL.

The client waits for the server challenge, prefers Digest, and falls back to
Basic only if offered. TLS certificate verification is always enabled for RCI
traffic. HTTP 401/403 are authentication failures; timeout, DNS, TCP and TLS
failures are transport failures and receive at most five attempts. RCI status
errors are deterministic and are not retried. Concurrent first requests share
one authentication handshake. `KEENETIC_TIMEOUT_MS` is the deadline for the
complete logical remote request, including handshake queueing, retry backoff,
and every transport attempt; it is not a fresh timeout for each attempt.

Accepted URL spellings end at the origin, `/`, `/rci`, or `/rci/`; all normalize
to `/rci/` without changing scheme or host. Only HTTPS is accepted remotely.

Run `keenetic-noc-mcp router test <id>` after changes to get a read-only report
of DNS, TLS, authentication, RCI, router system, configuration-read, and
startup-backup capability. Each item is probed separately. A remote profile can
be healthy while `/ci/startup-config.txt` is reported as unsupported remotely;
backup-before-write then requires a LAN profile. It saves only a redacted
summary of the result.

The opt-in read-only smoke check uses the default remote profile directly:

```sh
npm run smoke:remote
npm run smoke:remote -- --router <profile-id>
```

Profile secrets are read from the configured keychain or owner-only file and
are never placed in command-line arguments. The complete `KEENETIC_TEST_*`
environment remains available as an explicit CI override.
