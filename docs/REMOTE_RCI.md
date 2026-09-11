# Remote RCI

In Keenetic WebUI enable KeenDNS, then create a Web application named `rci` for
**this Keenetic**, local protocol **HTTP**, TCP port **79**, with **authorized
access**. HTTP describes the local proxy hop; the public client URL is HTTPS:

```text
https://rci.example.net/rci/
```

Create a dedicated, least-privilege Keenetic user. Do not reuse the
administrator password. Then run `keenetic-noc-mcp router add` (or its
`router init` alias) in your own terminal. The English-language wizard selects
remote KeenDNS by default; LAN remains available. It defaults the dedicated
account name to `mcp_agent`, generates a 24-character password, and reveals that
password once so that you can create the router account. It then requires you
to acknowledge these exact Web Application settings before continuing:

- device: **this Keenetic**;
- local protocol: **HTTP**;
- TCP port: **79**;
- **authorized access** enabled;
- the external client URL uses **HTTPS**.

For the router user's permissions:

- for read and write access, enable **HTTP Proxy**;
- for read-only operation, enable **HTTP Proxy** and also enable
  **Prohibit saving system settings** (**Запретить сохранять настройки системы**).

The prohibit-saving permission blocks persistent system saves but is not a
complete running-configuration write barrier. The A1 wizard therefore still
creates a read-only MCP profile and registers clients with `--read-only`, so
mutation tools are not exposed.

The wizard accepts a bare hostname, an HTTPS origin, or an HTTPS URL ending in
`/rci` or `/rci/`, and normalizes it to the stored `/rci/` form without changing
the hostname. Keenetic/Netcraze WebUI may copy its public endpoint with an
`http://` scheme. For known KeenDNS suffixes `*.keenetic.pro` and
`*.netcraze.club`, the wizard upgrades that explicit scheme to HTTPS.
Credentials, query strings, fragments, other paths, and HTTP URLs for every
other host are rejected. The underlying remote URL parser remains strict and
accepts HTTPS only.

Use the arrow keys on choice screens, `Esc` to return to the previous step, and
`Ctrl+C` to cancel. The wizard retains valid earlier answers when going back,
but changing the connection mode, endpoint, login, or generated password makes
it run the connection checks again. It writes neither the profile nor its
secret until preflight succeeds and you approve the secret store and final
secret-free review.

The client waits for the server challenge, prefers Digest, and falls back to
Basic only if offered. TLS certificate verification is always enabled for RCI
traffic. HTTP 401/403 are authentication failures; timeout, DNS, TCP and TLS
failures are transport failures and receive at most five attempts. RCI status
errors are deterministic and are not retried. Concurrent first requests share
one authentication handshake. `KEENETIC_TIMEOUT_MS` is the deadline for the
complete logical remote request, including handshake queueing, retry backoff,
and every transport attempt; it is not a fresh timeout for each attempt. The
default is 30 seconds for remote profiles (10 seconds for LAN connections),
because bounded log reads through KeenDNS can legitimately take longer than
10 seconds.

During preflight, DNS output is limited to success and address count. TLS uses
the system trust store and SNI, with certificate verification enabled. A
read-only `show/version` request verifies authentication and RCI and projects
only the model and firmware. Running/startup configuration capabilities and
bounded system, internet-status, and DNS diagnostics are probed independently;
router or configuration payloads are never printed. Endpoint, TLS,
authentication, and RCI failures block saving, while unavailable optional
capabilities are reported as warnings rather than credential failures. RCI
response reads used by preflight have explicit byte limits; oversized core
responses block setup and oversized optional diagnostics become warnings.

The password is saved and read back before the profile is added. The system
keychain is selected automatically when a disposable probe succeeds. Otherwise
the wizard explains the owner-only file fallback and requires explicit
confirmation, defaulting to no. If profile persistence fails, the newly saved
secret is removed.

Run `keenetic-noc-mcp router test <id>` after changes to get a read-only report
of DNS, TLS, authentication, RCI, router system, configuration-read, and
startup-backup capability. LAN profiles probe `/ci/startup-config.txt`
separately, so an unavailable backup produces a degraded result. A remote profile can
be healthy while the backup line says that write backup requires LAN. This is
separate from the successful remote RCI startup-config read: the read-only
configuration tools use the live-proven `more?filename=startup-config` surface,
while the existing mutation guard deliberately continues to require the
LAN-only `/ci/startup-config.txt` backup. It saves only a redacted summary of
the result.

The running MCP process exposes the same measurements through
`get_connection_status`. Operational capability results are cached only for
that client session; they are not written into the router profile or last-test
state. A failed authentication or transport probe is retried on the next call.
Remote checks probe normal RCI paths only and never request `/ci/`.

The opt-in read-only smoke check uses the default remote profile directly:

```sh
npm run smoke:remote
npm run smoke:remote -- --router <profile-id>
```

Profile secrets are read from the configured keychain or owner-only file and
are never placed in command-line arguments. The complete `KEENETIC_TEST_*`
environment remains available as an explicit CI override.
