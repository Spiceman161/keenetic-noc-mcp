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
errors are deterministic and are not retried.

Accepted URL spellings end at the origin, `/`, `/rci`, or `/rci/`; all normalize
to `/rci/` without changing scheme or host. Only HTTPS is accepted remotely.

Run `keenetic-noc-mcp router test <id>` after changes to get a read-only report
of DNS, TLS, authentication, RCI, router system, internet, configuration-read,
and startup-backup capability. It saves only a redacted summary of that result.
