# Source review and provenance

Review performed on 2026-09-09 before implementation. The commit identifiers
pin the material reviewed; later upstream changes are not implicitly part of
this review.

| Project | Reviewed commit | Licence | Use in this project |
| --- | --- | --- | --- |
| [salatmaster/keenetic-mcp](https://github.com/salatmaster/keenetic-mcp) | 2d4480dbbb85c9834e2d42bd373aa8482944e776 | MIT | Copied and adapted as the TypeScript/MCP base: stdio server, LAN session, RCI parsing, capability cache, projections, response budgeting, backup/config-state concepts, tools, tests, fixtures, and skills. The required upstream notice is retained in THIRD_PARTY_NOTICES.md. |
| [Spiceman161/fqdn-updater](https://github.com/Spiceman161/fqdn-updater) | 2d045878f029c4de878ff6654005b959816b130a | PolyForm Noncommercial 1.0.0 in the reviewed repository | Behavioural source for the independently implemented TypeScript remote transport: endpoint profiles, challenge-driven Digest with Basic fallback, verified TLS, bounded retry/backoff, typed transport/auth/RCI failures, and a separate diagnostic TLS probe. Python source was not copied. |
| [st412m/keenetic-mcp](https://github.com/st412m/keenetic-mcp) | ef463c39adada37df18b953c653c584c1f2cc8d2 | No licence found | Behaviour-only reference for log filtering, device alias resolution, and compact VPN/DNS projections. No source copied. |
| [Kykyryky23/Keenetic-router-plugin](https://github.com/Kykyryky23/Keenetic-router-plugin) | 36b8769c090f0a30c8d850384ccd53c50fd81103 | PolyForm Noncommercial 1.0.0 | Concept-only reference for dry-run, explicit confirmation, destructive gates, and audit trails. The implementation is original and no source was copied. |

## Review conclusions

- One process owns one immutable router connection profile; multiple routers use
  separate MCP process registrations.
- LAN authentication remains the tested Keenetic challenge/cookie flow.
- Remote authentication uses a separate transport because KeenDNS presents HTTP
  authentication challenges at a complete HTTPS endpoint.
- Router payload errors are parsed after HTTP transport succeeds and never
  trigger transport retries.
- Writes are absent from a read-only registry. In writable mode every mutation
  passes a common guard responsible for preview, confirmation, startup backup,
  verification, and redacted audit.
- Exact write shapes are inherited only where MIT upstream fixtures and tests
  establish them. Unknown VPN/configuration writes are deferred rather than
  guessed.
