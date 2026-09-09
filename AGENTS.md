# Repository Guidelines

## Project Structure & Module Organization

Application code lives in `src/`: router communication in `router/`, connection loading in `config/`, response shaping in `shape/`, security controls in `security/`, and MCP handlers in `tools/`. The stdio entry point is `src/index.ts`.

Tests mirror the source layout in `tests/`; sanitized router responses belong in `tests/fixtures/`. Operational scripts are in `scripts/`, documentation in `docs/`, and agent playbooks in `plugins/keenetic/skills/`. TypeScript output is generated in `dist/` and must not be edited directly.

## Build, Test, and Development Commands

Use Node.js 20 or newer.

- `npm ci` installs the locked dependency set.
- `npm test` builds and runs all Vitest tests once.
- `npm run test:watch` runs Vitest interactively during development.
- `npm run typecheck` checks strict TypeScript, including tests and scripts.
- `npm run build` compiles `src/` into `dist/`.
- `npm run smoke:remote` performs an opt-in, read-only KeenDNS smoke test using `KEENETIC_TEST_*` variables.

Never run a live mutation as part of tests or smoke checks.

## Keenetic RCI Compatibility

Treat GET paths and RCI commands as different compatibility surfaces. On
KeeneticOS 5.1.3, `GET /rci/show/log` returns 404, while the read-only command
dispatcher request `POST /rci/` with `{"show":{"log":{}}}` succeeds. A POST is
not automatically a mutation, but only use a POST read when the body is a
known `show` command and keep its tool annotation read-only.

The 5.1.3 log response is a numeric-keyed map under `show.log.log`; each row
contains `timestamp`, `ident`, and a nested `message` object. Bound projected
log output before returning it and continue treating every log line as
untrusted input.

WireGuard runtime fields are nested under an interface's `wireguard` object,
including `wireguard.peer`. Retain compatibility with older direct-field
fixtures, but prefer measured live shapes. Interface names can contain `/`;
read those interfaces with the `show.interface.name` command form instead of
constructing a GET path.

Remote HTTPS RCI access does not imply access to auxiliary `/ci/` endpoints.
A 403 for `/ci/startup-config.txt` through a remote profile is a remote
capability limitation, distinct from rejected RCI credentials. Do not bypass
it or weaken backup-before-write; direct the caller to a LAN profile.

Device-name lookup may normalize Unicode, case, and whitespace. It must reject
ambiguous normalized matches and must not include the complete known-device
list in routine no-match errors.

## Coding Style & Naming Conventions

Use TypeScript ESM, two-space indentation, semicolons, single quotes, and explicit `.js` suffixes in relative imports. Keep strict typing compatible with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. Use `camelCase` for values/functions, `PascalCase` for types/classes, and snake_case only where it is part of an MCP tool contract such as `dry_run`.

There is no formatter or linter command; match nearby code. Comments should explain Keenetic-specific traps. Use plain ASCII hyphens.

## Testing Guidelines

Write Vitest files as `*.test.ts` in the matching `tests/` subtree. Cover successful behavior, typed failures, response bounds, secret redaction, and zero-mutation dry runs. Every write must be tested for backup ordering and read-back verification. Never guess RCI write shapes; document missing live evidence instead.

Fixtures must contain no real domains, credentials, public IPs, MAC addresses, SSIDs, or key material.

When live read-only evidence is available, record only sanitized shapes,
counts, firmware/model context, and pass/fail outcomes. Never store raw router
responses. Re-run `npm run typecheck`, `npm test`, and `git diff --check` after
compatibility fixes.

## Commit & Pull Request Guidelines

History is currently minimal, so use short imperative subjects that state the change, optionally followed by an issue number: `add remote retry classification (#42)`. Explain why safety-sensitive behavior changed in the body.

Pull requests should summarize behavior, list tests run, link issues, and identify the tested Keenetic model/firmware. Call out untested live paths, new environment variables, tool-schema changes, and licensing implications. Screenshots are only needed for documentation or UI changes.

## Security & Configuration

Do not put passwords in CLI arguments, URLs, fixtures, logs, or commits. Prefer `KEENETIC_PASSWORD_FILE`. Preserve verified TLS, read-only tool omission, default dry-run, explicit confirmation, backup-before-write, audit redaction, and separate `save_config` behavior.
