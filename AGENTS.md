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
- `npm run smoke:remote` performs an opt-in, read-only KeenDNS smoke test using
  the default remote profile. Use `npm run smoke:remote -- --router <id>` to
  select another profile; a complete `KEENETIC_TEST_*` environment overrides
  profile discovery for CI.

Never run a live mutation as part of tests or smoke checks.

## Existing-Project Change Workflow

Use this workflow for fixes, compatibility work, refactors, and incremental
features in this repository. It is intentionally for changing an existing
system, not for greenfield product ideation.

1. Ground the change in repository evidence. Read the relevant implementation,
   adjacent tests, contracts, documentation, and current diff before editing.
   Reproduce a reported failure when it can be done safely and deterministically.
2. State the observable behavior being changed and the acceptance criteria.
   Identify compatibility surfaces such as MCP schemas, profile files, CLI exit
   codes, RCI wire shapes, redaction, and backup-before-write.
3. For a bug or regression, add or identify a test that fails for the right
   reason before changing production behavior. For a refactor, establish passing
   characterization coverage first. If a meaningful automated test is not
   possible, document why and define a bounded read-only validation instead.
4. Implement the smallest cohesive change that satisfies the acceptance
   criteria. Prefer additive contracts and existing seams. Do not mix unrelated
   cleanup, speculative abstractions, dependency changes, or broad rewrites into
   the same patch.
5. Diagnose unexpected failures before editing again. Read the complete error,
   identify the failing layer, and test one hypothesis at a time; do not stack
   unverified fixes or weaken assertions merely to make a test pass.
6. Review the resulting diff as a security and compatibility artifact. Check
   that secrets cannot reach arguments, URLs, output, fixtures, or git; response
   bounds still apply; read-only annotations are accurate; and old supported
   response shapes still work unless removal was explicitly requested.
7. Verify with the narrowest relevant tests while iterating, then run fresh
   `npm run typecheck`, `npm test`, and `git diff --check` before claiming the
   work is complete. Run live smoke checks only when explicitly authorized, keep
   them read-only, and report sanitized counts and shapes rather than raw data.

## Independent Review-Fix Cycle

Every material feature slice, security-sensitive fix, compatibility change, or
cross-cutting refactor must complete an independent review-fix cycle before it
is called complete. Documentation-only typo fixes and equivalent mechanical
changes may use one proportional review instead.

1. Finish a cohesive implementation and its focused tests first. Record the
   intended behavior, compatibility surfaces, and known live-evidence limits.
2. Ask at least two independent reviewers who did not implement the code they
   review. Use three reviewers when a slice spans security, persistence,
   networking, CLI contracts, or several subsystems.
3. Give reviewers distinct, slice-appropriate scopes. Typical scopes are:
   security and secret handling; state-machine and failure-path correctness;
   compatibility, tests, documentation, and licensing. Reviewers inspect the
   complete current diff and do not edit it.
4. Require findings to include severity, concrete file/line evidence, impact,
   and a proposed validation. Treat correctness, security, data-loss, contract,
   and required-test gaps as material findings. Do not dismiss a finding merely
   because the existing suite passes.
5. Diagnose and fix confirmed findings one hypothesis at a time. Add a
   regression test that fails for the reported reason when meaningful, then run
   the narrowest relevant checks.
6. Send the updated diff, or the final delta plus enough surrounding context,
   back to independent reviewers. Explicitly ask them to confirm prior findings
   are closed and to look for regressions introduced by the fix.
7. Repeat review -> fix -> focused verification -> re-review until reviewers
   report no material findings. Resolve low-severity required coverage gaps or
   document why they are intentionally deferred.
8. Only after the final review is clean, run fresh `npm run typecheck`,
   `npm test`, `npm run build`, and `git diff --check`. These commands must run
   after the last relevant edit; earlier green output is not final evidence.

Implementation delegation is not independent review. An agent that authored a
subsystem must not be its final reviewer. The completion report must state the
review scopes, number of review-fix iterations, material findings fixed, final
review outcome, verification commands, and any untested live paths.

Treat verification output as evidence, not ceremony: never claim a command
passed unless it was run after the final relevant edit. If a required check
cannot run, report that limitation explicitly instead of inferring success.

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
