# Keenetic NOC MCP development slice plan

Status: active implementation plan. A0 is merged and live-validated. A1 is
implemented in the current working diff, has completed its independent
review-fix cycle, and is awaiting commit/merge. A2 and later slices are planned.

Audience: AI coding agents and human reviewers working on this repository.

Primary product direction: evolve `keenetic-noc-mcp` from a safe collection of RCI tools into a self-hosted Keenetic/Netcraze NOC diagnostic agent with excellent onboarding, configuration awareness, bounded active diagnostics, and local change history.

This plan is intentionally incremental. Each slice must be independently reviewable, testable, and safe to merge. Do not implement later slices early just because a shared abstraction looks convenient.

## 0. Repository rules that override this plan

Before changing code, read and follow:

- `AGENTS.md`
- `CONTRIBUTING.md`
- `docs/ARCHITECTURE.md`
- `docs/rci-api.md`
- `docs/SAFETY.md`
- `SECURITY.md`

Important invariants:

- Never put passwords in CLI arguments, URLs, fixtures, logs, audit records, or commits.
- Never commit raw router responses, startup configuration, running configuration, SSIDs, device names, addresses, MAC addresses, or key material captured from real hardware.
- Live smoke tests are read-only. Never perform a live mutation as part of this plan unless the operator separately and explicitly authorizes one outside normal test/smoke flows.
- Verify Keenetic behavior against a real router before claiming compatibility. Mocks prove our code behavior, not router behavior.
- Treat GET paths and command-dispatch POST reads as different compatibility surfaces.
- Preserve response-size bounds, centralized redaction, read-only tool annotations, TLS verification, guarded writes, backup-before-write, read-back verification, audit redaction, and explicit `save_config` behavior.
- Preserve existing MCP tool contracts unless a slice explicitly calls for an additive schema change.
- Prefer additive behavior and small seams over broad refactors.
- Do not weaken backup-before-write just to make remote write mode easier.

Every slice is complete only after fresh final verification:

```sh
npm run typecheck
npm test
npm run build
git diff --check
```

Run `npm run smoke:remote` only when a real remote profile is available and the operator has authorized a read-only live check.

Every material slice also completes the independent review-fix cycle in
`AGENTS.md`. The review focus is specialized below for each slice; those lists
augment rather than replace the repository-wide security and compatibility
review.

---

# Milestone A: Onboarding + Config Intelligence

This is the highest-priority milestone. Complete slices A0 through A4 before moving to broad diagnostic expansion.

The target user experience is:

1. Add a Keenetic with a guided wizard that assumes remote KeenDNS RCI is the normal path but still supports LAN.
2. Validate endpoint, TLS, authentication, RCI, model, firmware, and actual capabilities before saving.
3. Read current running configuration safely over RCI.
4. Read saved startup configuration remotely if and only if a real read-only probe proves a supported RCI path.
5. Explain unsaved configuration changes and show a bounded, redacted diff without requiring the operator to understand RCI internals.

## Slice A0 - Baseline characterization and config capability probe harness

**Progress:** Complete and merged in `a3875f5` and `97bd474`. Read-only remote
evidence was recorded for Viva (KN-1912), KeeneticOS 5.1.3, without retaining
configuration content.

### Goal

Create a safe evidence-gathering seam for configuration capabilities before changing product behavior.

### Why first

Current code assumes remote `/ci/startup-config.txt` is unavailable and therefore classifies startup config as unsupported remotely. That assumption is correct for the tested `/ci/` proxy path but does not prove that the same data cannot be reached through an RCI command/path.

Known existing surfaces:

- `GET /rci/show/running-config` is expected to expose the live CLI configuration as a JSON value, measured upstream as an array of CLI lines.
- `GET /rci/` exposes the running configuration as structured JSON.
- `/ci/startup-config.txt` exposes the saved configuration on LAN but can be denied by the remote KeenDNS proxy.
- Candidate remote saved-config path to verify: `GET /rci/more?filename=startup-config`.

The candidate startup path is a hypothesis until measured on real hardware. Do not document it as supported before the live probe succeeds.

### Implementation

Extend the read-only remote smoke infrastructure so it can probe configuration surfaces without retaining or printing configuration content.

Likely files to inspect/edit:

- `scripts/smoke-remote.ts`
- `scripts/smoke-summary.ts`
- `tests/scripts/*`
- `src/router/rci.ts`
- `src/router/errors.ts`
- `docs/rci-api.md`

Add a small reusable capability probe layer if that keeps raw probing out of the CLI and MCP tool code, for example:

```text
src/router/config-capabilities.ts
```

Do not create the abstraction unless at least the smoke probe and later config tools can both use it cleanly.

### Probe requirements

Probe at minimum:

```text
GET /rci/show/running-config
GET /rci/more?filename=startup-config
```

For each probe, retain only sanitized metadata such as:

```json
{
  "available": true,
  "transport": "rci",
  "httpStatus": 200,
  "contentTypeClass": "json|text|binary|unknown",
  "shape": "array|string|object|unknown",
  "items": 123,
  "bytes": 12345
}
```

Never print or persist body content from a real router.

If the candidate startup path returns an RCI wrapper rather than plain text, inspect only enough structure in memory to determine how a future parser should read it, then discard the payload. Sanitized shape/count metadata may be documented.

### Acceptance criteria

- Existing smoke checks still work.
- Remote smoke reports `runningConfig` capability independently from `startupConfig` capability.
- A denied candidate path is reported as a capability result, not confused with bad credentials.
- No real configuration line appears in stderr, fixtures, snapshots, test output, or committed docs.
- Unit tests cover successful JSON, successful text-like shape, 404, 403/capability denial, authentication failure, and unexpected shape.
- No mutation is sent.

### Live validation gate

On an authorized real remote KeenDNS profile, record only:

- router model family or sanitized model string already allowed by current smoke policy;
- KeeneticOS version;
- pass/fail for `show/running-config`;
- pass/fail for `more?filename=startup-config`;
- response shape/count/byte size only.

Decision:

- If `more?filename=startup-config` succeeds and clearly represents saved config, continue with remote startup-config support in A3.
- If it fails, keep remote startup config unsupported and design A3 with running config plus capability-aware saved-config absence.
- Do not weaken TLS, authentication, or proxy restrictions to force success.

### Do not do in A0

- No new MCP tools.
- No wizard rewrite.
- No write-mode changes.
- No raw configuration logging.

### Independent review focus

- Probe-safety reviewer: prove every request is read-only and no payload can
  reach fixtures, logs, summaries, errors, or git.
- RCI-shape reviewer: verify 200/403/404/auth/unexpected-shape classification
  and wrapper/count/byte metadata against the measured wire evidence.
- Smoke/compatibility reviewer: confirm existing smoke behavior, credential
  loading, sanitized reporting, and no mutation paths regress.

---

## Slice A1 - Port the `fqdn-updater` router onboarding UX

**Progress:** Implemented in the current working diff. The review-fix cycle used
independent security, wizard/state-machine, and compatibility/docs reviewers;
all material findings are closed. Final automated verification passes. An
operator completed the remote wizard against a Netcraze KeenDNS endpoint, and a
subsequent authorized read-only connection test reported healthy DNS, TLS,
authentication, RCI, running/startup config capabilities, and diagnostics on a
Viva (KN-1913) running KeeneticOS 5.1.4. No live mutation was performed and no
raw router response was retained.

### Goal

Replace the current linear `readline` profile setup experience with a guided, testable router wizard based on the proven UX flow in `Spiceman161/fqdn-updater`.

Port behavior and interaction design, not the large Python implementation wholesale.

### Source UX to study

Repository:

```text
Spiceman161/fqdn-updater
```

Especially:

```text
src/fqdn_updater/cli/panel_router_flow.py
src/fqdn_updater/cli/panel_router_support.py
src/fqdn_updater/cli/panel_prompts.py
docs/PANEL.md
docs/KEENETIC_RCI_SETUP.md
```

Check licensing/provenance before literal code reuse. Reimplement small concepts in TypeScript where that is cleaner than copying Python logic.

### Target flow

Recommended flow:

```text
keenetic-noc-mcp router add

1. Router name
   -> derive profile id automatically

2. Connection method
   -> Remote via KeenDNS [recommended]
   -> Local network

3. Dedicated router account
   -> suggest mcp_agent
   -> generate strong password
   -> show exact Keenetic setup steps
   -> require operator acknowledgement before connection test

4. Endpoint
   -> accept friendly input
   -> normalize to canonical endpoint

5. Preflight
   -> DNS/reachability
   -> TLS/SAN for remote
   -> authentication
   -> RCI
   -> model/firmware
   -> config-read capabilities
   -> key diagnostic capabilities

6. Secret storage
   -> system keychain when available
   -> owner-only file fallback after explicit confirmation

7. Optional MCP registration
   -> Codex
   -> Claude

8. Review
   -> no secret value in review
   -> save only after successful validation and explicit confirmation
```

### UX rules

- Do not ask for a manual profile ID first. Derive it from the router name and resolve collisions deterministically.
- Make remote KeenDNS the recommended path while retaining LAN support.
- Do not default the router username to `admin`. Suggest a dedicated low-privilege account such as `mcp_agent`.
- Explain exactly how to publish the KeenDNS RCI web application: this Keenetic, local protocol HTTP, TCP port 79, authorized access, external HTTPS endpoint.
- Do not put credentials into the URL.
- The wizard must validate the router before saving credentials/profile state.
- Failure must leave no partial profile. If a secret was temporarily persisted before a later failure, roll it back.
- Existing `router add`, `router test`, `router register`, `router show`, `router list`, `router remove`, `router rotate-password`, and `router set-default` behavior must remain usable.

### Endpoint normalization

Improve friendly input handling.

Accept forms such as:

```text
rci.example.keenetic.pro
https://rci.example.keenetic.pro
https://rci.example.keenetic.pro/
https://rci.example.keenetic.pro/rci
https://rci.example.keenetic.pro/rci/
```

Canonical remote result:

```text
https://rci.example.keenetic.pro/rci/
```

Security constraints:

- Remote canonical endpoint is always HTTPS.
- Reject embedded username/password.
- Reject query/fragment in user-provided endpoint.
- Never silently change hostname.
- If the user enters `http://` for a KeenDNS hostname, the wizard may normalize the public endpoint to HTTPS only if this behavior is explicitly covered by tests and documented. The low-level config parser should remain strict if that separation reduces surprise.

Measured WebUI behavior also supplies `http://` copyable endpoints under
`*.netcraze.club`; A1 accepts that known KeenDNS suffix and upgrades only the
public scheme to HTTPS. Other explicit HTTP hosts remain rejected.

### Architecture

Split wizard behavior from terminal rendering so unit tests do not require a real TTY.

Suggested shape, adjust to repository style after inspection:

```text
src/cli/router.ts                  command dispatch only
src/cli/router-wizard.ts           orchestration/state machine
src/cli/ui/prompts.ts              terminal adapter
src/cli/ui/hints.ts                operator-facing setup text
src/router/preflight.ts            network/router checks
src/config/endpoint.ts             friendly normalization + strict canonical validation
```

Do not introduce a large TUI dependency merely for visual polish. First achieve the better flow and testability using the smallest suitable prompt abstraction. A focused prompt dependency may be proposed separately if keyboard selection/checkbox UX cannot be implemented cleanly with the current stack.

### Acceptance criteria

- First-time remote setup requires materially fewer unexplained choices.
- A user can paste only a KeenDNS hostname and reach a canonical remote profile.
- Profile ID is derived from name and collision-safe.
- Dedicated account instructions appear before credential validation.
- Password is generated locally and stored only in the selected secret backend.
- Failed validation saves nothing.
- Review never prints the password.
- Preflight shows model, firmware, TLS/auth/RCI state, and config capability summary.
- Existing stored profiles continue to load unchanged.
- Tests cover cancel/back/failure boundaries as well as success.

### Tests

Add/extend focused tests under:

```text
tests/cli/
tests/config/
tests/profiles/
tests/router/
```

Characterize old profile registry behavior before refactoring it.

### Documentation

Update:

- `README.md`
- `docs/REMOTE_RCI.md`
- any CLI reference if present

Keep instructions consistent with `fqdn-updater` where both projects configure the same KeenDNS RCI mechanism.

### Independent review focus

- Security/persistence reviewer: secrets in output/argv/URLs, TLS/SNI, response
  bounds, keychain probe cleanup, rollback, concurrent setup, stale locks, and
  backup-before-write separation.
- Wizard reviewer: every Back/Cancel boundary, retained answers, invalidation
  after mode/endpoint/login/password changes, defaults, TTY cleanup, and errors
  after profile save.
- Compatibility/provenance reviewer: registry v1, existing router subcommands
  and exit codes, LAN backup checks, registration argv, dependency licences,
  documentation accuracy, and proof that no incompatible source was copied.

---

## Slice A2 - Dynamic router capability model

**Progress:** Implemented in the current working diff. The independent
capability-model, cache/auth/concurrency, and MCP contract/security reviewers
report no remaining material findings after one review-fix iteration.

### Goal

Stop deriving capabilities only from connection mode when a real read-only probe can answer the question.

### Problem

Current logic can effectively encode assumptions such as:

```text
remote => startup config unsupported
```

That is too coarse. Transport mode and endpoint capability are not the same thing.

### Design

Keep static hardware/software capabilities from `show/version`:

```text
components
features
model
firmware
```

Add probed operational capabilities, for example:

```ts
interface ProbedCapabilities {
  config: {
    runningCli: 'available' | 'unavailable' | 'unknown';
    runningStructured: 'available' | 'unavailable' | 'unknown';
    startup: 'rci-more' | 'ci-file' | 'unavailable' | 'unknown';
  };
  diagnostics: {
    logs: 'show-command' | 'get' | 'unavailable' | 'unknown';
  };
}
```

The exact type may differ, but capability values must explain the proven access method where useful.

### Requirements

- Cache capabilities for the life of a client/session where safe, rather than re-probing large configuration endpoints on every tool call.
- Do not use capability cache to suppress re-authentication behavior.
- A failed probe should distinguish unsupported path, auth failure, transport failure, and unexpected response.
- `get_connection_status` should report measured config capabilities where already known or cheaply testable.
- Do not make `get_connection_status` fetch and expose full configuration content.

### Acceptance criteria

- Remote profile is no longer automatically labeled `startup-config unsupported` if A0 proved an RCI path.
- LAN profile can still use `/ci/startup-config.txt` where supported.
- Existing error classes remain meaningful.
- Unit tests cover a mixed-capability router.

### Independent review focus

- Capability-model reviewer: transport mode must not masquerade as measured
  capability; unknown, unavailable, denied, auth, and transport states remain
  distinct.
- Cache/concurrency reviewer: cache lifetime, failed-probe recovery, shared
  requests, and re-authentication behavior cannot become stale or suppress auth.
- Contract reviewer: connection-status output remains bounded, redacted, and
  backward compatible while mixed-capability tests match A0 evidence.

---

## Slice A3 - Safe configuration read tools

**Progress:** Implemented; local verification and independent review completed.

### Goal

Expose configuration awareness to the AI client without dumping a complete sensitive router configuration by default.

### New MCP tools

```text
get_running_config
get_startup_config
search_config
```

`get_startup_config` may be registered universally but must return a clear capability result when saved config is not available on the selected transport/router. Do not fabricate or infer startup state.

### Running configuration sources

Preferred source order:

1. `show/running-config` for bounded CLI-oriented output.
2. Structured RCI config branches for targeted section reads when that produces a safer/smaller answer.
3. Full `GET /rci/` only when explicitly requested and still bounded/redacted.

Do not use `/ci/running-config.txt` remotely merely because it exists on LAN if `show/running-config` provides the same information through normal RCI.

### Suggested tool contract

```json
{
  "section": "dns|interfaces|routing|wifi|vpn|users|system|all",
  "format": "cli|structured",
  "filter": "optional literal search",
  "limit": 200
}
```

Rules:

- Default section must not be `all`.
- Default output must be bounded.
- Full configuration requires explicit intent such as `section=all` plus a high enough requested limit, still capped by global response budget.
- Apply centralized redaction before returning content.
- Consider additional config-specific redaction for secrets that are syntactically visible in CLI text but not already covered by generic redaction.
- Never include configuration in audit records.

### Startup configuration

Source selection follows the measured capability from A0/A2:

```text
LAN /ci/startup-config.txt if verified
remote RCI startup path only if live-proven
otherwise unavailable
```

Do not silently fall back from startup to running config.

### `search_config`

Requirements:

- Search running or startup source explicitly.
- Literal/normalized text search is sufficient initially. Do not build a query language.
- Return bounded matching lines plus limited context.
- Redact before returning.
- Indicate truncation and total match count where practical.

### Acceptance criteria

- AI can answer targeted questions such as "which DNS servers are configured?" without receiving the whole router config.
- Full config output is never the default.
- Startup and running sources are never confused.
- All outputs respect `maxResponseBytes`.
- Tests include likely secret-bearing lines and prove redaction.
- Tools are annotated read-only.

### Independent review focus

- Configuration-security reviewer: config-specific secret/key redaction,
  response limits before and after parsing, truncation disclosure, and no config
  content in audit/errors/fixtures.
- Source-semantics reviewer: running and startup sources never mix; remote paths
  are enabled only from A0/A2 evidence and capability failures stay typed.
- MCP-contract reviewer: defaults are narrow, `all` requires explicit intent,
  schemas/annotations are additive, and search count/context behavior is tested.

---

## Slice A4 - Configuration diff and unsaved-change explanation

**Progress:** Implemented. The independent diff-correctness,
sensitive-output, and compatibility/performance reviewers report no remaining
material findings after one review-fix iteration. Final automated verification
passes. An authorized read-only remote smoke check on Viva (KN-1912),
KeeneticOS 5.1.3, confirmed that the running and startup RCI sources remained
available with the expected bounded array-of-CLI-lines shape. The smoke harness
does not invoke `get_config_diff`, so the live diff path remains untested.

### Goal

Turn `unsavedChanges: true` into an actionable explanation of what differs between running and saved configuration.

### New MCP tool

```text
get_config_diff
```

### Behavior

Compare running CLI config against startup CLI config when both are available.

Return a bounded semantic summary first, then a bounded textual diff when requested.

Suggested output shape:

```json
{
  "comparable": true,
  "unsavedChanges": true,
  "changedSections": ["dns", "interface", "routing"],
  "added": 4,
  "removed": 2,
  "diff": ["+ ...", "- ..."],
  "truncated": false,
  "lastChange": {
    "at": "...",
    "by": "...",
    "via": "..."
  }
}
```

### Normalization

Before diffing, investigate and test whether startup and running outputs differ only because of volatile headers/checksums/order/formatting.

Do not normalize away meaningful CLI ordering unless there is router evidence that order is semantically irrelevant for that block.

At minimum, exclude known generated checksum/header lines from user-facing diffs when they would create noise.

### Integration with `get_config_state`

Keep the existing checksum-based fast state check.

`get_config_state` remains the cheap answer to "are there unsaved changes?".

`get_config_diff` is the more expensive answer to "what changed?".

Do not make `get_config_state` always download and diff both configs.

### Acceptance criteria

- Identical configs produce `unsavedChanges=false` and an empty diff summary.
- Changed configs identify added/removed lines and changed top-level sections.
- Header/checksum noise does not create false differences.
- Unavailable startup config yields `comparable=false` with a useful reason, not a guessed diff.
- Tests cover ordering, comments/headers, truncation, and redaction.

### Independent review focus

- Diff-correctness reviewer: normalization removes only measured noise, retains
  meaningful order, and section/add/remove counts agree with the bounded diff.
- Sensitive-output reviewer: both inputs and every derived line are redacted;
  truncation cannot split or reveal secret material.
- Compatibility/performance reviewer: cheap config-state behavior remains
  cheap, unavailable startup yields `comparable=false`, and large inputs remain
  bounded in time and memory.

### Milestone A exit criteria

Do not start Milestone B until all of the following are true:

- Router wizard is materially easier than the old linear flow.
- Remote running config is live-verified read-only.
- Startup capability is based on a measured path, not transport assumption.
- Targeted running/startup config reads are bounded and redacted.
- `search_config` exists.
- `get_config_diff` exists or cleanly reports that saved config is unavailable.
- Existing write safety behavior remains unchanged.
- Full standard test/build verification passes.

---

# Milestone B: NOC diagnostic tools

The low-level tools already expose useful state. This milestone adds composite tools that answer operator questions directly.

The principle is: do not make the model manually reconstruct every common incident from ten separate tool calls when the server can assemble a deterministic evidence bundle safely.

## Slice B1 - `diagnose_internet`

**Progress:** Planned; blocked by Milestone A exit criteria.

### Goal

Create the first high-level NOC diagnostic tool for "internet is down/slow/not working" incidents.

### Evidence to combine

- system health
- `show/internet/status`
- WAN/global interfaces
- default route(s)
- DNS proxy status
- VPN/default-route influence where relevant
- recent related logs
- configuration unsaved state as context, not proof of causality

### Output

Return evidence plus deterministic findings, not an LLM-generated narrative inside the server.

### Acceptance criteria

- Tool does not mutate.
- Partial endpoint failure produces a degraded/unknown check rather than throwing away all other evidence unless authentication/transport makes the whole router unreachable.
- Results are bounded.
- Log text remains untrusted data.
- Unit tests cover healthy, physical link down, no default route, DNS failure, VPN/default-route anomaly, and partial endpoint failure.

### Independent review focus

- Diagnostic-logic reviewer: findings follow only from evidence, partial
  failures become unknown/degraded, and temporal correlation is not causality.
- Network/privacy reviewer: routes, addresses, logs, and router strings are
  projected/redacted/bounded and remain untrusted data.
- MCP compatibility reviewer: read-only annotation, stable schema, capability
  gating, and healthy/failure fixture coverage.

---

## Slice B2 - Deep DNS diagnostics

**Progress:** Planned.

### Goal

Make DNS incidents a first-class diagnostic domain.

### New tools

Likely set:

```text
list_dns_upstreams
diagnose_dns
```

Possible later tools after evidence:

```text
get_dns_upstream
get_dns_routes
resolve_from_router
```

Do not invent RCI paths for these. Inspect current firmware and existing config/state first.

### `diagnose_dns` evidence

Combine what is actually available from:

- `show/dns-proxy`
- internet DNS reachability flags
- configured DNS/DoT/DoH/DoH3 entries from targeted config reads
- route/interface used by relevant upstreams where determinable
- DNS-based route bindings if exposed
- recent DNS/TLS/resolver log entries

### Independent review focus

- DNS-domain reviewer: distinguish configuration, reachability, encryption,
  routing, and resolver evidence without guessing causality.
- RCI-evidence reviewer: every new path/shape is live-proven or explicitly
  unavailable; no invented commands or transport assumptions.
- Privacy/bounds reviewer: upstreams, hostnames, routes, and log text are
  redacted and bounded, with partial failure tests.

---

## Slice B3 - Bounded active diagnostics

**Progress:** Planned; requires explicit live command evidence.

### Goal

Allow the NOC agent to verify network behavior instead of only reading configuration/state.

### Candidate tools

Only implement commands verified against real Keenetic RCI/CLI:

```text
ping
traceroute
dns_lookup
```

### Safety limits

- small packet count
- maximum timeout
- maximum hop count
- no continuous mode
- no arbitrary shell/CLI string execution
- validate host/IP input
- reject obvious command-injection syntax even if no shell is used
- cap returned output

Do not add port scanning or arbitrary TCP probing in this slice.

### Independent review focus

- Abuse/safety reviewer: input validation, injection resistance, packet/hop/
  timeout ceilings, cancellation, and absence of continuous or scan modes.
- Router-command reviewer: exact RCI/CLI shapes are live-verified and classified
  correctly as bounded diagnostics rather than arbitrary execution.
- Resource reviewer: concurrency, timeouts, output limits, and partial results
  cannot exhaust the router or MCP process.

---

## Slice B4 - Device-centric diagnostics

**Progress:** Planned.

### New tool

```text
diagnose_device
```

Reuse current device resolution behavior and ambiguity rules.

Combine:

- registered/known device data
- DHCP/address state
- interface/AP association
- Wi-Fi metrics if wireless
- routing policy
- relevant recent logs
- DNS context where useful

Use `unknown` instead of guessing when telemetry is absent.

### Independent review focus

- Identity reviewer: normalized lookup rejects ambiguity and no-match errors do
  not enumerate known devices.
- Privacy reviewer: names, MACs, addresses, associations, and logs use existing
  anonymization/redaction and response budgets.
- Diagnostic reviewer: wired/wireless and absent-telemetry branches report
  evidence/unknown consistently without causal overclaims.

---

## Slice B5 - Wi-Fi health diagnostics

**Progress:** Planned.

### Candidate tools

```text
diagnose_wifi
get_wifi_client_health
```

Later, only if verified:

```text
scan_wifi_environment
```

Investigate measured availability of RSSI, PHY mode, tx/rx rates, retry/error counters, roam/FT/BSS transition events, deauthentication reasons, and channel utilization.

Do not fabricate metrics that measured RCI paths do not expose.

### Independent review focus

- Wi-Fi telemetry reviewer: units, missing metrics, interface nesting, AP/client
  association, and firmware variants match live evidence.
- Privacy/untrusted-data reviewer: SSIDs, device names, BSSIDs, and event text
  are anonymized, redacted, and bounded.
- Diagnostic reviewer: thresholds and findings are documented, deterministic,
  and never infer unavailable retry/utilization/roaming metrics.

---

# Milestone C: Local observability and change history

## Slice C1 - Lightweight router state snapshots

**Progress:** Planned.

### Goal

Allow the agent to answer "what changed before the incident?" without storing complete sensitive router dumps.

Store summaries only under the existing state/config root conventions, for example:

```text
<state-dir>/<router-id>/snapshots/
```

Possible snapshot fields:

```json
{
  "at": "...",
  "firmware": "...",
  "configChecksum": "...",
  "savedChecksum": "...",
  "interfaces": [],
  "defaultRoutes": [],
  "dns": {},
  "vpn": [],
  "wifiClientCount": 0,
  "deviceCount": 0,
  "system": {"cpuLoad": 0, "memoryFreeKb": 0}
}
```

Do not store raw logs or complete config by default. Implement bounded retention before automatic snapshots.

### Independent review focus

- Data-minimization reviewer: snapshots contain summaries only, with no raw
  logs/config, identifiers, secrets, or unexpected router strings.
- Storage reviewer: owner-only permissions, atomic writes, retention, cleanup,
  corruption recovery, disk bounds, and router-ID path safety.
- Compatibility reviewer: snapshot schema versioning and older-state handling
  are explicit and do not alter live MCP behavior on storage failure.

---

## Slice C2 - State comparison tools

**Progress:** Planned; gated on C1.

Candidate tools:

```text
get_recent_changes
compare_router_state
```

Report temporal correlation, not causality.

### Independent review focus

- Temporal-correctness reviewer: ordering, missing intervals, clock changes,
  reboot/NTP effects, and baseline selection are handled conservatively.
- Privacy/retention reviewer: comparison output cannot reconstruct prohibited
  raw state or bypass snapshot retention/redaction.
- MCP-contract reviewer: bounded comparisons expose correlation and uncertainty,
  not causal claims, with version-mismatch tests.

Focus on changes such as default route, interface up/down, DNS state, VPN default state, firmware, config checksum, and client-count anomalies.

---

# Milestone D: Fleet / multi-router NOC

Do not begin until single-router onboarding, config intelligence, and diagnostics are mature.

## Slice D1 - Multi-router orchestration design only

**Progress:** Planned; design-only and blocked by single-router maturity.

Before implementation, compare:

1. one MCP process hosting multiple router clients;
2. one supervisor/fleet MCP calling isolated per-router workers;
3. MCP client registering multiple named server instances.

Evaluate secret isolation, failure isolation, schema ergonomics, latency, response budgets, audit separation, and operator UX.

Desired future use cases:

```text
list_routers
fleet_health
compare_routers
compare_dns(routerA, routerB)
```

### Independent review focus

- Threat-model reviewer: compare secret, process, audit, and failure isolation
  for every architecture; reject designs that broaden one router's authority.
- Operations reviewer: startup, partial fleet failure, upgrades, observability,
  and per-router response budgets remain manageable.
- MCP UX reviewer: naming/routing schemas avoid ambiguity and preserve current
  one-profile deployments. This slice must produce a reviewed decision record,
  not implementation.

---

# Deferred write-side work

Do not prioritize broad write capability during Milestones A and B.

Keep the existing safety pipeline intact:

```text
guard -> backup -> apply -> read back -> verify -> audit -> explicit save_config
```

Do not add a generic `execute CLI` tool.

---

# Cross-cutting engineering tasks

## Response budgeting

Prefer compact projections and summaries. Every tool should make truncation visible. Do not raise global response limits without evidence.

## Redaction

Configuration intelligence expands the sensitive-data surface. Add tests for likely secrets and key material before exposing configuration tools.

Prefer structured redaction policy with tests over ad-hoc regex additions inside individual tools.

## Error taxonomy

Preserve clear distinction between:

```text
AuthError
TransportError
RciError
RemoteCapabilityError
VerificationError
GuardError
```

## Documentation provenance

When new RCI behavior is established on live hardware, record in `docs/rci-api.md`:

- router model/hardware family;
- KeeneticOS version;
- exact path or dispatcher shape;
- response shape, not real payload;
- whether LAN, remote KeenDNS, or both were verified.

Never paste production configuration as proof.

## Tests before abstraction

Do not build a generic NOC framework first. Extract reusable functions only after at least two real tools need them.

---

# Agent execution protocol

A coding agent assigned this plan should work one slice at a time.

For each slice:

1. Read current implementation and adjacent tests before editing.
2. State the observable behavior and compatibility surfaces being changed.
3. Add characterization/failing tests first when meaningful.
4. Implement the smallest cohesive patch.
5. Run narrow tests while iterating.
6. Run the slice-specific independent review scopes above and the review-fix
   cycle in `AGENTS.md`. Repeat until no material findings remain.
7. Review the resulting diff for secrets, response bounds, MCP schema
   compatibility, and read/write annotations.
8. Run fresh final verification after the last fix and clean re-review:

```sh
npm run typecheck
npm test
npm run build
git diff --check
```

9. If the slice has a live read-only validation gate, run it only with explicit operator authorization and report sanitized evidence only.
10. Update docs in the same slice when behavior changes.
11. Commit with a short imperative subject describing the behavior change.

The agent must not silently continue into the next slice. Each slice should end with a concise completion report containing:

```text
Implemented:
Tests added/changed:
Verification run:
Live evidence (if authorized):
Compatibility notes:
Security notes:
Open questions / decision gates:
Suggested next slice:
```

---

# Recommended immediate assignment

Assign the coding agent this sequence first:

```text
A0 -> A1 -> A2 -> A3 -> A4
```

Do not ask it to implement Milestones B-D in the same task.

The immediate deliverable should be called:

```text
Onboarding + Config Intelligence
```

Success means a new operator can connect a router with a guided flow and the AI can safely answer:

```text
What is the router running now?
What is saved for reboot?
Are there unsaved changes?
What exactly changed?
Where in the config is this DNS/interface/routing setting?
```

Only after those answers are reliable should the project expand into automatic incident diagnosis.
