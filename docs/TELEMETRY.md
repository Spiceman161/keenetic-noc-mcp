# MCP call telemetry

OBS-1 provides an optional local technical journal for understanding which MCP
tools run, how long they take, and how they finish. It is deterministic server
telemetry, not AI memory or an evaluation of diagnostic quality.

Telemetry is disabled by default. Enable it for one MCP process with:

```sh
export KEENETIC_TELEMETRY_ENABLED=true
```

The default journal is `mcp-calls.jsonl` below the platform state directory.
`KEENETIC_STATE_DIR` changes that state root. To select another file, provide an
absolute path:

```sh
export KEENETIC_TELEMETRY_PATH=/var/lib/keenetic-noc-mcp/mcp-calls.jsonl
```

The server creates its default state directory with mode `0700` and the journal
with mode `0600` on POSIX systems. A custom path's existing parent permissions
remain the operator's responsibility. A symlink or non-regular journal target
is refused. A short-lived adjacent `.lock` file serializes appends from
multiple profile processes; after a process crash, confirm no MCP process is
using the journal before removing a stale lock. A write failure produces one generic stderr warning and never
changes the MCP tool result. Stdout remains reserved for the MCP protocol.

## Record schema

Each completed handler invocation appends one schema-versioned JSON object:

```json
{"schema_version":1,"timestamp":"2026-09-12T12:00:00.000Z","finished_at":"2026-09-12T12:00:00.438Z","call_id":"8d16e5ae-18f8-44c7-aa3a-0a16e0a0cbe1","mcp_request_id":17,"router_profile":"tupik","tool":"diagnose_dns","tool_attributes":{"read_only":true,"open_world":false},"duration_ms":438,"status":"success","error_code":null,"args_summary":{"fields":{},"total_fields":0,"truncated":false},"result_size_bytes":1234,"output_truncated":false,"server_version":"0.0.0-dev"}
```

An error record contains a controlled code, not exception text:

```json
{"schema_version":1,"timestamp":"2026-09-12T12:01:00.000Z","finished_at":"2026-09-12T12:01:00.002Z","call_id":"6f889d91-f81f-49df-86ce-98b33b26dff6","mcp_request_id":18,"router_profile":"tupik","tool":"ping","tool_attributes":{"read_only":true,"destructive":false,"open_world":true},"duration_ms":2,"status":"error","error_code":"active_diagnostic_busy","args_summary":{"fields":{"target":{"type":"string","length":12}},"total_fields":1,"truncated":false},"result_size_bytes":312,"output_truncated":false,"server_version":"0.0.0-dev"}
```

`duration_ms` measures handler execution with a monotonic clock and excludes
the journal append. `result_size_bytes` is the UTF-8 size of the final callback
result, including its metadata; it is not the raw router response or the entire
JSON-RPC frame. The append is scheduled asynchronously so a stalled filesystem
cannot stall tool delivery. Concurrent records are queued in completion order;
the pending queue is capped and drops new records during a prolonged storage
stall. A process terminated immediately after a call may lose its final queued record.

Newly written schema-v1 records also include the optional additive
`rci_transport` object. Historical schema-v1 lines without it remain valid and
are not rewritten. It records only bounded causal counters for the current MCP
call: normal dispatcher attempts, shared-auth waits, fallback consideration and
activation, pinned attempts/recovery/exhaustion, a fixed controlled terminal
reason counter, and at most eight fallback events with two candidates each.
`correlation_complete` is false when the existing request/socket/error evidence
cannot be associated with that exact normal attempt; fallback stays subject to
the existing fail-closed transport gate. LAN records use `not_applicable` and
null measurements; an absent connection mode uses `unknown`. A remote handler
which makes no `RemoteSession` request has zero counters rather than a
fabricated success.

The normal case is appended after the handler. A cold shared-auth flight may
outlive its initiating handler; its record is deliberately appended after that
flight settles with `finalized_after_handler: true`, so journal order can differ
from handler completion order while timestamp, finished time, and duration keep
their original meaning.

Cloud edge IP retention is separately opt-in and deliberately strict:

```sh
export KEENETIC_TELEMETRY_RCI_EDGE_IPS=true
```

Even then, an IP is retained only for a canonical `https` endpoint at exactly
`/rci/`, with no userinfo, port, query, or fragment, whose hostname is a
recognized subdomain of `.keenetic.pro` or `.netcraze.club`. The address must
also be canonical public-unicast IPv4/IPv6; private, loopback, link-local,
multicast, unspecified, and documentation ranges are suppressed. At most 16
first-seen values are retained in each edge list. Other endpoints, any other
spelling, LAN, and unknown mode keep the counters but replace every edge-IP
slot/list with `null`. These bounds keep the complete JSONL record within the
writer's 16 KiB ceiling.

The MCP result `_meta` contains the same `call_id` under
`io.github.spiceman161/telemetry`. An integration can use this identifier for a
separate future semantic-quality record without mixing subjective evaluation
into this journal. A numeric `mcp_request_id` is client supplied correlation
data, not a globally unique identifier. Client-controlled string request IDs
are omitted rather than copied into the journal.

## Privacy boundary

The journal never stores argument values or result content. `args_summary`
contains only top-level field names and value shapes: type, string/array length,
or object field count. This applies especially to `rci_call`, configuration
searches, local backup paths, device selectors, and diagnostic targets.

The journal does not contain:

- passwords, keys, authorization headers, cookies, URLs, or credentials;
- raw RCI payloads, running/startup configuration, config search text, or logs;
- tool result bodies or exception/error messages;
- LLM prompts, responses, provider identity, session memory, or token usage;
- inferred retries, diagnostic quality, or fabricated client metadata.

`rci_transport` follows the same boundary. It never contains endpoint
hostnames or URLs, credentials, authorization/cookie/request headers, TLS
material, RCI methods/paths/bodies, response/router/configuration/log text, or
error text. Fallback candidate evidence has a nullable IP slot specifically so
that aggregate effectiveness counts remain useful when retention is disabled.

SDK input-schema failures and unknown tool names are rejected before the public
registered callback runs and are not recorded in OBS-1. Runtime validation in a
tool handler is recorded. Capturing pre-handler rejection is a separate future
slice because it requires a lower-level SDK/transport integration.
Timeouts and cancellations currently use the existing `transport` error code;
a distinct stable timeout subtype is also deferred.

## Operations and troubleshooting

Inspect recent calls with:

```sh
tail -n 20 /absolute/path/to/mcp-calls.jsonl
```

When neither path variable is set, use the platform state location described in
[Architecture](ARCHITECTURE.md). Invalid enable values or relative custom paths
disable telemetry and emit the generic stderr warning. Rotation and retention
are not implemented in OBS-1; use an operating-system facility such as
`logrotate`, preserving owner-only permissions, or periodically archive the
file while the MCP process is stopped.
