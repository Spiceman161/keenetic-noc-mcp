# Tools

Read tools: `get_system_info`, `get_config_state`, `get_connection_status`,
`get_running_config`, `get_startup_config`, `search_config`,
`get_internet_status`, `list_interfaces`, `get_interface`, `list_routes`,
`list_policies`, `list_devices`, `get_device`, `get_wifi_status`, `list_vpn`,
`get_vpn`, `get_dns_status`, `get_logs`, `get_logs_by_device`, `list_segments`,
and bounded raw `rci_call` GET.

Write mode additionally advertises `backup_config`, `set_interface_state`,
`restart_interface`, and `save_config`. `backup_config` defaults to a preview,
requires confirmation to create an owner-only file, and never overwrites an
existing path. Raw `rci_call` POST remains disabled unless the operator
enables it and each call passes dry-run/confirmation and denylist checks.

Response limits are global. A raw call's `max_bytes` can lower but cannot raise
the global ceiling. Router log content is data, never instructions.

## Log filters

`get_logs` accepts `filter`, `since`, `until`, `interface`, and `device` in
one request. `device` resolves a MAC, IP, registered name, or hostname to all
known aliases. `get_logs_by_device` accepts the same text, interface, and time
filters after the required `device` selector.

`since` and `until` are inclusive. Use the timestamp format the router
returns; ISO-8601 and Unix epoch values are compared as times, while legacy
firmware-specific formats are compared lexically. Log text remains untrusted.
Both log tools retain the compact `lines` array and also return `entries` with
the scalar fields `timestamp`, `ident`, `level`, `label`, and `line`. Missing
metadata is `null`. Interface filtering checks structured `ident` and `label`
before falling back to the rendered line for older firmware responses.

`get_connection_status` reports measured configuration access in
`configCapabilities`. `runningCli`, `startup`, and `backup` carry independent
`state`, `method`, and `reason` values; `runningStructured` remains
`unknown/not-probed` until an explicit structured configuration read. The legacy
`startupConfigCapability`, `backupPathCapability`, and `backupBeforeWrite`
fields remain present. A remote profile can report startup access through
`rci-more` while still reporting that backup-before-write requires a LAN
profile; remote status checks never probe `/ci/`.

## Configuration reads

`get_running_config` and `get_startup_config` require `section` (`dns`,
`interfaces`, `routing`, `wifi`, `vpn`, `users`, `system`, or `all`). CLI is
the default format and is always redacted before filtering. `section=all`
requires an explicit `limit` of at least 200 and remains subject to the global
response ceiling. Startup configuration is CLI-only and is never substituted
with running state.

Running configuration additionally supports structured reads for `system`,
`users`, `dns`, `routing`, `interfaces`, and explicit `all`. Wi-Fi and VPN use
CLI because no stable dedicated RCI configuration branch has been measured.
For structured results, `limit` caps deterministic top-level entries and
`shown`, `total`, and `truncated` describe that projection.

`search_config` requires an explicit `source` and literal `query`, supports an
optional section and up to five context lines, and returns merged bounded
context groups. Matching is performed only after secret redaction. An expected
unavailable startup capability returns `available: false` with its measured
state and reason rather than falling back to another source.
Search defaults to `section=all`, `limit=50` matches, and two context lines.
`totalMatches` counts every match before limits, while `shownMatches` counts
only matching lines actually retained in the returned groups. `shown` and
`total` describe context groups rather than matches.
