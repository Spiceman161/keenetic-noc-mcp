# Tools

Read tools: `get_system_info`, `get_config_state`, `get_connection_status`,
`get_internet_status`, `list_interfaces`, `get_interface`, `list_routes`,
`list_policies`, `list_devices`, `get_device`, `get_wifi_status`, `list_vpn`,
`get_vpn`, `get_dns_status`, `get_logs`, `get_logs_by_device`, `list_segments`,
`backup_config`, and bounded raw `rci_call` GET.

Write mode additionally advertises `set_interface_state`, `restart_interface`,
and `save_config`. Raw `rci_call` POST remains disabled unless the operator
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
