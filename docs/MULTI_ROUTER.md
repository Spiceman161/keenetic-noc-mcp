# Multiple routers with Codex and Claude

One MCP process owns one router profile. The guided `router add` wizard can
register the safely saved profile with Codex, Claude, or both. Registration is
optional and defaults to neither client. Repeat the wizard for each router, or
create profiles first and use the standalone command to register a separate
read-only client instance for each one:

~~~sh
keenetic-noc-mcp router add
keenetic-noc-mcp router register home --client codex
keenetic-noc-mcp router register office --client codex
~~~

Saved profiles use the project directory: `~/.config/keenetic-noc-mcp` on
Linux (or the platform equivalent). A normal startup migrates the previous
`keenetic-mcp` directory only when the project directory does not exist; it
never merges or overwrites two profile directories. Set `KEENETIC_CONFIG_DIR`
only when an operator intentionally needs a different location.

Standalone registration previews the client command and requires confirmation;
that behavior is unchanged by the wizard. For Codex, it uses the supported
`codex mcp add` command to create instances such as `keenetic_home`. The agent
configuration contains only the executable and router selection, never a
password or secret-file path. Existing instance names are not overwritten
without confirmation. Use `--client claude` for the equivalent Claude
registration, or omit the client flag to choose interactively.

Wizard-selected registrations run only after the password has been verified
and the profile has been persisted. The client command is invoked as an
argument array, not through a shell command string. A registration failure does
not roll back the valid profile; the wizard prints a secret-free client command
that can be retried later.

The resulting configuration is equivalent to:

~~~toml
[mcp_servers.keenetic_home]
command = "node"
args = ["/opt/keenetic-noc-mcp/dist/index.js", "--router", "home", "--read-only"]

[mcp_servers.keenetic_office]
command = "node"
args = ["/opt/keenetic-noc-mcp/dist/index.js", "--router", "office", "--read-only"]
~~~

Prefer router register over manually editing client settings. router show
records safe registration metadata and can compare it with the client CLI when
installed. Removing a profile can remove its registrations and local secret,
but never deletes the router user or changes router configuration.

For containers, do not use saved profiles. Provide KEENETIC_URL or
KEENETIC_HOST, KEENETIC_USER, and KEENETIC_PASSWORD_FILE to each process.
Do not combine explicit environment configuration with saved profile data.
MCP uses the process standard output for its protocol, so standard output must
remain protocol-only.
