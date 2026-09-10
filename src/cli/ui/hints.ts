const accountPrivileges = `Account privileges:

- Read and write: enable "HTTP Proxy".
- Read-only: enable "HTTP Proxy" and also enable "Prohibit saving system settings"
  ("Запретить сохранять настройки системы").

The prohibit-saving flag prevents persistent configuration saves; it does not
by itself prevent changes to the running configuration. The MCP profile created
by this wizard remains read-only and does not expose mutation tools.`;

export const remoteAccountInstructions = (login: string, password: string): string => `
Configure this Keenetic before continuing:

1. Open the router web interface and create a dedicated local user named "${login}".
2. Set its password to the generated value below (shown only during this wizard):

   ${password}

3. Create a KeenDNS Web Application for "this Keenetic".
4. Set its local protocol to HTTP and TCP port to 79.
5. Enable authorized access and copy the external HTTPS URL.

${accountPrivileges}

Do not reuse an administrator password.`;

export const lanAccountInstructions = (login: string, password: string): string => `
Configure this Keenetic before continuing:

1. Open the router web interface and create a dedicated local user named "${login}".
2. Set its password to the generated value below (shown only during this wizard):

   ${password}

3. Allow local HTTP management for this user.
4. Allow TCP port 79 (RCI) and authorized access.

${accountPrivileges}

Do not reuse an administrator password.`;

export function accountInstructions(mode: 'lan' | 'remote', login: string, password: string): string {
  return mode === 'remote' ? remoteAccountInstructions(login, password) : lanAccountInstructions(login, password);
}
