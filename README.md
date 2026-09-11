# Keenetic NOC MCP

[![CI](https://github.com/Spiceman161/keenetic-noc-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Spiceman161/keenetic-noc-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-stdio-7C3AED)](https://modelcontextprotocol.io/)

[English](#english) | [Русский](#русский)

## English

Keenetic NOC MCP is a security-first [Model Context Protocol](https://modelcontextprotocol.io/) server for diagnosing and carefully managing **Keenetic** and **Netcraze** routers. It gives an AI client controlled access to a router on the LAN through RCI or remotely through a KeenDNS HTTPS Web Application, while treating passwords, keys, addresses, and router responses as sensitive data.

It is intended for operators who want useful network automation without handing an agent an unrestricted router session.

### What it provides

- Safe, bounded diagnostics for system state, internet, Wi-Fi, interfaces, routes, devices, DNS, VPN, segments, logs, and redacted running/startup configuration.
- Finite, rate-limited ping and traceroute from the router, with strict target validation and cancellation.
- Named router profiles for LAN and remote HTTPS RCI access; one MCP process serves one selected profile.
- Remote transport with HTTPS-only endpoints, normal TLS certificate verification, and challenge-driven Digest or Basic authentication.
- Read-only mode that omits mutation tools entirely.
- Guarded changes: preview by default, explicit confirmation, backup before the first write, read-back verification, and separate persistence with save_config.
- Centralized redaction in tool responses, errors, and audit records. Passwords are not accepted in command-line arguments.

Keenetic and Netcraze are trademarks of their respective owners. This independent project is not affiliated with or endorsed by either company.

### Quick start

Requirements: Node.js 20 or newer and a router account with only the privileges it needs.

From a source checkout:

~~~sh
npm ci
npm run build
node dist/index.js router add
node dist/index.js router test home
node dist/index.js router snapshot home
~~~

After the package is published, the same profile setup can be started with:

~~~sh
npx -y keenetic-noc-mcp router add
~~~

Run the English-language profile wizard in your own terminal. Remote KeenDNS is
selected by default, and LAN connections remain supported. Use the arrow keys
on choice screens, `Esc` to return to the previous step, and `Ctrl+C` to cancel.
`router init` is an alias for `router add`.

The wizard derives a profile ID from the router name, creates a dedicated
account password, and shows the exact Keenetic account and Web Application
settings to apply. It performs the applicable read-only DNS, TLS,
authentication, RCI, configuration-capability, and bounded diagnostic checks
before saving anything. LAN addresses must be bare hostnames or IP addresses;
URLs, credentials, query strings, fragments, and paths are rejected.
For the dedicated router user, enable **HTTP Proxy**. For read-only operation,
also enable **Prohibit saving system settings** (**Запретить сохранять настройки
системы**). This router permission does not by itself block running changes, so
wizard-created MCP profiles remain read-only and expose no mutation tools.
The review contains no password or secret-file path. The password is stored in
the system keychain when available; using an owner-only file instead requires
explicit confirmation. After a successful save, the wizard can optionally
register the profile with Codex, Claude, or both. Neither client is selected by
default. Do not paste a password, endpoint credential, or secret-file path into
an AI chat.

`router snapshot <profile-id>` performs an explicit read-only router probe and
stores a privacy-minimized local state summary. It contains aggregate interface,
route, DNS, VPN, Wi-Fi, device and system state, plus configuration checksums,
but no configuration lines, logs, addresses, device names, SSIDs or interface
identifiers. Per-router history is limited to 96 snapshots, 30 days and 1 MiB.
Removing a profile also removes its local snapshots after confirmation.

For an unattended deployment, configure a single process explicitly:

~~~sh
export KEENETIC_URL=https://rci.example.net/rci/
export KEENETIC_USER=router_operator
export KEENETIC_PASSWORD_FILE=/run/secrets/keenetic-router
node dist/index.js --read-only
~~~

For a LAN router, use KEENETIC_HOST instead of KEENETIC_URL. A remote endpoint must be HTTPS and end in /rci/. See [Remote RCI](docs/REMOTE_RCI.md) for the required KeenDNS Web Application configuration.

### Safety model

- Start with --read-only. Mutation tools are not registered in that mode.
- A real change requires dry_run=false and confirm=true.
- Before the first real write, the server creates a startup-configuration backup. If the backup is unavailable, the write is blocked.
- Each supported write is read back and verified. The server never calls save_config automatically.
- Remote access to normal RCI does not imply access to auxiliary backup endpoints. Use a LAN profile when backup capability is unavailable remotely.
- Router logs and all router-provided strings are untrusted data, never instructions.
- Ping and traceroute do not change configuration but do emit bounded network traffic to one operator-selected target.
- The MCP server does not create state snapshots automatically. `router snapshot` is a separate, explicit CLI operation that writes owner-only local state.

Read the full [safety model](docs/SAFETY.md) and [security policy](SECURITY.md) before enabling write access.

### Development

~~~sh
npm ci
npm run typecheck
npm test
npm run build
git diff --check
~~~

The opt-in remote smoke check is read-only:

~~~sh
npm run smoke:remote
npm run smoke:remote -- --router <profile-id>
~~~

With no arguments it uses the default remote profile and its configured secret
store; `--router` selects another remote profile. A complete set of
KEENETIC_TEST_URL, KEENETIC_TEST_USER, and KEENETIC_TEST_PASSWORD overrides the
profile registry for CI. Its summary contains only response shapes, statuses,
and counts - never log lines, device aliases, addresses, or the endpoint. Never
run a live mutation as part of a test or smoke check.

### Documentation and contribution

- [Tools](docs/TOOLS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Remote RCI setup](docs/REMOTE_RCI.md)
- [Multi-router clients](docs/MULTI_ROUTER.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Issues and pull requests are welcome. Please remove real IP addresses, MAC addresses, SSIDs, passwords, keys, cookies, and router configuration from reports and fixtures.

Licensed under the [MIT License](LICENSE). This project contains adapted MIT-licensed work; the required notice is preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Русский

Keenetic NOC MCP - ориентированный на безопасность сервер [Model Context Protocol](https://modelcontextprotocol.io/) для диагностики и аккуратного управления роутерами **Keenetic** и **Netcraze**. Он даёт AI-клиенту контролируемый доступ к роутеру по LAN через RCI или удалённо через HTTPS Web Application KeenDNS, бережно обращаясь с паролями, ключами, адресами и ответами роутера.

Проект предназначен для операторов, которым нужна полезная автоматизация сети без выдачи агенту неограниченной сессии управления роутером.

### Возможности

- Безопасная диагностика с ограничением размера ответов: система, интернет, Wi-Fi, интерфейсы, маршруты, устройства, DNS, VPN, сегменты, журналы и отредактированная текущая/сохранённая конфигурация.
- Именованные профили роутеров для LAN и удалённого HTTPS RCI; один процесс MCP обслуживает один выбранный профиль.
- Удалённое подключение только по HTTPS, с обычной проверкой TLS-сертификата и аутентификацией Digest или Basic по запросу сервера.
- Режим только для чтения, в котором инструменты изменения вообще не регистрируются.
- Защищённые изменения: сначала предварительный просмотр, затем явное подтверждение, резервная копия перед первой записью, проверка чтением и отдельное сохранение конфигурации.
- Централизованная маскировка секретов в ответах инструментов, ошибках и журнале аудита. Пароли не принимаются в аргументах командной строки.

Keenetic и Netcraze - товарные знаки соответствующих владельцев. Это независимый проект, не аффилированный и не одобренный данными компаниями.

### Быстрый старт

Требуются Node.js 20+ и отдельная учётная запись роутера с минимально необходимыми правами.

Из исходного репозитория:

~~~sh
npm ci
npm run build
node dist/index.js router add
node dist/index.js router test home
~~~

После публикации пакета профиль можно создать так:

~~~sh
npx -y keenetic-noc-mcp router add
~~~

Запускайте англоязычный мастер профиля в собственном терминале. По умолчанию
выбран удалённый KeenDNS, но LAN-подключение также поддерживается. На экранах
выбора используйте стрелки, `Esc` для возврата к предыдущему шагу и `Ctrl+C`
для отмены. `router init` является alias для `router add`.

Мастер создаёт ID профиля из имени роутера, генерирует пароль отдельной учётной
записи и показывает точные параметры учётной записи и Web Application Keenetic.
До любого сохранения он выполняет применимые read-only проверки DNS, TLS,
аутентификации, RCI, доступности конфигурации и ограниченный набор диагностик.
В итоговом экране нет пароля или пути к файлу секрета. При возможности пароль сохраняется
в системном хранилище ключей; переход к owner-only файлу требует отдельного
подтверждения. После успешного сохранения мастер может зарегистрировать профиль
в Codex, Claude или обоих клиентах; по умолчанию не выбран ни один. Не
вставляйте пароль, учётные данные endpoint или путь к файлу секрета в AI-чат.

`router snapshot <profile-id>` выполняет явную read-only проверку роутера и
сохраняет локальный минимизированный снимок: агрегаты интерфейсов, маршрутов,
DNS, VPN, Wi-Fi, устройств и системы, а также checksums конфигурации. Строки
конфигурации, логи, адреса, имена устройств, SSID и идентификаторы интерфейсов
не сохраняются. На роутер действует retention: 96 снимков, 30 дней и 1 MiB.

Для отдельного пользователя роутера включите право **HTTP Proxy**. Для режима
только чтения дополнительно включите **Запретить сохранять настройки системы**.
Этот флаг сам по себе не запрещает менять running configuration, поэтому
созданный мастером MCP-профиль остается read-only и не публикует инструменты
изменения.

Для контейнера или другого неинтерактивного запуска укажите настройки одного процесса явно:

~~~sh
export KEENETIC_URL=https://rci.example.net/rci/
export KEENETIC_USER=router_operator
export KEENETIC_PASSWORD_FILE=/run/secrets/keenetic-router
node dist/index.js --read-only
~~~

Для LAN вместо KEENETIC_URL используйте KEENETIC_HOST. Удалённый endpoint должен работать по HTTPS и оканчиваться на /rci/. Настройка KeenDNS описана в [Remote RCI](docs/REMOTE_RCI.md).

### Модель безопасности

- Начинайте с --read-only: в этом режиме инструменты изменения не регистрируются.
- Реальное изменение требует dry_run=false и confirm=true.
- Перед первой реальной записью сервер создаёт резервную копию стартовой конфигурации. Если копия недоступна, изменение блокируется.
- Каждое поддерживаемое изменение читается обратно и проверяется. Сервер никогда не вызывает save_config автоматически.
- Удалённый доступ к RCI не гарантирует доступа к вспомогательному endpoint резервной копии. При такой недоступности используйте LAN-профиль.
- Логи и любые строки, полученные от роутера, являются недоверенными данными, а не инструкциями.
- MCP-сервер не создаёт снимки автоматически. `router snapshot` — отдельная явная CLI-операция, записывающая owner-only локальное состояние.

Перед включением записи изучите полную [модель безопасности](docs/SAFETY.md) и [политику безопасности](SECURITY.md).

### Разработка

~~~sh
npm ci
npm run typecheck
npm test
npm run build
git diff --check
~~~

Необязательная удалённая smoke-проверка выполняется только на чтение:

~~~sh
npm run smoke:remote
npm run smoke:remote -- --router <profile-id>
~~~

Без аргументов используются default remote-профиль и его secret store;
`--router` выбирает другой remote-профиль. Полный набор KEENETIC_TEST_URL,
KEENETIC_TEST_USER и KEENETIC_TEST_PASSWORD имеет приоритет в CI. В итоге выводятся только
формы ответов, статусы и счётчики - без строк лога, адресов, alias устройств и
endpoint. Никогда не выполняйте реальные изменения роутера в тестах или smoke-проверках.

### Документация и вклад

- [Инструменты](docs/TOOLS.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Настройка Remote RCI](docs/REMOTE_RCI.md)
- [Несколько роутеров](docs/MULTI_ROUTER.md)
- [Участие в разработке](CONTRIBUTING.md)
- [Сообщение об уязвимости](SECURITY.md)
- [Уведомления о стороннем коде](THIRD_PARTY_NOTICES.md)

Приветствуются issue и pull request. Перед публикацией удаляйте из отчётов и фикстур реальные IP-адреса, MAC-адреса, SSID, пароли, ключи, cookies и конфигурацию роутера.

Проект распространяется по [лицензии MIT](LICENSE). В нём используется адаптированный MIT-лицензированный код; обязательное уведомление сохранено в [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
