import { createRemoteClient } from '../src/router/client.js';
import { normalizeRemoteUrl } from '../src/config/load.js';

const endpoint = process.env['KEENETIC_TEST_URL'];
const login = process.env['KEENETIC_TEST_USER'];
const password = process.env['KEENETIC_TEST_PASSWORD'];
if (!endpoint || !login || !password) throw new Error('Set KEENETIC_TEST_URL, KEENETIC_TEST_USER and KEENETIC_TEST_PASSWORD.');
const client = createRemoteClient({ endpoint: normalizeRemoteUrl(endpoint), login, password, routerId: 'smoke', timeoutMs: 30_000 });
for (const path of ['show/version','show/system','show/interface','show/internet/status','show/ip/route','show/dns-proxy']) {
  await client.rci.get(path); process.stderr.write(`ok ${path}\n`);
}
try { await client.rci.post({ show: { log: {} } }); process.stderr.write('ok show log (read-only POST)\n'); }
catch (error) { process.stderr.write(`unsupported show log: ${(error as Error).message}\n`); process.exitCode = 2; }
try { await client.rci.getText('/ci/startup-config.txt'); process.stderr.write('ok /ci/startup-config.txt\n'); }
catch (error) { process.stderr.write(`unsupported /ci/startup-config.txt: ${(error as Error).message}\n`); process.exitCode = 2; }
