import { describe, expect, it, vi, afterEach } from 'vitest';
import { Rci, collectStatuses } from '../../src/router/rci.js';
import { RciError } from '../../src/router/errors.js';
import { Session } from '../../src/router/session.js';

// A Response body can only be read once, so each call must get a fresh instance.
// mockResolvedValue would hand back the same object and the second read fails.
function sessionReturning(payload: string, status = 200, contentType = 'application/json'): Session {
  const session = new Session({ host: '192.0.2.1', login: 'admin', password: 'x' });
  vi.spyOn(session, 'request').mockImplementation(
    async () => new Response(payload, { status, headers: { 'content-type': contentType } })
  );
  return session;
}

afterEach(() => vi.restoreAllMocks());

describe('collectStatuses', () => {
  it('finds a status block at the top level', () => {
    const found = collectStatuses({
      status: [{ status: 'error', code: '6553609', ident: 'Network::Interface::Base', message: 'nope' }]
    });
    expect(found).toHaveLength(1);
    expect(found[0]?.code).toBe('6553609');
  });

  it('finds a status block nested inside the response tree', () => {
    const found = collectStatuses({ show: { interface: { status: [{ status: 'error', message: 'deep' }] } } });
    expect(found.map(s => s.message)).toEqual(['deep']);
  });

  it('does not double-count a status block', () => {
    const found = collectStatuses({ status: [{ status: 'error', message: 'once' }] });
    expect(found).toHaveLength(1);
  });

  it('returns nothing for a clean response', () => {
    expect(collectStatuses({ title: '5.1.3', ndw: { components: 'base,ip6' } })).toEqual([]);
  });
});

describe('Rci.get', () => {
  it('parses a successful response', async () => {
    const rci = new Rci(sessionReturning('{"title":"5.1.3"}'));
    await expect(rci.get('show/version')).resolves.toEqual({ title: '5.1.3' });
  });

  it('throws RciError when HTTP 200 carries status=error', async () => {
    const body = JSON.stringify({
      status: [
        {
          status: 'error',
          code: '6553609',
          ident: 'Network::Interface::Base',
          message: 'unable to find (empty)'
        }
      ]
    });
    const rci = new Rci(sessionReturning(body));
    await expect(rci.get('show/interface/stat')).rejects.toThrow(RciError);
    await expect(rci.get('show/interface/stat')).rejects.toThrow(/show\/interface\/stat/);
  });

  it('does not fail on a non-error status level', async () => {
    const body = JSON.stringify({ status: [{ status: 'message', message: 'interface renamed' }] });
    const rci = new Rci(sessionReturning(body));
    await expect(rci.get('interface/Bridge0')).resolves.toBeDefined();
  });

  it('throws RciError with a usable message on HTTP 404', async () => {
    const rci = new Rci(sessionReturning('', 404));
    await expect(rci.get('show/bogus')).rejects.toThrow(/does not exist/i);
  });

  it('throws RciError when the body is not JSON', async () => {
    const rci = new Rci(sessionReturning('==== Table: "nat" ===='));
    await expect(rci.get('show/netfilter')).rejects.toThrow(/not JSON/i);
  });
});

describe('Rci.getText', () => {
  it('returns plain text without JSON parsing', async () => {
    const rci = new Rci(sessionReturning('! $$$ Model: Keenetic Model\n'));
    await expect(rci.getText('/ci/startup-config.txt')).resolves.toContain('Keenetic Model');
  });

  it('throws RciError carrying the HTTP status when the fetch fails', async () => {
    const rci = new Rci(sessionReturning('', 403));
    await expect(rci.getText('/ci/startup-config.txt')).rejects.toThrow(/403/);
  });
});

describe('Rci.probeGet', () => {
  it('retains only response metadata for JSON arrays', async () => {
    const body = JSON.stringify(['system', 'interface', 'service']);
    const rci = new Rci(sessionReturning(body));

    await expect(rci.probeGet('show/running-config')).resolves.toEqual({
      httpStatus: 200,
      contentTypeClass: 'json',
      shape: 'array',
      items: 3,
      bytes: Buffer.byteLength(body)
    });
  });

  it('classifies a text-like response without returning its content', async () => {
    const body = 'system\ninterface\n';
    const rci = new Rci(sessionReturning(body, 200, 'text/plain'));

    const result = await rci.probeGet('more?filename=startup-config');

    expect(result).toEqual({
      httpStatus: 200,
      contentTypeClass: 'text',
      shape: 'string',
      items: 2,
      bytes: Buffer.byteLength(body)
    });
    expect(JSON.stringify(result)).not.toContain('interface');
  });

  it('classifies malformed JSON as an unexpected shape', async () => {
    const rci = new Rci(sessionReturning('{not-json'));

    await expect(rci.probeGet('show/running-config')).resolves.toMatchObject({
      httpStatus: 200, contentTypeClass: 'json', shape: 'unknown', items: null
    });
  });

  it('reports HTTP failures without including their response body', async () => {
    const privateBody = 'private configuration must not escape';
    const rci = new Rci(sessionReturning(privateBody, 404));

    const result = await rci.probeGet('more?filename=startup-config');

    expect(result).toMatchObject({ httpStatus: 404, shape: 'unknown', bytes: Buffer.byteLength(privateBody) });
    expect(JSON.stringify(result)).not.toContain(privateBody);
  });

  it('does not classify an embedded RCI error as an available object', async () => {
    const body = JSON.stringify({
      status: [{ status: 'error', code: '123', ident: 'Config', message: 'private detail' }]
    });
    const rci = new Rci(sessionReturning(body));

    await expect(rci.probeGet('show/running-config')).rejects.toMatchObject({
      name: 'RciError', code: '123', ident: 'Config'
    });
    await expect(rci.probeGet('show/running-config')).rejects.not.toThrow(/private detail/);
  });
});
