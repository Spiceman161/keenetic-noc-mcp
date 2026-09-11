import { describe, expect, it, vi, afterEach } from 'vitest';
import { Rci, collectStatuses } from '../../src/router/rci.js';
import { AuthError, RciError } from '../../src/router/errors.js';
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

  it('cancels a chunked response that exceeds the requested bound', async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"value":"'));
        controller.enqueue(new TextEncoder().encode('too large"}'));
      },
      cancel() { cancelled = true; }
    });
    const rci = new Rci({ request: async () => new Response(body, { headers: { 'content-type': 'application/json' } }) });
    await expect(rci.get('show/version', 10)).rejects.toMatchObject({ code: 'response-too-large' });
    expect(cancelled).toBe(true);
  });

  it('preserves the legacy unbounded default outside explicit preflight reads', async () => {
    const body = JSON.stringify({ value: 'x'.repeat(1_000_100) });
    const rci = new Rci(sessionReturning(body));
    await expect(rci.get<{ value: string }>('show/large')).resolves.toMatchObject({ value: expect.any(String) });
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

describe('Rci.post', () => {
  it('applies an optional input byte ceiling to read-only dispatcher responses', async () => {
    const rci = new Rci(sessionReturning(JSON.stringify({ value: 'x'.repeat(100) })));
    await expect(rci.post({ show: { log: {} } }, 20)).rejects.toMatchObject({
      code: 'response-too-large'
    });
  });
});

describe('Rci.runContinued', () => {
  it('starts once, polls bounded chunks, and returns accumulated messages', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: ['started'], continued: true })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: ['reply'], continued: true })))
      .mockResolvedValueOnce(new Response('{}'));
    const result = await new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024, { timeoutMs: 5_000 });
    expect(result).toMatchObject({ messages: ['started', 'reply'], polls: 2,
      termination: 'completed', effectiveTimeoutMs: 5_000 });
    expect(request.mock.calls.map(call => call[0])).toEqual(['POST', 'GET', 'GET']);
  });

  it('sends the native DELETE cancellation after an active job fails', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: ['started'], continued: true })))
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024, { timeoutMs: 5_000 }))
      .rejects.toThrow('offline');
    expect(request.mock.calls.at(-1)?.slice(0, 2)).toEqual(['DELETE', '/rci/tools/ping']);
  });

  it('preserves a deterministic start HTTP error without issuing DELETE', async () => {
    const request = vi.fn().mockResolvedValue(new Response('{}', { status: 404 }));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ code: '404' });
    expect(request).toHaveBeenCalledOnce();
  });

  it.each([
    { status: 'error', code: 'bad', ident: 'tool' },
    { wrapper: { status: [{ status: 'error', code: 'bad', ident: 'tool' }] } }
  ])('preserves a deterministic start RCI rejection without DELETE', async payload => {
    const request = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ code: 'bad' });
    expect(request).toHaveBeenCalledOnce();
  });

  it('preserves a deterministic start authentication error without issuing DELETE', async () => {
    const auth = new AuthError('credentials rejected');
    const request = vi.fn().mockRejectedValue(auth);
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024)).rejects.toBe(auth);
    expect(request).toHaveBeenCalledOnce();
  });

  it('attempts cleanup when authentication fails after the start was acknowledged', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ continued: true })))
      .mockRejectedValueOnce(new AuthError('session expired'))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024)).rejects.toBeInstanceOf(AuthError);
    expect(request.mock.calls.map(call => call[0])).toEqual(['POST', 'GET', 'DELETE']);
  });

  it('attempts cleanup when an RCI rejection arrives after the start', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ continued: true })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: 'error', code: 'bad' })))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ code: 'bad' });
    expect(request.mock.calls.map(call => call[0])).toEqual(['POST', 'GET', 'DELETE']);
  });

  it('does not poll after a chunk exhausts the aggregate input budget', async () => {
    const first = JSON.stringify({ message: ['reply'], continued: true });
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(first))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, Buffer.byteLength(first)))
      .rejects.toMatchObject({ code: 'response-too-large' });
    expect(request.mock.calls.map(call => call[0])).toEqual(['POST', 'DELETE']);
  });

  it('reports uncertain state when native DELETE cancellation fails', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: ['started'], continued: true })))
      .mockRejectedValueOnce(new Error('offline'))
      .mockRejectedValueOnce(new Error('cancel failed'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024, { timeoutMs: 5_000 }))
      .rejects.toMatchObject({ name: 'ActiveDiagnosticUncertainError' });
  });

  it.each([
    { status: 'error', code: 'cancel-failed' },
    { wrapper: { status: [{ status: 'error', code: 'cancel-failed' }] } },
    { unexpected: true }
  ])('treats an unproven HTTP-success DELETE payload as uncertain', async payload => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ continued: true })))
      .mockRejectedValueOnce(new Error('poll failed'))
      .mockResolvedValueOnce(new Response(JSON.stringify(payload)));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ name: 'ActiveDiagnosticUncertainError' });
  });

  it('rejects malformed chunks instead of reporting success', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: { private: true } })))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ code: 'unexpected-response' });
  });

  it('rejects a non-empty unknown terminal object', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ unexpected: true })))
      .mockResolvedValueOnce(new Response('{}'));
    await expect(new Rci({ request }).runContinued('tools/ping',
      { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024))
      .rejects.toMatchObject({ code: 'unexpected-response' });
  });

  it('uses the session ceiling for the whole job and preserves partial timeout output', async () => {
    vi.useFakeTimers();
    try {
      const request = vi.fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({ message: ['reply'], continued: true })))
        .mockResolvedValueOnce(new Response('{}'));
      const session = { request, effectiveTimeoutMs: () => 100 };
      const pending = new Rci(session).runContinued('tools/ping',
        { host: '192.0.2.1', packetsize: 84, count: 1 }, 1024, { timeoutMs: 5_000 });
      await vi.advanceTimersByTimeAsync(101);
      await expect(pending).resolves.toMatchObject({ messages: ['reply'], termination: 'timeout',
        effectiveTimeoutMs: 100 });
      expect(request.mock.calls.at(-1)?.[0]).toBe('DELETE');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Rci.getConfig', () => {
  it('returns bounded JSON and its byte count', async () => {
    const body = JSON.stringify({ result: ['system'] });
    const rci = new Rci(sessionReturning(body));
    await expect(rci.getConfig('show/running-config', 1024)).resolves.toEqual({
      value: { result: ['system'] }, bytes: Buffer.byteLength(body)
    });
  });

  it('never includes an HTTP or RCI configuration body in errors', async () => {
    const secret = 'user agent password do-not-leak';
    const http = new Rci(sessionReturning(secret, 500));
    await expect(http.getConfig('show/running-config', 1024)).rejects.not.toThrow(secret);
    const embedded = new Rci(sessionReturning(JSON.stringify({ status: [{ status: 'error',
      code: secret, ident: secret, message: secret }] })));
    await expect(embedded.getConfig('show/running-config', 1024)).rejects.not.toThrow(secret);
  });

  it('cancels a body rejected by its declared content length', async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode('{}')); },
      cancel() { cancelled = true; }
    });
    const rci = new Rci({ request: async () => new Response(body, {
      headers: { 'content-type': 'application/json', 'content-length': '1000' }
    }) });
    await expect(rci.getConfig('show/running-config', 20)).rejects.toMatchObject({
      code: 'response-too-large'
    });
    expect(cancelled).toBe(true);
  });

  it('applies the input byte ceiling', async () => {
    const rci = new Rci(sessionReturning(JSON.stringify(['x'.repeat(100)])));
    await expect(rci.getConfig('show/running-config', 20)).rejects.toMatchObject({
      code: 'response-too-large'
    });
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
      bytes: Buffer.byteLength(body),
      payloadShape: 'array',
      payloadItems: 3,
      payloadItemShape: 'string',
      wrapperDepth: 0
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
      bytes: Buffer.byteLength(body),
      payloadShape: 'string',
      payloadItems: 2,
      payloadItemShape: 'unknown',
      wrapperDepth: 0
    });
    expect(JSON.stringify(result)).not.toContain('interface');
  });

  it('classifies malformed JSON as an unexpected shape', async () => {
    const rci = new Rci(sessionReturning('{not-json'));

    await expect(rci.probeGet('show/running-config')).resolves.toMatchObject({
      httpStatus: 200, contentTypeClass: 'json', shape: 'unknown', items: null
    });
  });

  it('describes a single-key RCI wrapper without returning wrapper keys or payload', async () => {
    const privateLine = 'private configuration must not escape';
    const body = JSON.stringify({ command: { result: [privateLine, 'second line'] } });
    const rci = new Rci(sessionReturning(body));

    const result = await rci.probeGet('more?filename=startup-config');

    expect(result).toMatchObject({
      shape: 'object', items: 1, payloadShape: 'array', payloadItems: 2,
      payloadItemShape: 'string', wrapperDepth: 2
    });
    expect(JSON.stringify(result)).not.toContain('command');
    expect(JSON.stringify(result)).not.toContain('result');
    expect(JSON.stringify(result)).not.toContain(privateLine);
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

  it('does not retain an oversized probe payload', async () => {
    const rci = new Rci(sessionReturning(JSON.stringify(['a'.repeat(200)])));
    await expect(rci.probeGet('show/running-config', 64)).rejects.toMatchObject({ code: 'response-too-large' });
  });
});

describe('Rci.probeStartupFile', () => {
  it('uses the absolute CI path and returns metadata without file content', async () => {
    const privateLine = 'private startup configuration';
    const session = sessionReturning(`${privateLine}\n`, 200, 'text/plain');
    const request = vi.mocked(session.request);
    const result = await new Rci(session).probeStartupFile(256_000);

    expect(request).toHaveBeenCalledWith('GET', '/ci/startup-config.txt');
    expect(result).toMatchObject({ shape: 'string', payloadShape: 'string', items: 1 });
    expect(JSON.stringify(result)).not.toContain(privateLine);
  });

  it('applies the response byte ceiling', async () => {
    const rci = new Rci(sessionReturning('x'.repeat(100), 200, 'text/plain'));
    await expect(rci.probeStartupFile(20)).rejects.toMatchObject({ code: 'response-too-large' });
  });
});
