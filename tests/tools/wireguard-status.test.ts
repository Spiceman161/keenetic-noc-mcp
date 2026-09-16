import { describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { AuthError, RciError, TransportError } from '../../src/router/errors.js';
import type { KeeneticClient } from '../../src/router/client.js';
import type { ToolContext, ToolResult } from '../../src/tools/registry.js';
import { registerVpnTools } from '../../src/tools/vpn.js';
import { stubBackup } from '../helpers/backup.js';

type StatusHandler = () => Promise<ToolResult>;

function harness(value: unknown, maxResponseBytes = 25_000): {
  get: ReturnType<typeof vi.fn>;
  handler: StatusHandler;
  config: Record<string, unknown>;
} {
  const get = vi.fn(async () => value);
  const client = { rci: { get } } as unknown as KeeneticClient;
  const ctx: ToolContext = { client, maxResponseBytes, readOnly: true, backup: stubBackup() };
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  let handler: StatusHandler | undefined;
  let config: Record<string, unknown> | undefined;
  vi.spyOn(server, 'registerTool').mockImplementation(((name: string, registered: unknown, callback: unknown) => {
    if (name === 'get_wireguard_status') {
      config = registered as Record<string, unknown>;
      handler = callback as StatusHandler;
    }
    return {} as never;
  }) as never);
  registerVpnTools(server, ctx);
  return { get, handler: handler!, config: config! };
}

function payload(result: ToolResult): any {
  return JSON.parse(result.content.map(part => part.text).join(''));
}

const topLevelKeys = [
  'schemaVersion', 'evidenceStatus', 'evidenceReason', 'peersObserved',
  'peersWithHandshakeEvidence', 'peersWithoutHandshakeEvidence',
  'peersWithUnknownHandshakeEvidence', 'peersWithInvalidHandshakeEvidence',
  'interfaces', 'shown', 'total', 'truncated'
].sort();
const interfaceKeys = [
  'id', 'state', 'link', 'defaultGateway', 'peerEvidenceStatus', 'peersObserved',
  'peersWithHandshakeEvidence', 'peersWithoutHandshakeEvidence',
  'peersWithUnknownHandshakeEvidence', 'peersWithInvalidHandshakeEvidence', 'peers',
  'peersShown', 'peersTotal', 'peersTruncated'
].sort();
const peerKeys = ['peerIndex', 'handshake', 'rxBytes', 'txBytes'].sort();
const forbiddenSentinels = [
  'SYNTHETIC_PRIVATE_KEY', 'SYNTHETIC_PSK', 'SYNTHETIC_PUBLIC_KEY', 'SYNTHETIC_PEER_ID',
  'SYNTHETIC_COLLECTION_KEY', 'SYNTHETIC_ENDPOINT', 'SYNTHETIC_ALLOWED_RANGE',
  'SYNTHETIC_RAW_PEER_OBJECT', 'SYNTHETIC_STABLE_ID', 'SYNTHETIC_HASH', 'SYNTHETIC_FINGERPRINT'
];

function peerWithSentinels(): Record<string, unknown> {
  return {
    'preshared-key': forbiddenSentinels[1], 'public-key': forbiddenSentinels[2],
    id: forbiddenSentinels[3], endpoint: forbiddenSentinels[5],
    'allowed-ips': [forbiddenSentinels[6]], raw: forbiddenSentinels[7],
    stable: forbiddenSentinels[8], hash: forbiddenSentinels[9], fingerprint: forbiddenSentinels[10],
    'last-handshake': 1, rxbytes: 0, txbytes: 1
  };
}

function sentinelSource(peerCount = 1): Record<string, unknown> {
  return {
    Wireguard0: {
      type: 'Wireguard', wireguard: {
        'private-key': forbiddenSentinels[0],
        peer: Object.fromEntries(Array.from({ length: peerCount }, (_, index) => [
          `${forbiddenSentinels[4]}_${index}`, peerWithSentinels()
        ]))
      }
    }
  };
}

function assertNoSentinels(value: unknown): void {
  const text = JSON.stringify(value);
  for (const sentinel of forbiddenSentinels) expect(text).not.toContain(sentinel);
}

function envelope(value: Record<string, unknown>): Record<string, unknown> {
  return {
    evidenceStatus: value.evidenceStatus,
    evidenceReason: value.evidenceReason,
    peersObserved: value.peersObserved,
    peersWithHandshakeEvidence: value.peersWithHandshakeEvidence,
    peersWithoutHandshakeEvidence: value.peersWithoutHandshakeEvidence,
    peersWithUnknownHandshakeEvidence: value.peersWithUnknownHandshakeEvidence,
    peersWithInvalidHandshakeEvidence: value.peersWithInvalidHandshakeEvidence,
    shown: value.shown,
    total: value.total,
    truncated: value.truncated
  };
}

function completeInterface(): Record<string, unknown> {
  return { type: 'Wireguard', wireguard: { peer: [{ 'last-handshake': 1 }] } };
}

describe('get_wireguard_status', () => {
  it('uses exactly one bounded interface read and projects only fixed safe evidence', async () => {
    const sentinels = [
      'SYNTHETIC_PRIVATE_KEY', 'SYNTHETIC_PSK', 'SYNTHETIC_PUBLIC_KEY', 'SYNTHETIC_PEER_ID',
      'SYNTHETIC_COLLECTION_KEY', 'SYNTHETIC_ENDPOINT', 'SYNTHETIC_ALLOWED_RANGE',
      'SYNTHETIC_STABLE_ID', 'SYNTHETIC_HASH', 'SYNTHETIC_FINGERPRINT'
    ];
    const { get, handler, config } = harness({
      Wireguard0: {
        type: 'Wireguard', state: 'up', link: 'down', defaultgw: true,
        wireguard: {
          'private-key': sentinels[0], peer: [{
            'preshared-key': sentinels[1], 'public-key': sentinels[2], id: sentinels[3],
            endpoint: sentinels[5], 'allowed-ips': [sentinels[6]], stable: sentinels[7],
            hash: sentinels[8], fingerprint: sentinels[9], 'last-handshake': 99, rxbytes: 0, txbytes: 8
          }, { 'last-handshake': null, rxbytes: 1, txbytes: 2 }, {
            'last-handshake': 0, rxbytes: 3, txbytes: 4
          }, { 'last-handshake': 'unknown-unit', rxbytes: -1, txbytes: 1.5 }]
        }
      },
      OpenVPN0: { type: 'OpenVPN' },
      Future0: { type: 'FutureVPN', description: 'Wireguard' }
    });
    const result = await handler();
    const out = payload(result);

    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('show/interface', 256_000);
    expect(config).toMatchObject({ inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false } });
    expect(Object.keys(out).sort()).toEqual(topLevelKeys);
    expect(out).toMatchObject({
      schemaVersion: 1, evidenceStatus: 'complete', evidenceReason: null,
      peersObserved: 4, peersWithHandshakeEvidence: 1, peersWithoutHandshakeEvidence: 1,
      peersWithUnknownHandshakeEvidence: 1, peersWithInvalidHandshakeEvidence: 1,
      shown: 1, total: 1, truncated: false
    });
    expect(Object.keys(out.interfaces[0]).sort()).toEqual(interfaceKeys);
    expect(Object.keys(out.interfaces[0].peers[0]).sort()).toEqual(peerKeys);
    expect(out.interfaces[0]).toMatchObject({ id: 'Wireguard0', state: 'up', link: 'down', defaultGateway: true });
    expect(out.interfaces[0].peers).toEqual([
      { peerIndex: 1, handshake: 'present', rxBytes: 0, txBytes: 8 },
      { peerIndex: 2, handshake: 'absent', rxBytes: 1, txBytes: 2 },
      { peerIndex: 3, handshake: 'unknown', rxBytes: 3, txBytes: 4 },
      { peerIndex: 4, handshake: 'invalid', rxBytes: null, txBytes: null }
    ]);
    const text = JSON.stringify(out);
    for (const sentinel of sentinels) expect(text).not.toContain(sentinel);
    expect(text).not.toMatch(/age|fresh|stale|health|failure/i);
  });

  it.each([
    ['null', null], ['scalar', 'wrong'], ['array', [{ type: 'Wireguard' }]], ['empty', {}],
    ['no classification-valid row', { Wireguard0: { type: null } }]
  ])('returns controlled unavailable evidence for a %s root', async (_label, value) => {
    const { get, handler } = harness(value);
    expect(payload(await handler())).toEqual({
      schemaVersion: 1, evidenceStatus: 'unavailable', evidenceReason: 'unexpected-response',
      peersObserved: null, peersWithHandshakeEvidence: null, peersWithoutHandshakeEvidence: null,
      peersWithUnknownHandshakeEvidence: null, peersWithInvalidHandshakeEvidence: null,
      interfaces: [], shown: 0, total: null, truncated: false
    });
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('fails closed on malformed rows but retains exact WireGuard siblings', async () => {
    const { handler } = harness({
      Wireguard0: { type: 'Wireguard', state: ['up'], link: 'wrong', defaultgw: 'true', wireguard: { peer: [{ rxbytes: 2, txbytes: 3 }] } },
      BadArray: ['Wireguard'],
      BadType: { type: null },
      Lowercase: { type: 'wireguard', wireguard: { peer: [{ rxbytes: 4 }] } },
      NameOnly: { type: 'FutureVPN', description: 'Wireguard', wireguard: { peer: [{ rxbytes: 5 }] } }
    });
    const out = payload(await handler());
    expect(out).toMatchObject({ evidenceStatus: 'partial', evidenceReason: 'partial-data', total: 1 });
    expect(out.interfaces[0]).toMatchObject({ state: 'unknown', link: 'unknown', defaultGateway: null });
    expect(out.interfaces[0].peers).toEqual([{ peerIndex: 1, handshake: 'absent', rxBytes: 2, txBytes: 3 }]);
  });

  it('distinguishes complete empty peer evidence from unavailable and preserves a usable fallback as partial', async () => {
    const complete = payload(await harness({
      Wireguard0: { type: 'Wireguard', wireguard: { peer: [] }, peer: [{ rxbytes: 9 }] }
    }).handler());
    expect(complete).toMatchObject({ evidenceStatus: 'complete', peersObserved: 0 });
    expect(complete.interfaces[0]).toMatchObject({ peerEvidenceStatus: 'complete', peersTotal: 0, peers: [] });

    const fallback = payload(await harness({
      Wireguard0: { type: 'Wireguard', wireguard: { peer: true }, peer: [{ rxbytes: 9 }] }
    }).handler());
    expect(fallback).toMatchObject({ evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: 1 });
    expect(fallback.interfaces[0]).toMatchObject({ peerEvidenceStatus: 'partial', peersTotal: 1 });

    const unavailable = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: [null, []] } } }).handler());
    expect(unavailable).toMatchObject({ evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: null });
    expect(unavailable.interfaces[0]).toMatchObject({
      peerEvidenceStatus: 'unavailable', peersObserved: null, peersTotal: null, peers: []
    });
  });

  it('keeps valid peer siblings, rejects nested-array rows, and ignores peer-map keys', async () => {
    const { handler } = harness({
      Wireguard0: { type: 'Wireguard', wireguard: { peer: {
        SYNTHETIC_COLLECTION_KEY: { 'last-handshake': 1, rxbytes: Number.MAX_SAFE_INTEGER, txbytes: Infinity },
        ignored: null,
        nested: []
      } } }
    });
    const out = payload(await handler());
    expect(out).toMatchObject({ evidenceStatus: 'partial', peersObserved: 1 });
    expect(out.interfaces[0].peers).toEqual([{ peerIndex: 1, handshake: 'present', rxBytes: Number.MAX_SAFE_INTEGER, txBytes: null }]);
    expect(JSON.stringify(out)).not.toContain('SYNTHETIC_COLLECTION_KEY');
  });

  it('uses the status table for no-WireGuard, RCI, auth, and transport outcomes', async () => {
    expect(payload(await harness({ Future0: { type: 'FutureVPN' } }).handler())).toMatchObject({
      evidenceStatus: 'complete', evidenceReason: null, peersObserved: 0, total: 0
    });
    const tooLarge = harness(new RciError('bounded', { path: 'response', code: 'response-too-large', ident: 'rci' }));
    tooLarge.get.mockRejectedValueOnce(new RciError('bounded', { path: 'response', code: 'response-too-large', ident: 'rci' }));
    expect(envelope(payload(await tooLarge.handler()))).toEqual({
      evidenceStatus: 'unavailable', evidenceReason: 'response-too-large', peersObserved: null,
      peersWithHandshakeEvidence: null, peersWithoutHandshakeEvidence: null,
      peersWithUnknownHandshakeEvidence: null, peersWithInvalidHandshakeEvidence: null,
      shown: 0, total: null, truncated: false
    });

    const rci = harness(new RciError('missing', { path: 'show/interface', code: '404', ident: 'rci' }));
    rci.get.mockRejectedValueOnce(new RciError('missing', { path: 'show/interface', code: '404', ident: 'rci' }));
    expect(envelope(payload(await rci.handler()))).toEqual({
      evidenceStatus: 'unavailable', evidenceReason: 'rci-error', peersObserved: null,
      peersWithHandshakeEvidence: null, peersWithoutHandshakeEvidence: null,
      peersWithUnknownHandshakeEvidence: null, peersWithInvalidHandshakeEvidence: null,
      shown: 0, total: null, truncated: false
    });

    const auth = harness({}); auth.get.mockRejectedValueOnce(new AuthError('denied'));
    const transport = harness({}); transport.get.mockRejectedValueOnce(new TransportError('offline'));
    expect((await auth.handler()).isError).toBe(true);
    expect((await transport.handler()).isError).toBe(true);
  });

  it('reduces mixed interface evidence independently of map insertion order', async () => {
    const good = { type: 'Wireguard', wireguard: { peer: [{ 'last-handshake': 1 }] } };
    const unavailable = { type: 'Wireguard', wireguard: { peer: true } };
    const first = payload(await harness({ Good: good, Bad: { type: null }, Unavailable: unavailable }).handler());
    const second = payload(await harness({ Unavailable: unavailable, Bad: { type: null }, Good: good }).handler());
    for (const out of [first, second]) {
      expect(out).toMatchObject({ evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: 1 });
    }
  });

  it('bounds peer and interface detail while preserving complete aggregate evidence', async () => {
    const peers = Array.from({ length: 101 }, () => ({ 'last-handshake': 1, rxbytes: 0, txbytes: 0 }));
    const peerOnly = payload(await harness({
      Wireguard0: { type: 'Wireguard', wireguard: { peer: peers } }
    }).handler());
    expect(peerOnly).toMatchObject({ peersObserved: 101, truncated: false });
    expect(peerOnly.interfaces[0]).toMatchObject({ peersShown: 100, peersTotal: 101, peersTruncated: true });

    const interfaces = Object.fromEntries(Array.from({ length: 101 }, (_, index) => [
      `Wireguard${index}`, { type: 'Wireguard', wireguard: { peer: peers } }
    ]));
    const out = payload(await harness(interfaces).handler());
    expect(out).toMatchObject({
      evidenceStatus: 'complete', peersObserved: 10_201, peersWithHandshakeEvidence: 10_201,
      total: 101, truncated: true
    });
    expect(out.shown).toBeGreaterThan(0);
    expect(out.shown).toBeLessThanOrEqual(100);
    expect(out.interfaces[0]).toMatchObject({ peersTotal: 101, peersTruncated: true });
    expect(out.interfaces[0].peersShown).toBeLessThanOrEqual(100);
  });

  it('preserves the fixed envelope under the minimum response ceiling before dropping detail', async () => {
    const { handler } = harness({
      Wireguard0: { type: 'Wireguard', wireguard: { peer: Array.from({ length: 10 }, () => ({ 'last-handshake': 1 })) } }
    }, 512);
    const result = await handler();
    const text = result.content.map(part => part.text).join('');
    const out = JSON.parse(text);
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(512);
    expect(Object.keys(out).sort()).toEqual(topLevelKeys);
    expect(out).toMatchObject({ schemaVersion: 1, evidenceStatus: 'complete', evidenceReason: null, peersObserved: 10, truncated: true });
  });

  it.each([
    ['complete + complete', completeInterface(), completeInterface(),
      { evidenceStatus: 'complete', evidenceReason: null, peersObserved: 2, peersWithHandshakeEvidence: 2,
        peersWithoutHandshakeEvidence: 0, peersWithUnknownHandshakeEvidence: 0,
        peersWithInvalidHandshakeEvidence: 0, shown: 2, total: 2, truncated: false }],
    ['complete + partial', completeInterface(), { type: 'Wireguard', wireguard: { peer: [{ 'last-handshake': 1 }, null] } },
      { evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: 2, peersWithHandshakeEvidence: 2,
        peersWithoutHandshakeEvidence: 0, peersWithUnknownHandshakeEvidence: 0,
        peersWithInvalidHandshakeEvidence: 0, shown: 2, total: 2, truncated: false }],
    ['complete + unavailable', completeInterface(), { type: 'Wireguard', wireguard: { peer: true } },
      { evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: 1, peersWithHandshakeEvidence: 1,
        peersWithoutHandshakeEvidence: 0, peersWithUnknownHandshakeEvidence: 0,
        peersWithInvalidHandshakeEvidence: 0, shown: 2, total: 2, truncated: false }],
    ['unavailable + unavailable', { type: 'Wireguard', wireguard: { peer: true } }, { type: 'Wireguard', wireguard: { peers: null } },
      { evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: null, peersWithHandshakeEvidence: null,
        peersWithoutHandshakeEvidence: null, peersWithUnknownHandshakeEvidence: null,
        peersWithInvalidHandshakeEvidence: null, shown: 2, total: 2, truncated: false }]
  ])('reduces %s independently of interface-map order', async (_label, first, second, expected) => {
    const outcomes = await Promise.all([
      harness({ First: first, Second: second }).handler().then(payload),
      harness({ Second: second, First: first }).handler().then(payload)
    ]);
    for (const out of outcomes) {
      expect(envelope(out)).toEqual(expected);
      expect(out.evidenceReason).not.toBeUndefined();
      expect(JSON.stringify(out)).not.toContain('not-supported');
    }
    expect(envelope(outcomes[0])).toEqual(envelope(outcomes[1]));
  });

  it.each([
    ['array', []], ['null', null], ['scalar', 'SYNTHETIC_MALFORMED_OUTER']
  ])('keeps direct fallback evidence partial for a present malformed outer %s container in either property order', async (_label, outer) => {
    for (const directName of ['peer', 'peers']) {
      const fallback = [{ 'last-handshake': 1, rxbytes: 3, txbytes: 4 }];
      const rows = [
        { type: 'Wireguard', wireguard: outer, [directName]: fallback },
        { type: 'Wireguard', [directName]: fallback, wireguard: outer }
      ];
      for (const row of rows) {
        const tested = harness({ Wireguard0: row });
        const out = payload(await tested.handler());
        expect(envelope(out)).toEqual(expect.objectContaining({
          evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: 1,
          peersWithHandshakeEvidence: 1, total: 1
        }));
        expect(out.interfaces).toHaveLength(1);
        expect(out.interfaces[0]).toMatchObject({
          peerEvidenceStatus: 'partial', peersTotal: 1,
          peers: [{ peerIndex: 1, handshake: 'present', rxBytes: 3, txBytes: 4 }]
        });
        expect(tested.get.mock.calls).toEqual([['show/interface', 256_000]]);
        expect(JSON.stringify(out)).not.toContain('SYNTHETIC_MALFORMED_OUTER');
      }
    }
  });

  it('distinguishes absent outer compatibility from malformed outer evidence and collapses unusable collections', async () => {
    const absent = payload(await harness({
      Wireguard0: { type: 'Wireguard', peer: [{ 'last-handshake': 1 }] }
    }).handler());
    expect(envelope(absent)).toEqual(expect.objectContaining({
      evidenceStatus: 'complete', evidenceReason: null, peersObserved: 1
    }));
    const presentRecord = payload(await harness({
      Wireguard0: { type: 'Wireguard', wireguard: {}, peer: [{ 'last-handshake': 1 }] }
    }).handler());
    expect(envelope(presentRecord)).toEqual(envelope(absent));

    for (const outer of [[], null, 0]) {
      const out = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: outer } }).handler());
      expect(envelope(out)).toEqual(expect.objectContaining({
        evidenceStatus: 'partial', evidenceReason: 'partial-data', peersObserved: null
      }));
      expect(out.interfaces[0]).toMatchObject({ peerEvidenceStatus: 'unavailable', peers: [], peersTotal: null });
    }

    const missing = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: {} } }).handler());
    const malformed = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: true } } }).handler());
    expect(missing.interfaces[0]).toEqual(malformed.interfaces[0]);
    expect(envelope(missing)).toEqual(envelope(malformed));
  });

  it.each([
    ['missing', undefined, 'absent'], ['null', null, 'absent'], ['zero', 0, 'unknown'],
    ['positive', 1, 'present'], ['large/future-looking', Number.MAX_SAFE_INTEGER, 'present'],
    ['negative', -1, 'invalid'], ['infinity', Infinity, 'invalid'], ['negative infinity', -Infinity, 'invalid'],
    ['NaN', NaN, 'invalid'], ['string', '1', 'invalid'], ['boolean', true, 'invalid'],
    ['object', {}, 'invalid'], ['array', [], 'invalid']
  ])('classifies every handshake shape without time or health inference', async (_label, value, expected) => {
    const peer: Record<string, unknown> = { rxbytes: 0, txbytes: 0 };
    if (value !== undefined) peer['last-handshake'] = value;
    const out = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: [peer] } } }).handler());
    expect(out.interfaces[0].peers[0]).toEqual({ peerIndex: 1, handshake: expected, rxBytes: 0, txBytes: 0 });
    expect(JSON.stringify(out)).not.toMatch(/age|fresh|stale|health|failure|rate|throughput|delta|reset|wrap/i);
  });

  it.each([
    ['missing', undefined, null], ['zero', 0, 0], ['maximum safe integer', Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
    ['negative', -1, null], ['fractional', 1.5, null], ['infinity', Infinity, null],
    ['NaN', NaN, null], ['unsafe integer', Number.MAX_SAFE_INTEGER + 1, null], ['string', '1', null],
    ['boolean', false, null], ['object', {}, null], ['array', [], null]
  ])('accepts only safe current counter shapes', async (_label, value, expected) => {
    const peer: Record<string, unknown> = { 'last-handshake': 1 };
    if (value !== undefined) {
      peer.rxbytes = value;
      peer.txbytes = value;
    }
    const out = payload(await harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: [peer] } } }).handler());
    expect(out.interfaces[0].peers[0]).toEqual({ peerIndex: 1, handshake: 'present', rxBytes: expected, txBytes: expected });
    expect(JSON.stringify(out)).not.toMatch(/rate|throughput|delta|reset|wrap/i);
  });

  it('keeps every forbidden sentinel out of all focused output and error paths', async () => {
    const cases: Array<[string, ReturnType<typeof harness>]> = [
      ['complete', harness(sentinelSource())],
      ['partial', harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: [peerWithSentinels(), null] } } })],
      ['unavailable', harness({ Wireguard0: { type: 'Wireguard', wireguard: { peer: true, raw: forbiddenSentinels } } })],
      ['malformed outer', harness({ Wireguard0: { type: 'Wireguard', wireguard: [forbiddenSentinels], peer: [peerWithSentinels()] } })],
      ['peer truncation', harness(sentinelSource(101))],
      ['interface truncation', harness(Object.fromEntries(Array.from({ length: 101 }, (_, index) => [
        `Wireguard${index}`, sentinelSource().Wireguard0
      ])))],
      ['512-byte budget', harness(sentinelSource(101), 512)]
    ];
    const errorText = `private-key=${forbiddenSentinels.join(':')}`;
    const rci = harness(sentinelSource());
    rci.get.mockRejectedValueOnce(new RciError(errorText, { path: 'show/interface', code: '404', ident: 'rci' }));
    const auth = harness(sentinelSource()); auth.get.mockRejectedValueOnce(new AuthError(errorText));
    const transport = harness(sentinelSource()); transport.get.mockRejectedValueOnce(new TransportError(errorText));
    cases.push(['rci error', rci], ['auth error', auth], ['transport error', transport]);

    for (const [_label, tested] of cases) {
      const result = await tested.handler();
      assertNoSentinels(result);
      expect(tested.get.mock.calls).toEqual([['show/interface', 256_000]]);
    }
    const complete = payload(await harness(sentinelSource()).handler());
    expect(complete).toMatchObject({ evidenceStatus: 'complete', peersObserved: 1 });
  });
});
