import { describe, expect, it } from 'vitest';
import {
  boundedArrayEnvelope,
  boundedStructuredEnvelope,
  filterConfigLines,
  searchConfigLines,
  selectConfigSection
} from '../../src/shape/config.js';

const CONFIG = [
  'system',
  '    hostname example',
  'interface WifiMaster0/AccessPoint0',
  '    ssid Example',
  'interface Wireguard1',
  '    wireguard peer peer-one',
  'dns-proxy',
  '    enabled'
];

describe('configuration shaping', () => {
  it.each([
    ['system', 'clock timezone UTC', 'system'],
    ['users', 'user agent', 'users'],
    ['dns', 'ip name-server 192.0.2.53', 'dns'],
    ['routing', 'ip policy Policy0', 'routing'],
    ['interfaces', 'interface Bridge0', 'interfaces']
  ] as const)('maps %s CLI roots to their section', (_name, opening, section) => {
    expect(selectConfigSection([opening, '    description selected'], section))
      .toHaveLength(2);
    expect(selectConfigSection([opening, '    description selected'],
      section === 'system' ? 'dns' : 'system')).toEqual([]);
  });

  it('preserves all lines and applies normalized literal filters', () => {
    const all = selectConfigSection(['system', '    description Café   Router'], 'all');
    expect(all).toHaveLength(2);
    expect(filterConfigLines(all, 'CAFE\u0301 ROUTER').map(line => line.lineNumber)).toEqual([2]);
    expect(filterConfigLines(all, '   ')).toEqual(all);
  });

  it('retains complete selected CLI blocks with original line numbers', () => {
    expect(selectConfigSection(CONFIG, 'wifi')).toEqual([
      { lineNumber: 3, text: 'interface WifiMaster0/AccessPoint0' },
      { lineNumber: 4, text: '    ssid Example' }
    ]);
    expect(selectConfigSection(CONFIG, 'vpn').map(line => line.lineNumber)).toEqual([5, 6]);
  });

  it('normalizes Unicode, case and whitespace and merges overlapping context', () => {
    const corpus = selectConfigSection(['system', '    hostname Café Router',
      '    description CAFE\u0301   ROUTER'], 'all');
    const result = searchConfigLines(corpus, 'café router', 50, 1);
    expect(result.totalMatches).toBe(2);
    expect(result.shownMatches).toBe(2);
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0]?.lines.filter(line => line.match)).toHaveLength(2);
  });

  it('reports match-limit truncation independently of merged group count', () => {
    const corpus = selectConfigSection(Array.from({ length: 100 }, (_, index) =>
      `match ${index}`), 'all');
    const found = searchConfigLines(corpus, 'match', 50, 0);
    expect(found).toMatchObject({ shownMatches: 50, totalMatches: 100 });
    const envelope = boundedArrayEnvelope({ shownMatches: found.shownMatches,
      totalMatches: found.totalMatches }, 'groups', found.groups, 25_000, found.groups.length,
    found.shownMatches < found.totalMatches);
    expect(envelope['truncated']).toBe(true);
  });

  it('does not merge search context across omitted section blocks', () => {
    const lines = ['interface WifiMaster0/AccessPoint0', '    ssid first',
      'dns-proxy', '    enabled', 'interface WifiMaster0/AccessPoint1', '    ssid second'];
    const corpus = selectConfigSection(lines, 'wifi');
    const result = searchConfigLines(corpus, 'ssid', 50, 2);
    expect(result.groups).toHaveLength(2);
    expect(result.groups.map(group => [group.startLine, group.endLine])).toEqual([[1, 2], [5, 6]]);
  });

  it('accounts for the complete pretty-printed envelope when truncating', () => {
    const result = boundedArrayEnvelope({ source: 'running' }, 'lines',
      Array.from({ length: 50 }, () => '😀'.repeat(20)), 500);
    expect(Buffer.byteLength(JSON.stringify(result, null, 2), 'utf8')).toBeLessThanOrEqual(500);
    expect(result['truncated']).toBe(true);
  });

  it('applies structured entry and byte limits without losing the envelope', () => {
    const data = Object.fromEntries(Array.from({ length: 20 }, (_, index) =>
      [`branch-${index}`, { value: `данные-${index}-${'x'.repeat(50)}` }]));
    const result = boundedStructuredEnvelope({ source: 'running', format: 'structured',
      section: 'all', available: true, method: 'rci-root', omittedBranches: [] }, data, 10, 250);
    expect(Buffer.byteLength(JSON.stringify(result, null, 2), 'utf8')).toBeLessThanOrEqual(250);
    expect(result).toMatchObject({ source: 'running', format: 'structured', section: 'all',
      method: 'rci-root', total: 20, truncated: true });
    expect((result['shown'] as number)).toBeLessThanOrEqual(10);
  });
});
