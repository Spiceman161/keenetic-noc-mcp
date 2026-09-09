import { describe, expect, it } from 'vitest';
import { loadConfig, normalizeRemoteUrl } from '../../src/config/load.js';

describe('remote connection profile', () => {
  it.each(['https://rci.example.test', 'https://rci.example.test/', 'https://rci.example.test/rci', 'https://rci.example.test/rci/'])('normalizes %s', value => {
    expect(normalizeRemoteUrl(value)).toBe('https://rci.example.test/rci/');
  });
  it('rejects insecure, credential-bearing, and unexpected URLs', () => {
    expect(() => normalizeRemoteUrl('http://rci.example.test')).toThrow(/https/);
    expect(() => normalizeRemoteUrl('https://user:pass@rci.example.test')).toThrow(/credentials/);
    expect(() => normalizeRemoteUrl('https://rci.example.test/other')).toThrow(/path/);
  });
  it('selects remote mode from KEENETIC_URL', async () => {
    const config = await loadConfig([], { KEENETIC_URL: 'https://rci.example.test', KEENETIC_PASSWORD: 'test-only' });
    expect(config).toMatchObject({ mode: 'remote', endpoint: 'https://rci.example.test/rci/', routerId: 'home' });
  });
});
