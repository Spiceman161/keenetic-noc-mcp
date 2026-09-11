import { describe, expect, it } from 'vitest';
import { parseSavedChecksum } from '../../src/router/config-state.js';

describe('saved configuration checksum parser', () => {
  it('extracts only a strict generated MD5 header from strings or lines', () => {
    const checksum = 'ABCDEF0123456789ABCDEF0123456789';
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${checksum}\ninterface private`))
      .toBe(checksum.toLowerCase());
    expect(parseSavedChecksum(['header', `! $$$ Md5 checksum: ${checksum}`]))
      .toBe(checksum.toLowerCase());
  });

  it('rejects malformed and non-header values', () => {
    expect(parseSavedChecksum('password=' + 'a'.repeat(32))).toBeNull();
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${'g'.repeat(32)}`)).toBeNull();
  });
});
