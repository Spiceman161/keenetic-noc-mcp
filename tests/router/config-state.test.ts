import { describe, expect, it } from 'vitest';
import { parseSavedChecksum } from '../../src/router/config-state.js';

describe('saved configuration checksum parser', () => {
  it('extracts only a strict generated MD5 header from strings or lines', () => {
    const checksum = 'ABCDEF0123456789ABCDEF0123456789';
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${checksum}\ninterface private`))
      .toBe(checksum.toLowerCase());
    expect(parseSavedChecksum(['header', `! $$$ Md5 checksum: ${checksum}`]))
      .toBe(checksum.toLowerCase());
    expect(parseSavedChecksum(`! \t$$$\tMd5 checksum:\t${checksum}\t\r\ninterface private`))
      .toBe(checksum.toLowerCase());
  });

  it('rejects malformed and non-header values', () => {
    expect(parseSavedChecksum('password=' + 'a'.repeat(32))).toBeNull();
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${'g'.repeat(32)}`)).toBeNull();
  });

  it('rejects checksum prefixes with an appended token suffix', () => {
    const checksum = 'abcdef0123456789abcdef0123456789';
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${checksum}a`)).toBeNull();
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${checksum}!`)).toBeNull();
  });

  it.each(['$', '$$', '$$$$'])('rejects the non-exact marker %j', marker => {
    const checksum = 'abcdef0123456789abcdef0123456789';
    expect(parseSavedChecksum(`! ${marker} Md5 checksum: ${checksum}`)).toBeNull();
  });

  it.each([
    ['bare carriage return', '\r'],
    ['Unicode line separator', '\u2028'],
    ['Unicode paragraph separator', '\u2029']
  ])('rejects a valid header prefix followed by %s and a suffix', (_name, separator) => {
    const checksum = 'abcdef0123456789abcdef0123456789';
    expect(parseSavedChecksum(`! $$$ Md5 checksum: ${checksum}${separator}unexpected`)).toBeNull();
  });

  it.each([
    ['after the exclamation mark', `!\n$$$ Md5 checksum: abcdef0123456789abcdef0123456789`],
    ['after the dollar marker', `! $$$\nMd5 checksum: abcdef0123456789abcdef0123456789`],
    ['after the label', `! $$$ Md5 checksum:\nabcdef0123456789abcdef0123456789`]
  ])('rejects a header split across lines %s', (_where, value) => {
    expect(parseSavedChecksum(value)).toBeNull();
  });

  it.each(['\r', '\n', '\v', '\f'])('rejects vertical whitespace %j inside the header', whitespace => {
    const checksum = 'abcdef0123456789abcdef0123456789';
    expect(parseSavedChecksum(`!${whitespace}$$$ Md5 checksum: ${checksum}`)).toBeNull();
    expect(parseSavedChecksum(`! $$$${whitespace}Md5 checksum: ${checksum}`)).toBeNull();
    expect(parseSavedChecksum(`! $$$ Md5 checksum:${whitespace}${checksum}`)).toBeNull();
  });
});
