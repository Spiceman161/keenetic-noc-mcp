import { describe, expect, it } from 'vitest';
import { redact, redactText } from '../../src/security/redact.js';

describe('redaction', () => {
  it('redacts nested secrets without changing input', () => {
    const input = { peer: { 'private-key': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234', publicKey: 'short-public-id' }, password: 'hunter2' };
    expect(redact(input)).toEqual({ peer: { 'private-key': '[REDACTED]', publicKey: 'short-public-id' }, password: '[REDACTED]' });
    expect(input.password).toBe('hunter2');
  });
  it('redacts labelled values in errors', () => expect(redactText('password=oops token:abc')).toBe('password=[REDACTED] token=[REDACTED]'));
  it('redacts common Wi-Fi secret keys and quoted text values', () => {
    expect(redact({ key: 'short', passphrase: 'two words', 'wpa-psk': '12345678' })).toEqual({
      key: '[REDACTED]', passphrase: '[REDACTED]', 'wpa-psk': '[REDACTED]'
    });
    expect(redactText('passphrase="two words" key=short')).toBe('passphrase=[REDACTED] key=[REDACTED]');
  });
});
