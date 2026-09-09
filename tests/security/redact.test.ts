import { describe, expect, it } from 'vitest';
import { redact, redactText } from '../../src/security/redact.js';

describe('redaction', () => {
  it('redacts nested secrets without changing input', () => {
    const input = { peer: { 'private-key': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234', publicKey: 'short-public-id' }, password: 'hunter2' };
    expect(redact(input)).toEqual({ peer: { 'private-key': '[REDACTED]', publicKey: 'short-public-id' }, password: '[REDACTED]' });
    expect(input.password).toBe('hunter2');
  });
  it('redacts labelled values in errors', () => expect(redactText('password=oops token:abc')).toBe('password=[REDACTED] token=[REDACTED]'));
});
