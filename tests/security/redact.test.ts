import { describe, expect, it } from 'vitest';
import { redact, redactConfigLines, redactStructuredConfig, redactText } from '../../src/security/redact.js';

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
  it('uses the strict secret-key policy for every object output', () => {
    const output = redact({ snmp: { community: 'community-value' },
      radius: { 'shared-secret': 'shared-value', 'auth-key': 'auth-value' },
      oauth: { 'client-secret': 'client-value', 'api-token': 'token-value',
        'password-hash': 'hash-value', 'secret-key': 'secret-value',
        clientSecret: 'camel-client', apiToken: 'camel-token', passwordHash: 'camel-hash',
        secretKey: 'camel-secret', 'public-key': 'public-value', publicKey: 'camel-public' } });
    expect(JSON.stringify(output)).not.toMatch(/community-value|shared-value|auth-value|client-value|token-value|hash-value|secret-value|camel-client|camel-token|camel-hash|camel-secret/);
    expect(output.oauth['public-key']).toBe('public-value');
    expect(output.oauth.publicKey).toBe('camel-public');
  });
  it('does not let a public-key suffix override an earlier sensitive component', () => {
    const output = redact({ 'password-public-key': 'first-secret',
      privateKeyPublicKey: 'second-secret', 'wireguard-public-key': 'public-value' });
    expect(JSON.stringify(output)).not.toMatch(/first-secret|second-secret/);
    expect(output['wireguard-public-key']).toBe('public-value');
  });
  it('redacts strict key variants in free-form errors', () => {
    const output = redactText('shared-secret=one auth_key:two community=three');
    expect(output).not.toMatch(/one|two|three/);
  });
  it('redacts camelCase labels and quoted values in free-form errors', () => {
    const output = redactText(
      'clientSecret=one apiToken:"two words" passwordHash=three secretKey=\'four words\''
    );
    expect(output).not.toMatch(/one|two words|three|four words/);
  });
  it('redacts arbitrary key labels without masking public-key labels or safe words', () => {
    const output = redactText(
      'apiKey=one accessKey:"two words" signingKey=three publicKey=four ' +
      'wireguard-public-key=five monkey=six hockey=seven'
    );
    expect(output).not.toMatch(/one|two words|three/);
    expect(output).toContain('publicKey=four');
    expect(output).toContain('wireguard-public-key=five');
    expect(output).toContain('monkey=six');
    expect(output).toContain('hockey=seven');
  });
  it('redacts acronym-prefixed key labels in objects and free-form text', () => {
    const object = redact({ APIKey: 'one', HMACKey: 'two', SSHKey: 'three' });
    expect(JSON.stringify(object)).not.toMatch(/one|two|three/);
    const text = redactText('APIKey=one HMACKey:"two words" SSHKey=three');
    expect(text).not.toMatch(/one|two words|three/);
  });
  it('removes URL credentials, query secrets, fragments and complete authorization values', () => {
    const output = redactText(
      'https://alice:swordfish@example.test/path?token=private#fragment Authorization: Bearer short-secret'
    );
    expect(output).toContain('https://example.test/path');
    expect(output).not.toMatch(/alice|swordfish|token=|fragment|short-secret|Bearer/);
    expect(redactText('Authorization: Basic c2hvcnQ=')).not.toContain('c2hvcnQ');
    expect(redactText('Authorization=Bearer short-secret next')).not.toMatch(/short-secret|Bearer|next/);
    expect(redactText('authorization = Basic c2hvcnQ= next')).not.toMatch(/c2hvcnQ|Basic|next/);
  });
});

describe('configuration redaction', () => {
  it('redacts positional Keenetic CLI secrets before projection or search', () => {
    const lines = [
      'user agent password short-secret',
      '    wpa-psk "two words"',
      '    private-key abc123',
      '    preshared-key xyz789'
    ];
    const output = redactConfigLines(lines).join('\n');
    expect(output).not.toMatch(/short-secret|two words|abc123|xyz789/);
    expect(output.match(/\[REDACTED\]/g)).toHaveLength(4);
    expect(lines[0]).toContain('short-secret');
  });

  it('redacts complete private-key blocks', () => {
    const output = redactConfigLines([
      '-----BEGIN PRIVATE KEY-----',
      'private-material',
      '-----END PRIVATE KEY-----',
      'system'
    ]);
    expect(output.join('\n')).not.toContain('private-material');
    expect(output.at(-1)).toBe('system');
  });

  it('preserves indentation of a redacted key block for section parsing', () => {
    expect(redactConfigLines(['interface Wireguard1', '    -----BEGIN PRIVATE KEY-----',
      '    material', '    -----END PRIVATE KEY-----', '    description tunnel'])).toEqual([
      'interface Wireguard1',
      '    [REDACTED_PRIVATE_KEY_BLOCK]',
      '    [REDACTED_PRIVATE_KEY_BLOCK]',
      '    [REDACTED_PRIVATE_KEY_BLOCK]',
      '    description tunnel'
    ]);
  });

  it('redacts continuations of unterminated quoted CLI secrets', () => {
    const output = redactConfigLines(['private-key "first line', 'second', 'end"',
      "secret 'third line", 'fourth', "end'", 'system'])
      .join('\n');
    expect(output).not.toMatch(/first|second|third|fourth/);
    expect(output).toContain('system');
  });

  it('uses a stronger secret-key policy for structured configuration', () => {
    const output = redactStructuredConfig({ snmp: { community: 'community-value' },
      radius: { 'shared-secret': 'shared-value', 'auth-key': 'auth-value' } });
    expect(JSON.stringify(output)).not.toMatch(/community-value|shared-value|auth-value/);
  });
});
