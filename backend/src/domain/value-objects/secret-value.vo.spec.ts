import { SecretValue } from './secret-value.vo.js';

describe('SecretValue', () => {
  it('accepts and preserves a non-empty secret value', () => {
    const value = SecretValue.create('radiussecret');

    expect(value.getValue()).toBe('radiussecret');
  });

  it('rejects an empty secret value', () => {
    expect(() => SecretValue.create('')).toThrow();
  });

  it('rejects a secret value larger than 4096 bytes', () => {
    expect(() => SecretValue.create('x'.repeat(4097))).toThrow();
  });

  it('serializes as redacted text', () => {
    expect(JSON.stringify({ value: SecretValue.create('radiussecret') })).toBe(
      '{"value":"[redacted]"}',
    );
  });
});
