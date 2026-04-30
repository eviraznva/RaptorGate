import { SecretRef } from './secret-ref.vo.js';

describe('SecretRef', () => {
  it('accepts environment variable references', () => {
    expect(SecretRef.create('env:RADIUS_SECRET').getValue()).toBe(
      'env:RADIUS_SECRET',
    );
  });

  it('accepts managed secret references', () => {
    expect(SecretRef.create('secret://identity/radius/lab').getValue()).toBe(
      'secret://identity/radius/lab',
    );
  });

  it('rejects plaintext secret values', () => {
    expect(() => SecretRef.create('radiussecret')).toThrow();
  });
});
