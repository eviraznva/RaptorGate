import { validate } from './env.validation.js';

describe('env validation identity secrets', () => {
  const validConfig = {
    JWT_SECRET: 'x'.repeat(32),
    REFRESH_TOKEN_SECRET: 'y'.repeat(32),
    COOKIE_SECRET: 'z'.repeat(32),
    SECRET_STORE_KEY: Buffer.alloc(32, 7).toString('base64'),
    RADIUS_SECRET: 'radiussecret',
    IDENTITY_LDAP_BIND_PASSWORD: 'admin',
  };

  it('requires a secret store key in all environments', () => {
    const { SECRET_STORE_KEY, ...config } = validConfig;

    expect(() => validate(config)).toThrow('Invalid environment variables');
  });

  it('rejects invalid secret store key material', () => {
    expect(() =>
      validate({
        ...validConfig,
        SECRET_STORE_KEY: Buffer.alloc(31, 7).toString('base64'),
      }),
    ).toThrow('Invalid environment variables');
  });

  it('requires explicit radius and ldap bootstrap secrets', () => {
    const { RADIUS_SECRET, IDENTITY_LDAP_BIND_PASSWORD, ...config } =
      validConfig;

    expect(() => validate(config)).toThrow('Invalid environment variables');
  });

  it('accepts explicit bootstrap secrets and secret store key', () => {
    expect(validate(validConfig).SECRET_STORE_KEY).toBe(
      validConfig.SECRET_STORE_KEY,
    );
  });
});
