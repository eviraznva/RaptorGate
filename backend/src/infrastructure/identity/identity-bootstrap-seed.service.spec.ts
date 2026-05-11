import { jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import type {
  IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { ISecretStoreRepository } from '../../domain/repositories/secret-store.repository.js';
import type { Env } from '../../shared/config/env.validation.js';
import type { ISecretCryptoService } from '../../application/ports/secret-crypto.service.js';
import { IdentityBootstrapSeedService } from './identity-bootstrap-seed.service.js';

describe('IdentityBootstrapSeedService', () => {
  const envValues: Partial<Env> = {
    RADIUS_HOST: '192.168.20.30',
    RADIUS_PORT: 1812,
    RADIUS_TIMEOUT_MS: 3000,
    RADIUS_RETRIES: 1,
    RADIUS_SECRET: 'radiussecret',
    RADIUS_NAS_IP: '192.168.20.254',
    RADIUS_NAS_IDENTIFIER: 'raptorgate',
    IDENTITY_LDAP_ENABLED: true,
    IDENTITY_GROUP_SOURCE_PRIMARY: 'ldap',
    IDENTITY_LDAP_HOST: '192.168.20.40',
    IDENTITY_LDAP_PORT: 389,
    IDENTITY_LDAP_BIND_DN: 'cn=admin,dc=raptorgate,dc=local',
    IDENTITY_LDAP_BIND_PASSWORD: 'admin',
    IDENTITY_LDAP_USER_BASE_DN: 'ou=users,dc=raptorgate,dc=local',
    IDENTITY_LDAP_USER_FILTER_ATTRIBUTE: 'uid',
    IDENTITY_LDAP_GROUP_BASE_DN: 'ou=groups,dc=raptorgate,dc=local',
    IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE: 'memberUid',
    IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE: 'cn',
    IDENTITY_LDAP_TIMEOUT_MS: 3000,
    IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS: 300,
    IDENTITY_SESSION_TTL_SECONDS: 1800,
  };

  function configService(): ConfigService<Env, true> {
    return {
      get: jest.fn((key: keyof Env) => envValues[key]),
    } as unknown as ConfigService<Env, true>;
  }

  beforeAll(() => {
    jest.useFakeTimers().setSystemTime(new Date('2026-04-30T10:00:00.000Z'));
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('writes env seed once when identity config storage is missing', async () => {
    const repository = {
      exists: jest.fn(async () => false),
      overwrite: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const secretRepository = {
      exists: jest.fn(async () => false),
      save: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<ISecretStoreRepository>;
    const secretCryptoService = {
      encrypt: jest.fn(() => ({
        ciphertext: 'ciphertext',
        iv: 'iv',
        authTag: 'auth-tag',
      })),
    } as unknown as jest.Mocked<ISecretCryptoService>;
    const service = new IdentityBootstrapSeedService(
      repository,
      configService(),
      secretRepository,
      secretCryptoService,
    );

    await service.onModuleInit();

    expect(repository.overwrite).toHaveBeenCalledTimes(1);
    const config = repository.overwrite.mock.calls[0][0];
    expect(config.getRadiusServerProfiles()[0].getSharedSecretRef()).toBe(
      'secret://identity/radius/default',
    );
    expect(config.getLdapServerProfiles()[0].getBindPasswordRef()).toBe(
      'secret://identity/ldap/default',
    );
    expect(config.getSettings().getPortalAuthenticationProfileId()).toBe(
      'default-portal-radius',
    );
    expect(config.getRadiusServerProfiles()[0].getCreatedAt()).toEqual(
      new Date('2026-04-30T10:00:00.000Z'),
    );
    expect(secretRepository.save).toHaveBeenCalledTimes(2);
  });

  it('does not overwrite existing identity config storage', async () => {
    const repository = {
      exists: jest.fn(async () => true),
      overwrite: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const service = new IdentityBootstrapSeedService(
      repository,
      configService(),
      { exists: jest.fn(), save: jest.fn() } as unknown as ISecretStoreRepository,
      { encrypt: jest.fn() } as unknown as ISecretCryptoService,
    );

    await service.onModuleInit();

    expect(repository.overwrite).not.toHaveBeenCalled();
  });

  it('does not seed ldap secret when ldap is disabled', async () => {
    const repository = {
      exists: jest.fn(async () => false),
      overwrite: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const secretRepository = {
      exists: jest.fn(async () => false),
      save: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<ISecretStoreRepository>;
    const secretCryptoService = {
      encrypt: jest.fn(() => ({
        ciphertext: 'ciphertext',
        iv: 'iv',
        authTag: 'auth-tag',
      })),
    } as unknown as jest.Mocked<ISecretCryptoService>;
    const disabledEnv = {
      ...envValues,
      IDENTITY_LDAP_ENABLED: false,
    };
    const service = new IdentityBootstrapSeedService(
      repository,
      {
        get: jest.fn((key: keyof Env) => disabledEnv[key]),
      } as unknown as ConfigService<Env, true>,
      secretRepository,
      secretCryptoService,
    );

    await service.onModuleInit();

    expect(secretRepository.save).toHaveBeenCalledTimes(1);
    const config = repository.overwrite.mock.calls[0][0];
    expect(config.getLdapServerProfiles()).toEqual([]);
  });
});
