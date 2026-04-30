import { jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import type {
  IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { Env } from '../../shared/config/env.validation.js';
import { IdentityBootstrapSeedService } from './identity-bootstrap-seed.service.js';

describe('IdentityBootstrapSeedService', () => {
  const envValues: Partial<Env> = {
    RADIUS_HOST: '192.168.20.30',
    RADIUS_PORT: 1812,
    RADIUS_TIMEOUT_MS: 3000,
    RADIUS_RETRIES: 1,
    RADIUS_NAS_IP: '192.168.20.254',
    RADIUS_NAS_IDENTIFIER: 'raptorgate',
    IDENTITY_LDAP_ENABLED: true,
    IDENTITY_GROUP_SOURCE_PRIMARY: 'ldap',
    IDENTITY_LDAP_HOST: '192.168.20.40',
    IDENTITY_LDAP_PORT: 389,
    IDENTITY_LDAP_BIND_DN: 'cn=admin,dc=raptorgate,dc=local',
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

  it('writes env seed once when identity config storage is missing', async () => {
    const repository = {
      exists: jest.fn(async () => false),
      overwrite: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const service = new IdentityBootstrapSeedService(
      repository,
      configService(),
    );

    await service.onModuleInit();

    expect(repository.overwrite).toHaveBeenCalledTimes(1);
    const config = repository.overwrite.mock.calls[0][0];
    expect(config.getRadiusServerProfiles()[0].getSharedSecretRef()).toBe(
      'env:RADIUS_SECRET',
    );
    expect(config.getLdapServerProfiles()[0].getBindPasswordRef()).toBe(
      'env:IDENTITY_LDAP_BIND_PASSWORD',
    );
    expect(config.getSettings().getPortalAuthenticationProfileId()).toBe(
      'default-portal-radius',
    );
  });

  it('does not overwrite existing identity config storage', async () => {
    const repository = {
      exists: jest.fn(async () => true),
      overwrite: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const service = new IdentityBootstrapSeedService(
      repository,
      configService(),
    );

    await service.onModuleInit();

    expect(repository.overwrite).not.toHaveBeenCalled();
  });
});
