import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { SecretRecord } from '../../domain/entities/secret-record.entity.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import {
  SECRET_STORE_REPOSITORY_TOKEN,
  type ISecretStoreRepository,
} from '../../domain/repositories/secret-store.repository.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import {
  SECRET_CRYPTO_SERVICE_TOKEN,
  type ISecretCryptoService,
} from '../../application/ports/secret-crypto.service.js';
import type { Env } from '../../shared/config/env.validation.js';

const DEFAULT_RADIUS_SECRET_REF = 'secret://identity/radius/default';
const DEFAULT_LDAP_BIND_PASSWORD_REF = 'secret://identity/ldap/default';

@Injectable()
export class IdentityBootstrapSeedService implements OnModuleInit {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly configService: ConfigService<Env, true>,
    @Inject(SECRET_STORE_REPOSITORY_TOKEN)
    private readonly secretStoreRepository: ISecretStoreRepository,
    @Inject(SECRET_CRYPTO_SERVICE_TOKEN)
    private readonly secretCryptoService: ISecretCryptoService,
  ) {}

  async onModuleInit(): Promise<void> {
    if (await this.identityConfigRepository.exists()) return;

    const createdAt = new Date();
    const createdBy = 'system';
    const ldapEnabled = this.configService.get('IDENTITY_LDAP_ENABLED', {
      infer: true,
    });

    await this.seedSecret(
      DEFAULT_RADIUS_SECRET_REF,
      'RADIUS_SECRET',
      createdAt,
      createdBy,
    );

    if (ldapEnabled) {
      await this.seedSecret(
        DEFAULT_LDAP_BIND_PASSWORD_REF,
        'IDENTITY_LDAP_BIND_PASSWORD',
        createdAt,
        createdBy,
      );
    }

    await this.identityConfigRepository.overwrite(
      this.defaultFromEnv(createdAt, createdBy),
    );
  }

  private defaultFromEnv(createdAt: Date, createdBy: string): IdentityConfiguration {
    const ldapEnabled = this.configService.get('IDENTITY_LDAP_ENABLED', {
      infer: true,
    });
    const primaryGroupSource = this.configService.get(
      'IDENTITY_GROUP_SOURCE_PRIMARY',
      { infer: true },
    );
    const groupSource =
      ldapEnabled && primaryGroupSource === 'ldap' ? 'ldap' : 'radius_vsa';
    const ldapProfileId = groupSource === 'ldap' ? 'default-ldap' : null;

    const radiusProfile = RadiusServerProfile.create(
      'default-radius',
      'Default RADIUS',
      'Seeded from environment',
      true,
      this.configService.get('RADIUS_HOST', { infer: true }),
      this.configService.get('RADIUS_PORT', { infer: true }),
      DEFAULT_RADIUS_SECRET_REF,
      this.configService.get('RADIUS_TIMEOUT_MS', { infer: true }),
      this.configService.get('RADIUS_RETRIES', { infer: true }),
      this.configService.get('RADIUS_NAS_IP', { infer: true }),
      this.configService.get('RADIUS_NAS_IDENTIFIER', { infer: true }),
      null,
      createdAt,
      createdAt,
      createdBy,
    );

    const ldapProfiles = ldapEnabled
      ? [
          LdapServerProfile.create(
            'default-ldap',
            'Default LDAP',
            'Seeded from environment',
            true,
            this.configService.get('IDENTITY_LDAP_HOST', { infer: true }),
            this.configService.get('IDENTITY_LDAP_PORT', { infer: true }),
            'disabled',
            this.configService.get('IDENTITY_LDAP_BIND_DN', { infer: true }),
            DEFAULT_LDAP_BIND_PASSWORD_REF,
            this.configService.get('IDENTITY_LDAP_USER_BASE_DN', { infer: true }),
            this.configService.get('IDENTITY_LDAP_USER_FILTER_ATTRIBUTE', {
              infer: true,
            }),
            this.configService.get('IDENTITY_LDAP_GROUP_BASE_DN', { infer: true }),
            this.configService.get('IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE', {
              infer: true,
            }),
            this.configService.get('IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE', {
              infer: true,
            }),
            this.configService.get('IDENTITY_LDAP_TIMEOUT_MS', { infer: true }),
            this.configService.get('IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS', {
              infer: true,
            }),
            createdAt,
            createdAt,
            createdBy,
          ),
        ]
      : [];

    const authProfile = IdentityAuthenticationProfile.create(
      'default-portal-radius',
      'Default portal RADIUS',
      'Seeded from environment',
      true,
      'radius',
      'default-radius',
      ldapProfileId,
      groupSource,
      this.configService.get('IDENTITY_SESSION_TTL_SECONDS', { infer: true }),
      createdAt,
      createdAt,
      createdBy,
    );

    return IdentityConfiguration.create(
      [radiusProfile],
      ldapProfiles,
      [authProfile],
      IdentitySettings.create('default-portal-radius', null, createdAt, createdBy),
    );
  }

  private async seedSecret(
    ref: string,
    envKey: 'RADIUS_SECRET' | 'IDENTITY_LDAP_BIND_PASSWORD',
    createdAt: Date,
    createdBy: string,
  ): Promise<void> {
    if (await this.secretStoreRepository.exists(ref)) return;

    const encrypted = this.secretCryptoService.encrypt(
      SecretValue.create(this.configService.get(envKey, { infer: true })),
    );

    await this.secretStoreRepository.save(
      SecretRecord.create(
        ref,
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.authTag,
        createdAt,
        createdAt,
        createdBy,
      ),
    );
  }
}
