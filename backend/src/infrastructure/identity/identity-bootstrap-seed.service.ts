import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { Env } from '../../shared/config/env.validation.js';

@Injectable()
export class IdentityBootstrapSeedService implements OnModuleInit {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly configService: ConfigService<Env, true>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (await this.identityConfigRepository.exists()) return;

    await this.identityConfigRepository.overwrite(this.defaultFromEnv());
  }

  private defaultFromEnv(): IdentityConfiguration {
    const createdAt = new Date('1970-01-01T00:00:00.000Z');
    const createdBy = 'system';
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
      'env:RADIUS_SECRET',
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
            'env:IDENTITY_LDAP_BIND_PASSWORD',
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
}
