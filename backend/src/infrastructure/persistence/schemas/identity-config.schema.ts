import { isoDateTimeSchema } from './_common.js';
import { z } from 'zod';
import { SECRET_REF_PATTERN } from '../../../domain/value-objects/secret-ref.vo.js';

const idSchema = z.string().min(1).max(128);
const nullableTextSchema = z.string().min(1).max(512).nullable();

export const RadiusServerProfileRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535),
    sharedSecretRef: z.string().regex(SECRET_REF_PATTERN),
    timeoutMs: z.number().int().positive(),
    retries: z.number().int().min(0),
    nasIp: nullableTextSchema,
    nasIdentifier: nullableTextSchema,
    calledStationId: nullableTextSchema,
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict();

export const LdapServerProfileRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535),
    tlsMode: z.enum(['disabled', 'starttls', 'ldaps']),
    bindDn: z.string().min(1).max(512),
    bindPasswordRef: z.string().regex(SECRET_REF_PATTERN),
    userBaseDn: z.string().min(1).max(512),
    userFilterAttribute: z.string().min(1).max(128),
    groupBaseDn: z.string().min(1).max(512),
    groupMemberAttribute: z.string().min(1).max(128),
    groupNameAttribute: z.string().min(1).max(128),
    timeoutMs: z.number().int().positive(),
    cacheTtlSeconds: z.number().int().positive(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict();

export const IdentityAuthenticationProfileRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    provider: z.enum(['radius', 'ldap', 'local']),
    radiusProfileId: idSchema.nullable(),
    ldapProfileId: idSchema.nullable(),
    groupSource: z.enum(['none', 'ldap', 'radius_vsa']),
    sessionTtlSeconds: z.number().int().positive(),
    adminRoleMappings: z.array(
      z.object({
        matchType: z.enum(['username', 'ldap_group', 'radius_vsa']),
        matchValue: z.string().min(1).max(256),
        role: z.enum(['super_admin', 'admin', 'operator', 'viewer']),
      }).strict(),
    ).default([]),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict();

export const IdentitySettingsRecordSchema = z
  .object({
    portalAuthenticationProfileId: idSchema.nullable(),
    adminAuthenticationProfileId: idSchema.nullable(),
    portalListener: z.object({
      enabled: z.boolean(),
      interfaceName: nullableTextSchema,
      zoneId: nullableTextSchema,
      bindAddress: nullableTextSchema,
      bindPort: z.number().int().min(1).max(65535),
    }).strict().default({
      enabled: false,
      interfaceName: null,
      zoneId: null,
      bindAddress: null,
      bindPort: 443,
    }),
    updatedAt: isoDateTimeSchema.nullable(),
    updatedBy: z.string().min(1).max(128).nullable(),
  })
  .strict();

export const IdentityConfigurationRecordSchema = z
  .object({
    radius_server_profiles: z.object({
      items: z.array(RadiusServerProfileRecordSchema),
    }).strict(),
    ldap_server_profiles: z.object({
      items: z.array(LdapServerProfileRecordSchema),
    }).strict(),
    authentication_profiles: z.object({
      items: z.array(IdentityAuthenticationProfileRecordSchema),
    }).strict(),
    settings: IdentitySettingsRecordSchema,
  })
  .strict();

export type RadiusServerProfileRecord = z.infer<
  typeof RadiusServerProfileRecordSchema
>;
export type LdapServerProfileRecord = z.infer<
  typeof LdapServerProfileRecordSchema
>;
export type IdentityAuthenticationProfileRecord = z.infer<
  typeof IdentityAuthenticationProfileRecordSchema
>;
export type IdentitySettingsRecord = z.infer<
  typeof IdentitySettingsRecordSchema
>;
export type IdentityConfigurationRecord = z.infer<
  typeof IdentityConfigurationRecordSchema
>;
