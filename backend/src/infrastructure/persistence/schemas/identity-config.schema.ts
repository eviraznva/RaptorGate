import { isoDateTimeSchema } from './_common.js';
import { z } from 'zod';
import { SECRET_REF_PATTERN } from '../../../domain/value-objects/secret-ref.vo.js';
import { isIP } from 'node:net';

const idSchema = z.string().min(1).max(128);
const nullableTextSchema = z.string().min(1).max(512).nullable();
const interfaceNameSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,64}$/).nullable();
const zoneIdSchema = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i).nullable();
const bindAddressSchema = z.string().refine((value) => isIP(value) !== 0).nullable();
const ldapServerTypeSchema = z.enum(['active_directory', 'e_directory', 'sun', 'other']);

export const RadiusServerEndpointRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535),
    sharedSecretRef: z.string().regex(SECRET_REF_PATTERN),
    priority: z.number().int().min(1).max(65535),
    isActive: z.boolean(),
  })
  .strict();

export const LdapServerEndpointRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535),
    priority: z.number().int().min(1).max(65535),
    isActive: z.boolean(),
  })
  .strict();

export const LdapGroupMappingRecordSchema = z
  .object({
    userBaseDn: z.string().min(1).max(512),
    userFilterAttribute: z.string().min(1).max(128),
    userNameAttribute: z.string().min(1).max(128),
    groupBaseDn: z.string().min(1).max(512),
    groupMemberAttribute: z.string().min(1).max(128),
    groupNameAttribute: z.string().min(1).max(128),
    includeGroups: z.array(z.string().min(1).max(512)).default([]),
    updateIntervalSeconds: z.number().int().positive(),
  })
  .strict();

export const RadiusServerProfileRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    host: z.string().min(1).max(255).optional(),
    port: z.number().int().min(1).max(65535).optional(),
    sharedSecretRef: z.string().regex(SECRET_REF_PATTERN).optional(),
    authenticationProtocol: z.enum(['pap']).default('pap'),
    certificateProfileRef: nullableTextSchema.optional(),
    outerIdentity: nullableTextSchema.optional(),
    servers: z.array(RadiusServerEndpointRecordSchema).optional(),
    timeoutMs: z.number().int().positive(),
    retries: z.number().int().min(0),
    nasIp: nullableTextSchema,
    nasIdentifier: nullableTextSchema,
    calledStationId: nullableTextSchema,
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict()
  .superRefine((record, ctx) => {
    const hasLegacyEndpoint =
      record.host !== undefined &&
      record.port !== undefined &&
      record.sharedSecretRef !== undefined;
    const hasProductionEndpoint =
      record.servers !== undefined &&
      record.servers.length > 0;

    if (!hasLegacyEndpoint && !hasProductionEndpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'radius profile requires legacy endpoint fields or servers',
      });
    }
  });

export const LdapServerProfileRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    host: z.string().min(1).max(255).optional(),
    port: z.number().int().min(1).max(65535).optional(),
    serverType: ldapServerTypeSchema.optional(),
    baseDn: z.string().min(1).max(512).optional(),
    tlsMode: z.enum(['disabled', 'starttls', 'ldaps']),
    verifyServerCertificate: z.boolean().optional(),
    certificateProfileRef: nullableTextSchema.optional(),
    connectTimeoutMs: z.number().int().positive().optional(),
    searchTimeoutMs: z.number().int().positive().optional(),
    retryIntervalSeconds: z.number().int().positive().optional(),
    bindDn: z.string().min(1).max(512),
    bindPasswordRef: z.string().regex(SECRET_REF_PATTERN),
    userBaseDn: z.string().min(1).max(512).optional(),
    userFilterAttribute: z.string().min(1).max(128).optional(),
    groupBaseDn: z.string().min(1).max(512).optional(),
    groupMemberAttribute: z.string().min(1).max(128).optional(),
    groupNameAttribute: z.string().min(1).max(128).optional(),
    groupMapping: LdapGroupMappingRecordSchema.optional(),
    timeoutMs: z.number().int().positive().optional(),
    cacheTtlSeconds: z.number().int().positive(),
    servers: z.array(LdapServerEndpointRecordSchema).optional(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict()
  .superRefine((record, ctx) => {
    const hasLegacyEndpoint =
      record.host !== undefined &&
      record.port !== undefined;
    const hasProductionEndpoint =
      record.servers !== undefined &&
      record.servers.length > 0;
    const hasLegacyMapping =
      record.userBaseDn !== undefined &&
      record.userFilterAttribute !== undefined &&
      record.groupBaseDn !== undefined &&
      record.groupMemberAttribute !== undefined &&
      record.groupNameAttribute !== undefined;

    if (!hasLegacyEndpoint && !hasProductionEndpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ldap profile requires legacy endpoint fields or servers',
      });
    }

    if (!hasLegacyMapping && !record.groupMapping) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ldap profile requires legacy mapping fields or groupMapping',
      });
    }

    if (record.timeoutMs === undefined && record.connectTimeoutMs === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ldap profile requires timeoutMs or connectTimeoutMs',
      });
    }

    if (record.timeoutMs === undefined && record.searchTimeoutMs === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ldap profile requires timeoutMs or searchTimeoutMs',
      });
    }
  });

export const AuthenticationSequenceRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    isActive: z.boolean(),
    profileIds: z.array(idSchema),
    exitOnReject: z.boolean(),
    useDomainRouting: z.boolean(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: z.string().min(1).max(128),
  })
  .strict();

export const IdentityGroupRecordSchema = z
  .object({
    id: idSchema,
    name: z.string().min(1).max(128),
    description: nullableTextSchema,
    source: z.enum(['local', 'ldap', 'radius_vsa']),
    externalDn: nullableTextSchema,
    members: z.array(
      z.object({
        principal: z.string().min(1).max(256),
        principalType: z.enum(['username', 'external_id']),
      }).strict(),
    ).default([]),
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
      interfaceName: interfaceNameSchema,
      zoneId: zoneIdSchema,
      bindAddress: bindAddressSchema,
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
    authentication_sequences: z.object({
      items: z.array(AuthenticationSequenceRecordSchema),
    }).strict().optional(),
    identity_groups: z.object({
      items: z.array(IdentityGroupRecordSchema),
    }).strict().optional(),
    authenticationSequences: z.array(AuthenticationSequenceRecordSchema).optional(),
    identityGroups: z.array(IdentityGroupRecordSchema).optional(),
    settings: IdentitySettingsRecordSchema,
  })
  .strict()
  .transform((record) => ({
    radius_server_profiles: record.radius_server_profiles,
    ldap_server_profiles: record.ldap_server_profiles,
    authentication_profiles: record.authentication_profiles,
    authentication_sequences:
      record.authentication_sequences ?? { items: record.authenticationSequences ?? [] },
    identity_groups: record.identity_groups ?? { items: record.identityGroups ?? [] },
    settings: record.settings,
  }));

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
export type RadiusServerEndpointRecord = z.infer<
  typeof RadiusServerEndpointRecordSchema
>;
export type LdapServerEndpointRecord = z.infer<
  typeof LdapServerEndpointRecordSchema
>;
export type LdapGroupMappingRecord = z.infer<
  typeof LdapGroupMappingRecordSchema
>;
export type AuthenticationSequenceRecord = z.infer<
  typeof AuthenticationSequenceRecordSchema
>;
export type IdentityGroupRecord = z.infer<
  typeof IdentityGroupRecordSchema
>;
export type IdentityConfigurationRecord = z.infer<
  typeof IdentityConfigurationRecordSchema
>;
