import { z } from 'zod';

function isValidSecretStoreKey(value: string): boolean {
  return Buffer.from(value, 'base64').length === 32;
}

const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().positive().default(3000),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('60s'),
  REFRESH_TOKEN_SECRET: z.string().min(32),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
  BCRYPT_SALT_ROUNDS: z.coerce.number().min(10).max(31).default(12),
  GRPC_SOCKET_PATH: z.string().default('../sockets/event.sock'),
  FIREWALL_GRPC_SOCKET_PATH: z
    .string()
    .default('../sockets/control-plane.sock'),
  FIREWALL_QUERY_SOCKET_PATH: z.string().default('../sockets/query.sock'),
  FIREWALL_QUERY_GRPC_SOCKET_PATH: z
    .string()
    .default('../sockets/query.sock'),
  SERVER_CERT_GRPC_SOCKET_PATH: z
    .string()
    .default('../sockets/server-cert.sock'),
  BACKEND_LOG_DIR: z.string().default('/var/log/raptorgate/backend'),
  BACKEND_LOG_LEVELS: z.string().default('log,error,warn'),
  AUTH_COOKIE_PATH: z.string().min(1).default('/auth/refresh'),
  COOKIE_SECRET: z
    .string()
    .min(32, 'COOKIE_SECRET must be at least 32 characters'),
  SECRET_STORE_KEY: z.string().min(1),
  RAPTORGATE_PKI_DIR: z.string().default('/var/lib/raptorgate/pki'),
  CORS_ORIGIN: z
    .string()
    .or(z.array(z.string()))
    .transform((val) => {
      if (typeof val === 'string') {
        return val.split(',').map((origin) => origin.trim());
      }
      return val;
    })
    .default([]),
  RADIUS_HOST: z.string().min(1).default('192.168.20.30'),
  RADIUS_PORT: z.coerce.number().int().positive().max(65535).default(1812),
  RADIUS_SECRET: z.string().min(1),
  RADIUS_TIMEOUT_MS: z.coerce.number().int().positive().default(3000),
  RADIUS_RETRIES: z.coerce.number().int().min(0).max(5).default(1),
  RADIUS_NAS_IP: z.string().min(1).default('192.168.20.254'),
  RADIUS_NAS_IDENTIFIER: z.string().min(1).default('raptorgate-backend'),
  IDENTITY_SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(1800),
  IDENTITY_SESSION_SWEEP_INTERVAL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(30_000),
  IDENTITY_SESSION_REPLAY_INTERVAL_MS: z.coerce
    .number()
    .int()
    .min(0)
    .default(30_000),
  IDENTITY_LDAP_ENABLED: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : v.toLowerCase() === 'true'))
    .default(true),
  IDENTITY_LDAP_HOST: z.string().min(1).default('192.168.20.40'),
  IDENTITY_LDAP_PORT: z.coerce.number().int().positive().max(65535).default(389),
  IDENTITY_LDAP_BIND_DN: z.string().min(1).default('cn=admin,dc=raptorgate,dc=local'),
  IDENTITY_LDAP_BIND_PASSWORD: z.string().min(1),
  IDENTITY_LDAP_USER_BASE_DN: z
    .string()
    .min(1)
    .default('ou=users,dc=raptorgate,dc=local'),
  IDENTITY_LDAP_USER_FILTER_ATTRIBUTE: z.string().min(1).default('uid'),
  IDENTITY_LDAP_GROUP_BASE_DN: z
    .string()
    .min(1)
    .default('ou=groups,dc=raptorgate,dc=local'),
  IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE: z.string().min(1).default('memberUid'),
  IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE: z.string().min(1).default('cn'),
  IDENTITY_LDAP_TIMEOUT_MS: z.coerce.number().int().positive().default(3000),
  IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(300),
  IDENTITY_GROUP_SOURCE_PRIMARY: z.enum(['ldap', 'vsa']).default('ldap'),
  IDENTITY_GROUP_REFRESH_INTERVAL_MS: z.coerce
    .number()
    .int()
    .min(0)
    .default(60_000),
  METRICS_WS_PORT: z.coerce.number().positive().default(2000),
  ALERTS_WS_PORT: z.coerce.number().positive().default(2001),
}).superRefine((data, ctx) => {
  if (!isValidSecretStoreKey(data.SECRET_STORE_KEY)) {
    ctx.addIssue({
      code: 'custom',
      path: ['SECRET_STORE_KEY'],
      message: 'SECRET_STORE_KEY must be a base64 encoded 32 byte key',
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function validate(config: Record<string, unknown>) {
  const result = envSchema.safeParse(config);

  if (!result.success) {
    const flattened = z.flattenError(result.error);
    console.error('❌ Invalid environment variables:', flattened.fieldErrors);
    throw new Error('Invalid environment variables');
  }

  return result.data;
}
