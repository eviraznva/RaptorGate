import { z } from 'zod';

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
  // RADIUS provider (Issue 3). Backend laczy sie do FreeRADIUS w labie (192.168.20.30).
  RADIUS_HOST: z.string().min(1).default('192.168.20.30'),
  RADIUS_PORT: z.coerce.number().int().positive().max(65535).default(1812),
  RADIUS_SECRET: z.string().min(1).default('radiussecret'),
  RADIUS_TIMEOUT_MS: z.coerce.number().int().positive().default(3000),
  RADIUS_RETRIES: z.coerce.number().int().min(0).max(5).default(1),
  // NAS-IP-Address (RFC 2865 attr 4). Domyslnie adres r1 w sieci 192.168.20.0/24.
  RADIUS_NAS_IP: z.string().min(1).default('192.168.20.254'),
  // NAS-Identifier (attr 32) i Called-Station-Id (attr 30) — wartosc informacyjna.
  RADIUS_NAS_IDENTIFIER: z.string().min(1).default('raptorgate-backend'),
  // Lifecycle aktywnej sesji identity (Issue 3, ADR 0003).
  IDENTITY_SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(1800),
  IDENTITY_SESSION_SWEEP_INTERVAL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(30_000),
  // LDAP provider (Issue 4, ADR 0005). Backend laczy sie do slapd w labie (192.168.20.40).
  IDENTITY_LDAP_ENABLED: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : v.toLowerCase() === 'true'))
    .default(true),
  IDENTITY_LDAP_HOST: z.string().min(1).default('192.168.20.40'),
  IDENTITY_LDAP_PORT: z.coerce.number().int().positive().max(65535).default(389),
  IDENTITY_LDAP_BIND_DN: z.string().min(1).default('cn=admin,dc=raptorgate,dc=local'),
  IDENTITY_LDAP_BIND_PASSWORD: z.string().min(1).default('admin'),
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
  // Cache grup user -> groups: zywotnosc wpisu, niezalezna od TTL sesji identity.
  IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(300),
  // Wybor zrodla grup (Issue 4): docelowo ldap, vsa jako fallback / tryb MVP.
  IDENTITY_GROUP_SOURCE_PRIMARY: z.enum(['ldap', 'vsa']).default('ldap'),
  // Refresher grup dla aktywnych sesji: pozwala podmienic grupy bez relogowania.
  IDENTITY_GROUP_REFRESH_INTERVAL_MS: z.coerce
    .number()
    .int()
    .min(0)
    .default(60_000),
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
