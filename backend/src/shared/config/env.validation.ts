import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: z.coerce.number().positive().default(3000),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  JWT_EXPIRES_IN: z.string().default("60s"),
  REFRESH_TOKEN_SECRET: z.string().min(32),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default("7d"),
  BCRYPT_SALT_ROUNDS: z.coerce.number().min(10).max(31).default(12),
  GRPC_SOCKET_PATH: z.string().default("../sockets/firewall.sock"),
  FIREWALL_GRPC_SOCKET_PATH: z
    .string()
    .default("../sockets/control-plane.sock"),
  FIREWALL_QUERY_GRPC_SOCKET_PATH: z.string().default("../sockets/query.sock"),
  BACKEND_LOG_DIR: z.string().default("/var/log/raptorgate/backend"),
  AUTH_COOKIE_PATH: z.string().min(1).default("/auth/refresh"),
  COOKIE_SECRET: z
    .string()
    .min(32, "COOKIE_SECRET must be at least 32 characters"),
  CORS_ORIGIN: z
    .string()
    .or(z.array(z.string()))
    .transform((val) => {
      if (typeof val === "string") {
        return val.split(",").map((origin) => origin.trim());
      }
      return val;
    })
    .default([]),
});

export type Env = z.infer<typeof envSchema>;

export function validate(config: Record<string, unknown>) {
  const result = envSchema.safeParse(config);

  if (!result.success) {
    const flattened = z.flattenError(result.error);
    console.error("❌ Invalid environment variables:", flattened.fieldErrors);
    throw new Error("Invalid environment variables");
  }

  return result.data;
}
