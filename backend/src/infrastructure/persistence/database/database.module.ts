import { Env } from 'src/shared/config/env.validation';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';

export const DB_CONNECTION = Symbol('DB_CONNECTION');

@Global()
@Module({
  providers: [
    {
      provide: DB_CONNECTION,
      inject: [ConfigService],
      useFactory: (configService: ConfigService<Env, true>) => {
        const connectionString = configService.get('DATABASE_URL', {
          infer: true,
        });

        const pool = new Pool({
          connectionString,
          max: 10,
          idleTimeoutMillis: 30000,
        });

        return drizzle({
          client: pool,
          logger: configService.get('NODE_ENV') === 'development',
        });
      },
    },
  ],
  exports: [DB_CONNECTION],
})
export class DatabaseModule {}
