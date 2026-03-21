import { RolesPermissionsGuard } from './infrastructure/adapters/roles-permissions.guard';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy';
import { ZonePairsModule } from './modules/zone-pairs.module';
import { validate } from './shared/config/env.validation';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './modules/auth.module';
import { ZoneModule } from './modules/zone.module';
import { PassportModule } from '@nestjs/passport';
import { AppController } from './app.controller';
import { NatModule } from './modules/nat.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { Module } from '@nestjs/common';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate,
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minuta
        limit: 100, // 100 requestów globalnie
      },
    ]),
    PassportModule,
    AuthModule,
    ZoneModule,
    ZonePairsModule,
    NatModule,
  ],
  controllers: [AppController],
  providers: [
    JwtStrategy,
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesPermissionsGuard },
  ],
})
export class AppModule {}
