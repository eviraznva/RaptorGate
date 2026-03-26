import { RolesPermissionsGuard } from './infrastructure/adapters/roles-permissions.guard.js';
import { DomainExceptionFilter } from './presentation/filters/domain-exception.filter.js';
import { ConfigSnapshotModule } from './modules/config-snapshot.module.js';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard.js';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy.js';
import { GrpcModule } from './infrastructure/grpc/grpc.module.js';
import { ZonePairsModule } from './modules/zone-pairs.module.js';
import { RealtimeModule } from './modules/realtime.module.js';
import { validate } from './shared/config/env.validation.js';
import { RulesModule } from './modules/rules.module.js';
import { AuthModule } from './modules/auth.module.js';
import { ZoneModule } from './modules/zone.module.js';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller.js';
import { NatModule } from './modules/nat.module.js';
import { ThrottlerModule } from '@nestjs/throttler';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
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
    ConfigSnapshotModule,
    ZonePairsModule,
    RealtimeModule,
    PassportModule,
    RulesModule,
    GrpcModule,
    AuthModule,
    ZoneModule,
    NatModule,
  ],
  controllers: [AppController],
  providers: [
    JwtStrategy,
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesPermissionsGuard },
    { provide: APP_FILTER, useClass: DomainExceptionFilter },
  ],
})
export class AppModule {}
