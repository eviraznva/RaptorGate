import { SuccessEnvelopeInterceptor } from './presentation/interceptors/success-envelope.interceptor.js';
import { HttpExceptionEnvelopeFilter } from './presentation/filters/http-exception-envelope.filter.js';
import { RolesPermissionsGuard } from './infrastructure/adapters/roles-permissions.guard.js';
import { ConfigSnapshotModule } from './modules/config-snapshot.module.js';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard.js';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy.js';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { FirewallEventsModule } from './modules/firewall-events/firewall-events.module.js';
import { GrpcModule } from './infrastructure/grpc/grpc.module.js';
import { ZonePairsModule } from './modules/zone-pairs.module.js';
import { RealtimeModule } from './modules/realtime.module.js';
import { validate } from './shared/config/env.validation.js';
import { RulesModule } from './modules/rules.module.js';
import { AuthModule } from './modules/auth.module.js';
import { ZoneModule } from './modules/zone.module.js';
import { UserModule } from './modules/user.module.js';
import { AppController } from './app.controller.js';
import { SslModule } from './modules/ssl.module.js';
import { NatModule } from './modules/nat.module.js';
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
    UserModule,
    GrpcModule,
    FirewallEventsModule,
    AuthModule,
    ZoneModule,
    NatModule,
    SslModule,
  ],
  controllers: [AppController],
  providers: [
    JwtStrategy,
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesPermissionsGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_FILTER, useClass: HttpExceptionEnvelopeFilter },
    { provide: APP_INTERCEPTOR, useClass: SuccessEnvelopeInterceptor },
  ],
})
export class AppModule {}
