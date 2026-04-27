import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import { PassportModule } from "@nestjs/passport";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { AppController } from "./app.controller.js";
import { JwtStrategy } from "./infrastructure/adapters/jwt.strategy.js";
import { JwtAuthGuard } from "./infrastructure/adapters/jwt-auth.guard.js";
import { RolesPermissionsGuard } from "./infrastructure/adapters/roles-permissions.guard.js";
import { GrpcModule } from "./infrastructure/grpc/grpc.module.js";
import { AuthModule } from "./modules/auth.module.js";
import { ConfigSnapshotModule } from "./modules/config-snapshot.module.js";
import { DnsBlacklistModule } from "./modules/dns-blacklist.module.js";
import { DnsInspectionModule } from "./modules/dns-inspection.module.js";
import { FirewallEventsModule } from "./modules/firewall-events.module.js";
import { IpsConfigModule } from "./modules/ips-config.module.js";
import { NatModule } from "./modules/nat.module.js";
import { PinningModule } from "./modules/pinning.module.js";
import { RealtimeModule } from "./modules/realtime.module.js";
import { RulesModule } from "./modules/rules.module.js";
import { SslModule } from "./modules/ssl.module.js";
import { TcpSessionsModule } from "./modules/tcp-sessions.module.js";
import { UserModule } from "./modules/user.module.js";
import { ZoneModule } from "./modules/zone.module.js";
import { ZonePairsModule } from "./modules/zone-pairs.module.js";
import { HttpExceptionEnvelopeFilter } from "./presentation/filters/http-exception-envelope.filter.js";
import { SuccessEnvelopeInterceptor } from "./presentation/interceptors/success-envelope.interceptor.js";
import { validate } from "./shared/config/env.validation.js";

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
    DnsInspectionModule,
    DnsBlacklistModule,
    ZonePairsModule,
    IpsConfigModule,
    RealtimeModule,
    PassportModule,
    RulesModule,
    UserModule,
    GrpcModule,
    FirewallEventsModule,
    AuthModule,
    ZoneModule,
    NatModule,
    PinningModule,
    TcpSessionsModule,
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
