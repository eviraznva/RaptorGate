import { RolesPermissionsGuard } from './infrastructure/adapters/roles-permissions.guard';
import { DomainExceptionFilter } from './presentation/filters/domain-exception.filter';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy';
import { ZonePairsModule } from './modules/zone-pairs.module';
import { validate } from './shared/config/env.validation';
import { RulesModule } from './modules/rules.module';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './modules/auth.module';
import { ZoneModule } from './modules/zone.module';
import { PassportModule } from '@nestjs/passport';
import { AppController } from './app.controller';
import { NatModule } from './modules/nat.module';
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
    ZonePairsModule,
    PassportModule,
    RulesModule,
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
