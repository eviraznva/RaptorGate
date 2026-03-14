import { DatabaseModule } from './infrastructure/persistence/database/database.module';
import { TOKEN_SERVICE_TOKEN } from './application/ports/token-service.interface';
import { TokenService } from './infrastructure/adapters/jwt-token.service';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { validate } from './shared/config/env.validation';
import { Env } from './shared/config/env.validation';
import { PassportModule } from '@nestjs/passport';
import { AppController } from './app.controller';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate,
    }),
    DatabaseModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService<Env, true>) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get('JWT_EXPIRES_IN') || '60s',
        },
      }),
    }),
  ],
  controllers: [AppController],
  providers: [
    { provide: TOKEN_SERVICE_TOKEN, useClass: TokenService },
    JwtStrategy,
    { provide: APP_GUARD, useClass: JwtAuthGuard }, // najpierw autentykacja
  ],
})
export class AppModule {}
