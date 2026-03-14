import { DatabaseModule } from './infrastructure/persistence/database/database.module';
import { JwtAuthGuard } from './infrastructure/adapters/jwt-auth.guard';
import { JwtStrategy } from './infrastructure/adapters/jwt.strategy';
import { validate } from './shared/config/env.validation';
import { AuthModule } from './modules/auth.module';
import { PassportModule } from '@nestjs/passport';
import { AppController } from './app.controller';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { Module } from '@nestjs/common';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate,
    }),
    DatabaseModule,
    PassportModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    JwtStrategy,
    { provide: APP_GUARD, useClass: JwtAuthGuard }, // najpierw autentykacja
  ],
})
export class AppModule {}
