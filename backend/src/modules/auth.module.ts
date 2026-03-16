import { DrizzleUserRepository } from 'src/infrastructure/persistence/repositories/drizzle-user.repository';
import { BcryptPasswordHasher } from 'src/infrastructure/adapters/bcrypt-password-hasher';
import { PASSWORD_HASHER_TOKEN } from 'src/application/ports/passowrd-hasher.interface';
import { RefreshTokenUseCase } from 'src/application/use-cases/refresh-token.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { LoginUserUseCase } from 'src/application/use-cases/login-user.use-case';
import { USER_REPOSITORY_TOKEN } from 'src/domain/repositories/user.repository';
import { AuthController } from 'src/presentation/controllers/auth.controller';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [AuthController],
  providers: [
    LoginUserUseCase,
    RefreshTokenUseCase,
    {
      provide: PASSWORD_HASHER_TOKEN,
      useClass: BcryptPasswordHasher,
    },
    {
      provide: USER_REPOSITORY_TOKEN,
      useClass: DrizzleUserRepository,
    },
    { provide: TOKEN_SERVICE_TOKEN, useClass: TokenService },
    JwtService,
  ],
})
export class AuthModule {}
