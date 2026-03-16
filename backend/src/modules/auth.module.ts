import { DrizzlePermissionRepository } from 'src/infrastructure/persistence/repositories/drizzle-permission.repository';
import { DrizzleUserRepository } from 'src/infrastructure/persistence/repositories/drizzle-user.repository';
import { DrizzleRoleRepository } from 'src/infrastructure/persistence/repositories/drizzle-role.repository';
import { PERMISSION_REPOSITORY_TOKEN } from 'src/domain/repositories/permission.repository';
import { RolesPermissionsGuard } from 'src/infrastructure/adapters/roles-permissions.guard';
import { BcryptPasswordHasher } from 'src/infrastructure/adapters/bcrypt-password-hasher';
import { PASSWORD_HASHER_TOKEN } from 'src/application/ports/passowrd-hasher.interface';
import { RefreshTokenUseCase } from 'src/application/use-cases/refresh-token.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { LogoutUserUseCase } from 'src/application/use-cases/logout-user.use-case';
import { LoginUserUseCase } from 'src/application/use-cases/login-user.use-case';
import { ROLE_REPOSITORY_TOKEN } from 'src/domain/repositories/role.repository';
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
    LogoutUserUseCase,
    { provide: PASSWORD_HASHER_TOKEN, useClass: BcryptPasswordHasher },
    { provide: USER_REPOSITORY_TOKEN, useClass: DrizzleUserRepository },
    { provide: ROLE_REPOSITORY_TOKEN, useClass: DrizzleRoleRepository },
    {
      provide: PERMISSION_REPOSITORY_TOKEN,
      useClass: DrizzlePermissionRepository,
    },
    { provide: TOKEN_SERVICE_TOKEN, useClass: TokenService },
    JwtService,
    RolesPermissionsGuard,
  ],
  exports: [
    RolesPermissionsGuard,
    ROLE_REPOSITORY_TOKEN,
    PERMISSION_REPOSITORY_TOKEN,
    TOKEN_SERVICE_TOKEN,
  ],
})
export class AuthModule {}
