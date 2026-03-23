import { JsonPermissionRepository } from '../infrastructure/persistence/repositories/json-permission.repository';
import { JsonRoleRepository } from '../infrastructure/persistence/repositories/json-role.repository';
import { JsonUserRepository } from '../infrastructure/persistence/repositories/json-user.repository';
import { PERMISSION_REPOSITORY_TOKEN } from '../domain/repositories/permission.repository';
import { RolesPermissionsGuard } from '../infrastructure/adapters/roles-permissions.guard';
import { BcryptPasswordHasher } from '../infrastructure/adapters/bcrypt-password-hasher';
import { PASSWORD_HASHER_TOKEN } from '../application/ports/passowrd-hasher.interface';
import { RefreshTokenUseCase } from '../application/use-cases/refresh-token.use-case';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface';
import { LogoutUserUseCase } from '../application/use-cases/logout-user.use-case';
import { LoginUserUseCase } from '../application/use-cases/login-user.use-case';
import { ROLE_REPOSITORY_TOKEN } from '../domain/repositories/role.repository';
import { USER_REPOSITORY_TOKEN } from '../domain/repositories/user.repository';
import { AuthController } from '../presentation/controllers/auth.controller';
import { TokenService } from '../infrastructure/adapters/jwt-token.service';
import { FileStore } from '../infrastructure/persistence/json/file-store';
import { Mutex } from '../infrastructure/persistence/json/file-mutex';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [AuthController],
  providers: [
    LoginUserUseCase,
    RefreshTokenUseCase,
    LogoutUserUseCase,
    FileStore,
    Mutex,
    { provide: PASSWORD_HASHER_TOKEN, useClass: BcryptPasswordHasher },
    { provide: USER_REPOSITORY_TOKEN, useClass: JsonUserRepository },
    { provide: ROLE_REPOSITORY_TOKEN, useClass: JsonRoleRepository },
    {
      provide: PERMISSION_REPOSITORY_TOKEN,
      useClass: JsonPermissionRepository,
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
