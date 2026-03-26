import { JsonPermissionRepository } from '../infrastructure/persistence/repositories/json-permission.repository.js';
import { JsonRoleRepository } from '../infrastructure/persistence/repositories/json-role.repository.js';
import { JsonUserRepository } from '../infrastructure/persistence/repositories/json-user.repository.js';
import { PERMISSION_REPOSITORY_TOKEN } from '../domain/repositories/permission.repository.js';
import { RolesPermissionsGuard } from '../infrastructure/adapters/roles-permissions.guard.js';
import { BcryptPasswordHasher } from '../infrastructure/adapters/bcrypt-password-hasher.js';
import { PASSWORD_HASHER_TOKEN } from '../application/ports/passowrd-hasher.interface.js';
import { RefreshTokenUseCase } from '../application/use-cases/refresh-token.use-case.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { LogoutUserUseCase } from '../application/use-cases/logout-user.use-case.js';
import { LoginUserUseCase } from '../application/use-cases/login-user.use-case.js';
import { ROLE_REPOSITORY_TOKEN } from '../domain/repositories/role.repository.js';
import { USER_REPOSITORY_TOKEN } from '../domain/repositories/user.repository.js';
import { AuthController } from '../presentation/controllers/auth.controller.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
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
