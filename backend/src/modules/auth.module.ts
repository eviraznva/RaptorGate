import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PASSWORD_HASHER_TOKEN } from 'src/application/ports/passowrd-hasher.interface';
import { RECOVERY_TOKEN_SERVICE_TOKEN } from 'src/application/ports/recovery-token-service.interface';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { LoginUserUseCase } from 'src/application/use-cases/login-user.use-case';
import { LogoutUserUseCase } from 'src/application/use-cases/logout-user.use-case';
import { RecoverPasswordUseCase } from 'src/application/use-cases/recover-password.use-case';
import { RefreshTokenUseCase } from 'src/application/use-cases/refresh-token.use-case';
import { PERMISSION_REPOSITORY_TOKEN } from 'src/domain/repositories/permission.repository';
import { ROLE_REPOSITORY_TOKEN } from 'src/domain/repositories/role.repository';
import { USER_REPOSITORY_TOKEN } from 'src/domain/repositories/user.repository';
import { BcryptPasswordHasher } from 'src/infrastructure/adapters/bcrypt-password-hasher';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { RecoveryTokenService } from 'src/infrastructure/adapters/recovery-token.service';
import { RolesPermissionsGuard } from 'src/infrastructure/adapters/roles-permissions.guard';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { JsonPermissionRepository } from 'src/infrastructure/persistence/repositories/json-permission.repository';
import { JsonRoleRepository } from 'src/infrastructure/persistence/repositories/json-role.repository';
import { JsonUserRepository } from 'src/infrastructure/persistence/repositories/json-user.repository';
import { AuthController } from 'src/presentation/controllers/auth.controller';

@Module({
  imports: [],
  controllers: [AuthController],
  providers: [
    LoginUserUseCase,
    RefreshTokenUseCase,
    LogoutUserUseCase,
    RecoverPasswordUseCase,
    FileStore,
    Mutex,
    { provide: PASSWORD_HASHER_TOKEN, useClass: BcryptPasswordHasher },
    { provide: USER_REPOSITORY_TOKEN, useClass: JsonUserRepository },
    { provide: ROLE_REPOSITORY_TOKEN, useClass: JsonRoleRepository },
    {
      provide: PERMISSION_REPOSITORY_TOKEN,
      useClass: JsonPermissionRepository,
    },
    { provide: RECOVERY_TOKEN_SERVICE_TOKEN, useClass: RecoveryTokenService },
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
