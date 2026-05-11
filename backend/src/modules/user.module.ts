import { JsonRoleRepository } from '../infrastructure/persistence/repositories/json-role.repository.js';
import { JsonUserRepository } from '../infrastructure/persistence/repositories/json-user.repository.js';
import { BcryptPasswordHasher } from '../infrastructure/adapters/bcrypt-password-hasher.js';
import { PASSWORD_HASHER_TOKEN } from '../application/ports/passowrd-hasher.interface.js';
import { GetAllUsersUseCase } from '../application/use-cases/get-all-users.use-case.js';
import { CreateUserUseCase } from '../application/use-cases/create-user.use-case.js';
import { DeleteUserUseCase } from '../application/use-cases/delete-user.use-case.js';
import { ROLE_REPOSITORY_TOKEN } from '../domain/repositories/role.repository.js';
import { USER_REPOSITORY_TOKEN } from '../domain/repositories/user.repository.js';
import { EditUserUseCase } from '../application/use-cases/edit-user.use-case.js';
import { UserController } from '../presentation/controllers/user.controller.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [UserController],
  providers: [
    GetAllUsersUseCase,
    DeleteUserUseCase,
    CreateUserUseCase,
    EditUserUseCase,
    FileStore,
    Mutex,
    {
      provide: USER_REPOSITORY_TOKEN,
      useClass: JsonUserRepository,
    },
    {
      provide: PASSWORD_HASHER_TOKEN,
      useClass: BcryptPasswordHasher,
    },
    {
      provide: ROLE_REPOSITORY_TOKEN,
      useClass: JsonRoleRepository,
    },
    JwtService,
  ],
})
export class UserModule {}
