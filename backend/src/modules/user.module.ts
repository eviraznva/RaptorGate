import { JsonRoleRepository } from "src/infrastructure/persistence/repositories/json-role.repository";
import { JsonUserRepository } from "src/infrastructure/persistence/repositories/json-user.repository";
import { BcryptPasswordHasher } from "src/infrastructure/adapters/bcrypt-password-hasher";
import { PASSWORD_HASHER_TOKEN } from "src/application/ports/passowrd-hasher.interface";
import { GetAllUsersUseCase } from "src/application/use-cases/get-all-users.use-case";
import { CreateUserUseCase } from "src/application/use-cases/create-user.use-case";
import { DeleteUserUseCase } from "src/application/use-cases/delete-user.use-case";
import { ROLE_REPOSITORY_TOKEN } from "src/domain/repositories/role.repository";
import { USER_REPOSITORY_TOKEN } from "src/domain/repositories/user.repository";
import { EditUserUseCase } from "src/application/use-cases/edit-user.use-case";
import { UserController } from "src/presentation/controllers/user.controller";
import { FileStore } from "src/infrastructure/persistence/json/file-store";
import { Mutex } from "src/infrastructure/persistence/json/file-mutex";
import { JwtService } from "@nestjs/jwt";
import { Module } from "@nestjs/common";

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
