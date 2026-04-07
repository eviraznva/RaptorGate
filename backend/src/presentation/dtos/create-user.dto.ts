import { ApiProperty } from "@nestjs/swagger";
import {
	IsString,
	IsNotEmpty,
	MinLength,
	Matches,
	MaxLength,
} from "class-validator";
import { Role } from "src/domain/enums/role.enum";

export class CreateUserDto {
	@ApiProperty({ example: "jankowal" })
	@IsNotEmpty()
	@IsString()
	@MinLength(3)
	@MaxLength(20)
	@Matches(/^[a-zA-Z][a-zA-Z0-9_-]*$/, {
		message:
			"Username must start with a letter and can only contain letters, numbers, underscores (_), and hyphens (-).",
	})
	username: string;

	@ApiProperty({
		example: "StrongPass123!",
		minLength: 8,
		description: "Hasło użytkownika",
	})
	@IsString()
	@IsNotEmpty()
	@MinLength(8)
	password: string;

	@ApiProperty({
		example: [Role.Admin],
		description: "Rola użytkownika",
	})
	@IsNotEmpty()
	roles: string[];
}
