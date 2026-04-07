import { IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class LoginDto {
	@ApiProperty({ example: "admin" })
	@IsNotEmpty()
	@IsString()
	@MinLength(3)
	@MaxLength(20)
	username: string;

	@ApiProperty({ example: "admin123" })
	@IsNotEmpty()
	@IsString()
	password: string;
}
