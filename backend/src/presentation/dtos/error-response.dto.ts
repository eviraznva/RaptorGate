import { ApiProperty } from "@nestjs/swagger";

export class ErrorResponseDto {
	@ApiProperty({
		description: "HTTP status code",
		example: 401,
	})
	statusCode: number;

	@ApiProperty({
		description: "Error message",
		example: "Invalid email or password.",
	})
	message: string;

	@ApiProperty({
		description: "Error type",
		example: "Unauthorized",
	})
	error: string;
}

export class ValidationErrorResponseDto {
	@ApiProperty({
		description: "HTTP status code",
		example: 400,
	})
	statusCode: number;

	@ApiProperty({
		description: "Array of validation error messages",
		example: ["username must be longer than or equal to 3 characters"],
		isArray: true,
	})
	message: string[];

	@ApiProperty({
		description: "Error type",
		example: "Bad Request",
	})
	error: string;
}
