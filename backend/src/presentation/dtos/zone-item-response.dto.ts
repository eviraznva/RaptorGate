import { ApiProperty } from "@nestjs/swagger";

export class ZoneItemResponseDto {
	@ApiProperty({ example: "123e4567-e89b-12d3-a456-426614174000" })
	id: string;

	@ApiProperty({ example: "Living Room" })
	name: string;

	@ApiProperty({
		example: "The main living area of the house",
		nullable: true,
	})
	description: string | null;

	@ApiProperty({ example: true })
	isActive: boolean;

	@ApiProperty({ example: "2024-06-01T12:00:00Z" })
	createdAt: Date;

	@ApiProperty({ example: "345e4567-e89b-12d3-a456-426614174000" })
	createdBy: string;
}
