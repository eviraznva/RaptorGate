import { ApiProperty } from "@nestjs/swagger";

export class RuleItemResponseDto {
	@ApiProperty({ example: "123e4567-e89b-12d3-a456-426614174000" })
	id: string;

	@ApiProperty({ example: "Allow HTTPS" })
	name: string;

	@ApiProperty({ example: "Allow outgoing HTTPS traffic", nullable: true })
	description: string | null;

	@ApiProperty({ example: "c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4" })
	zonePairId: string;

	@ApiProperty({ example: true })
	isActive: boolean;

	@ApiProperty({ example: "allow tcp any any eq 443" })
	content: string;

	@ApiProperty({ example: 10 })
	priority: number;

	@ApiProperty({ example: "345e4567-e89b-12d3-a456-426614174000" })
	createdBy: string;

	@ApiProperty({ example: "2024-06-01T12:00:00Z" })
	createdAt: string;

	@ApiProperty({ example: "2024-06-01T12:00:00Z" })
	updatedAt: string;
}
