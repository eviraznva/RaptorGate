import { ApiProperty } from "@nestjs/swagger";
import { RuleItemResponseDto } from "./rule-item-response.dto";

export class GetAllRulesResponseDto {
  @ApiProperty({
    type: () => [RuleItemResponseDto],
    example: [
      {
        id: "123e4567-e89b-12d3-a456-426614174000",
        name: "Allow HTTPS",
        description: "Allow outgoing HTTPS traffic",
        zonePairId: "c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4",
        isActive: true,
        content: "allow tcp any any eq 443",
        priority: 10,
        createdBy: "345e4567-e89b-12d3-a456-426614174000",
        createdAt: "2024-06-01T12:00:00Z",
        updatedAt: "2024-06-01T12:00:00Z",
      },
    ],
  })
  rules: RuleItemResponseDto[];
}
