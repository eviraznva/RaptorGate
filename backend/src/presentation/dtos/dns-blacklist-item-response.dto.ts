import { ApiProperty } from "@nestjs/swagger";

export class DnsBlacklistEntryItemResponseDto {
  @ApiProperty({ example: "123e4567-e89b-12d3-a456-426614174000" })
  id: string;

  @ApiProperty({ example: "example.com" })
  domain: string;

  @ApiProperty({ example: "Known malicious domain" })
  reason: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: "2024-06-01T12:00:00Z" })
  createdAt: string;

  @ApiProperty({ example: "345e4567-e89b-12d3-a456-426614174000" })
  createdBy: string;
}
