import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';

export type NatRuleActionResponseDto =
  | {
      $case: 'snat';
      snat: {
        srcCidr: string;
        translatedIp: string;
        srcPortMin?: number;
        srcPortMax?: number;
      };
    }
  | { $case: 'dnat'; dnat: { dstCidr: string; translatedIp: string; translatedPort?: number } }
  | {
      $case: 'pat';
      pat: {
        dstIp: string;
        dstPort: number;
        translatedIp: string;
        translatedPort: number;
      };
    }
  | {
      $case: 'masquerade';
      masquerade: {
        srcCidr?: string;
        srcPortMin?: number;
        srcPortMax?: number;
      };
    };

export class NatRuleItemResponseDto {
  @ApiProperty({ example: '123e4567-e89b-12d3-a456-426614174000' })
  id: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: 10, minimum: 1, maximum: 100 })
  priority: number;

  @ApiProperty({ enum: NatProtocol, example: NatProtocol.NAT_PROTOCOL_ALL })
  protocol: NatProtocol;

  @ApiPropertyOptional({ example: 'lan0', nullable: true })
  inInterface: string | null;

  @ApiPropertyOptional({ example: 'wan0', nullable: true })
  outInterface: string | null;

  @ApiPropertyOptional({ example: 'lan', nullable: true })
  inZone: string | null;

  @ApiPropertyOptional({ example: 'wan', nullable: true })
  outZone: string | null;

  @ApiPropertyOptional({ example: 1024, nullable: true, minimum: 1, maximum: 65535 })
  matchSrcPortMin: number | null;

  @ApiPropertyOptional({ example: 65535, nullable: true, minimum: 1, maximum: 65535 })
  matchSrcPortMax: number | null;

  @ApiPropertyOptional({ example: 443, nullable: true, minimum: 1, maximum: 65535 })
  matchDstPortMin: number | null;

  @ApiPropertyOptional({ example: 443, nullable: true, minimum: 1, maximum: 65535 })
  matchDstPortMax: number | null;

  @ApiProperty({
    example: {
      $case: 'dnat',
      dnat: { dstCidr: '203.0.113.10/32', translatedIp: '10.0.0.10' },
    },
  })
  action: NatRuleActionResponseDto;

  @ApiProperty({ example: '2024-06-01T12:00:00Z' })
  createdAt: string;

  @ApiProperty({ example: '2024-06-01T12:00:00Z' })
  updatedAt: string;
}
