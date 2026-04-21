import { ApiProperty } from '@nestjs/swagger';

export class PinningBypassResponseDto {
  @ApiProperty({
    description: 'Whether an active bypass exists for this (source_ip, domain)',
    example: true,
  })
  found: boolean;

  @ApiProperty({
    description: 'Reason that triggered the auto-bypass (empty when not found)',
    example: 'tcp_reset',
  })
  reason: string;

  @ApiProperty({
    description: 'Number of failures recorded before bypass activation',
    example: 3,
  })
  failureCount: number;
}
