import { ApiProperty } from '@nestjs/swagger';

export class PinningStatsResponseDto {
  @ApiProperty({
    description: 'Number of currently active pinning auto-bypass entries',
    example: 3,
  })
  activeBypasses: number;

  @ApiProperty({
    description: 'Number of (source_ip, domain) pairs with recent failures',
    example: 12,
  })
  trackedFailures: number;
}
