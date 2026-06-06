import { ApiProperty } from '@nestjs/swagger';

export class DecryptionExclusionStatsResponseDto {
  @ApiProperty({
    description: 'Number of currently active local TLS decryption exclusions',
    example: 3,
  })
  activeExclusions: number;

  @ApiProperty({
    description: 'Number of target failure windows currently tracked',
    example: 12,
  })
  trackedFailures: number;
}
