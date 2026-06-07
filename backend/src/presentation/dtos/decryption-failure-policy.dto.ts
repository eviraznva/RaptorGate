import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsIn, IsInt, Max, Min } from 'class-validator';

export type DecryptionFailurePolicyActionDto = 'block' | 'cacheAndBypass';

export class DecryptionFailurePolicyDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: 3 })
  @IsInt()
  @Min(1)
  @Max(1000)
  failureThreshold: number;

  @ApiProperty({ example: 60 })
  @IsInt()
  @Min(1)
  failureWindowSec: number;

  @ApiProperty({ example: 86400 })
  @IsInt()
  @Min(1)
  localExclusionTtlSec: number;

  @ApiProperty({ example: 4096 })
  @IsInt()
  @Min(1)
  maxEntries: number;

  @ApiProperty({ example: 'block', enum: ['block', 'cacheAndBypass'] })
  @IsIn(['block', 'cacheAndBypass'])
  action: DecryptionFailurePolicyActionDto;
}

export class GetDecryptionFailurePolicyResponseDto {
  @ApiProperty({ type: DecryptionFailurePolicyDto })
  decryptionFailurePolicy: DecryptionFailurePolicyDto;
}

export class UpdateDecryptionFailurePolicyResponseDto extends GetDecryptionFailurePolicyResponseDto {}
