import { ApiProperty } from '@nestjs/swagger';

export class LocalDecryptionExclusionDto {
  @ApiProperty({
    description: 'Domain or SNI of the TLS target',
    example: 'api.example.com',
  })
  domain: string;

  @ApiProperty({
    description: 'Server IP of the TLS target',
    example: '142.250.203.36',
  })
  serverIp: string;

  @ApiProperty({
    description: 'Server port of the TLS target',
    example: 443,
  })
  serverPort: number;

  @ApiProperty({
    description: 'Reason that triggered the local exclusion',
    example: 'tcp_reset',
  })
  reason: string;

  @ApiProperty({
    description: 'Number of failures recorded before exclusion activation',
    example: 3,
  })
  failureCount: number;

  @ApiProperty({
    description: 'Last client source IP that triggered a failure for this target',
    example: '10.0.0.42',
  })
  lastSourceIp: string;
}

export class DecryptionExclusionResponseDto {
  @ApiProperty({
    description: 'Whether an active local TLS decryption exclusion exists',
    example: true,
  })
  found: boolean;

  @ApiProperty({
    description: 'Local TLS decryption exclusion detail',
    required: false,
    type: LocalDecryptionExclusionDto,
  })
  exclusion?: LocalDecryptionExclusionDto;
}

export class DecryptionExclusionListResponseDto {
  @ApiProperty({
    description: 'Active local TLS decryption exclusions',
    type: [LocalDecryptionExclusionDto],
  })
  exclusions: LocalDecryptionExclusionDto[];
}

export class ClearDecryptionExclusionsResponseDto {
  @ApiProperty({
    description: 'Number of local TLS decryption exclusions removed',
    example: 3,
  })
  removed: number;
}
