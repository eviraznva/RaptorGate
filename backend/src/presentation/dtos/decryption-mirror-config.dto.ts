import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsInt, IsString, Max, Min } from 'class-validator';

export class DecryptionMirrorConfigDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: '127.0.0.1' })
  @IsString()
  targetHost: string;

  @ApiProperty({ example: 9000 })
  @IsInt()
  @Min(0)
  @Max(65535)
  targetPort: number;

  @ApiProperty({ example: true })
  @IsBoolean()
  includeClientToServer: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  includeServerToClient: boolean;

  @ApiProperty({ example: true })
  @IsBoolean()
  forwardedOnly: boolean;

  @ApiProperty({ example: 16777216 })
  @IsInt()
  @Min(1)
  maxSessionBytes: number;
}

export class GetDecryptionMirrorConfigResponseDto {
  @ApiProperty({ type: DecryptionMirrorConfigDto })
  decryptionMirror: DecryptionMirrorConfigDto;
}

export class UpdateDecryptionMirrorConfigResponseDto extends GetDecryptionMirrorConfigResponseDto {}
