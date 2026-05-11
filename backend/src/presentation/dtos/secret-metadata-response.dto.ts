import { ApiProperty } from '@nestjs/swagger';

export class SecretMetadataResponseDto {
  @ApiProperty()
  ref: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  @ApiProperty()
  updatedBy: string;
}
