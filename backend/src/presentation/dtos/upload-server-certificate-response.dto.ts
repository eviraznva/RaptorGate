import { ApiProperty } from '@nestjs/swagger';

export class UploadServerCertificateResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  commonName: string;

  @ApiProperty()
  fingerprint: string;

  @ApiProperty()
  bindAddress: string;

  @ApiProperty()
  bindPort: number;

  @ApiProperty()
  inspectionBypass: boolean;
}
