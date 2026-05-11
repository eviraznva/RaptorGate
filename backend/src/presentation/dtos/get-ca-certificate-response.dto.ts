import { ApiProperty } from '@nestjs/swagger';

export class GetCaCertificateResponseDto {
  @ApiProperty({
    example:
      '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n',
  })
  certPem: string;

  @ApiProperty({
    example:
      'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89',
  })
  fingerprint: string;

  @ApiProperty({ example: '2036-03-30T00:00:00.000Z' })
  expiresAt: Date;
}
