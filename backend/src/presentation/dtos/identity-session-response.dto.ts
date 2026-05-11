import { ApiProperty } from '@nestjs/swagger';

export class IdentitySessionResponseDto {
  @ApiProperty({
    description:
      'true gdy istnieje aktywna, niewygasla sesja identity dla tego source IP',
  })
  authenticated: boolean;

  @ApiProperty()
  sourceIp: string;

  @ApiProperty({ required: false })
  sessionId?: string;

  @ApiProperty({ required: false })
  username?: string;

  @ApiProperty({ required: false, type: String, format: 'date-time' })
  authenticatedAt?: Date;

  @ApiProperty({ required: false, type: String, format: 'date-time' })
  expiresAt?: Date;

  @ApiProperty({ required: false, type: [String] })
  groups?: string[];
}
