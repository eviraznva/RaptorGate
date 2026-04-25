import { ApiProperty } from '@nestjs/swagger';

export class IdentityLoginResponseDto {
  @ApiProperty()
  sessionId: string;

  @ApiProperty()
  username: string;

  @ApiProperty()
  sourceIp: string;

  @ApiProperty({ type: String, format: 'date-time' })
  authenticatedAt: Date;

  @ApiProperty({ type: String, format: 'date-time' })
  expiresAt: Date;
}
