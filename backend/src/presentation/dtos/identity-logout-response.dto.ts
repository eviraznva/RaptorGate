import { ApiProperty } from '@nestjs/swagger';

export class IdentityLogoutResponseDto {
  @ApiProperty({
    description:
      'true gdy backend albo firewall usunal sesje pod tym source IP',
  })
  removed: boolean;
}
