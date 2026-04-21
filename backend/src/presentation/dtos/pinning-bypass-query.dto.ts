import { ApiProperty } from '@nestjs/swagger';
import { IsIP, IsNotEmpty, IsString, MaxLength } from 'class-validator';

export class PinningBypassQueryDto {
  @ApiProperty({
    description: 'Source IP of the client whose bypass status is queried',
    example: '10.0.0.42',
  })
  @IsIP()
  sourceIp: string;

  @ApiProperty({
    description: 'Domain (SNI) of the pinned site',
    example: 'api.example.com',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(253)
  domain: string;
}
