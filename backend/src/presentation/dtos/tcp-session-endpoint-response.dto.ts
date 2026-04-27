import { ApiProperty } from '@nestjs/swagger';

export class TcpSessionEndpointResponseDto {
  @ApiProperty({ example: '192.168.1.10' })
  ip: string;

  @ApiProperty({ example: 443 })
  port: number;
}
