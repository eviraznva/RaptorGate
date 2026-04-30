import { ApiProperty } from '@nestjs/swagger';
import { TcpTrackedSessionItemResponseDto } from './tcp-tracked-session-item-response.dto.js';

export class GetTcpSessionsResponseDto {
  @ApiProperty({ type: () => [TcpTrackedSessionItemResponseDto] })
  tcpSessions: TcpTrackedSessionItemResponseDto[];
}
