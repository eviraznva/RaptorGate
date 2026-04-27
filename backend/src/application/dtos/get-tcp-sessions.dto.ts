import type { TcpTrackedSession } from '../../domain/entities/tcp-tracked-session.entity.js';

export interface GetTcpSessionsDto {
  tcpSessions: TcpTrackedSession[];
}
