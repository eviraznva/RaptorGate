import type { TcpTrackedSession } from '../../domain/entities/tcp-tracked-session.entity.js';

export interface IFirewallTcpSessionsQueryService {
  getTcpSessions(): Promise<TcpTrackedSession[]>;
}

export const FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN = Symbol(
  'FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN',
);
