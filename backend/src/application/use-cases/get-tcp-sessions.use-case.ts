import { Inject, Injectable } from '@nestjs/common';
import type { GetTcpSessionsDto } from '../dtos/get-tcp-sessions.dto.js';
import {
  FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN,
  type IFirewallTcpSessionsQueryService,
} from '../ports/firewall-tcp-sessions-query-service.interface.js';

@Injectable()
export class GetTcpSessionsUseCase {
  constructor(
    @Inject(FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN)
    private readonly firewallTcpSessionsQueryService: IFirewallTcpSessionsQueryService,
  ) {}

  async execute(): Promise<GetTcpSessionsDto> {
    const tcpSessions =
      await this.firewallTcpSessionsQueryService.getTcpSessions();

    return { tcpSessions };
  }
}
