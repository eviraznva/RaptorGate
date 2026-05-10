import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { IFirewallDnsInspectionQueryService } from '../../application/ports/firewall-dns-inspection-query-service.interface.js';
import type { DnsInspectionConfig } from '../../domain/entities/dns-inspection-config.entity.js';

export const FIREWALL_QUERY_GRPC_CLIENT_TOKEN = 'FIREWALL_QUERY_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcFirewallDnsInspectionQueryService
  implements IFirewallDnsInspectionQueryService
{
  async swapDnsInspectionConfig(): Promise<void> {
    throw new ServiceUnavailableException(
      'Direct DNS inspection config RPC is not supported by generated proto. Use config snapshot push.',
    );
  }

  async getDnsInspectionConfig(): Promise<DnsInspectionConfig> {
    throw new ServiceUnavailableException(
      'Direct DNS inspection config RPC is not supported by generated proto. Use local repository or config snapshot push.',
    );
  }
}
