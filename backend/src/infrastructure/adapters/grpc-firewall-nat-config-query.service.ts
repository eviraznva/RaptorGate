import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { IFirewallNatConfigQueryService } from '../../application/ports/firewall-nat-config-query-service.interface.js';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';

@Injectable()
export class GrpcFirewallNatConfigQueryService
  implements IFirewallNatConfigQueryService
{
  async swapNatConfig(): Promise<void> {
    throw new ServiceUnavailableException(
      'Direct NAT config RPC is not supported by generated proto. Use config snapshot push.',
    );
  }

  async getNatConfig(): Promise<NatRule[]> {
    throw new ServiceUnavailableException(
      'Direct NAT config RPC is not supported by generated proto. Use config snapshot push.',
    );
  }
}
