import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { IFirewallIpsConfigQueryService } from "src/application/ports/firewall-ips-config-query-service.interface";
import { IpsConfig } from "src/domain/entities/ips-config.entity";

@Injectable()
export class GrpcFirewallIpsConfigQueryService
  implements IFirewallIpsConfigQueryService
{
  async swapIpsConfig(): Promise<void> {
    throw new ServiceUnavailableException(
      "Direct IPS config RPC is not supported by generated proto. Use config snapshot push.",
    );
  }

  async getIpsConfig(): Promise<IpsConfig> {
    throw new ServiceUnavailableException(
      "Direct IPS config RPC is not supported by generated proto. Use local repository or config snapshot push.",
    );
  }
}
