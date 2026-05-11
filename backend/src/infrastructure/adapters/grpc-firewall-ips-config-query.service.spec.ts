import { describe, expect, it } from '@jest/globals';
import { GrpcFirewallIpsConfigQueryService } from './grpc-firewall-ips-config-query.service.js';

describe('GrpcFirewallIpsConfigQueryService', () => {
  it('rejects direct IPS config swap', async () => {
    const service = new GrpcFirewallIpsConfigQueryService();

    await expect(service.swapIpsConfig()).rejects.toThrow(
      'Direct IPS config RPC is not supported by generated proto. Use config snapshot push.',
    );
  });

  it('rejects direct IPS config get', async () => {
    const service = new GrpcFirewallIpsConfigQueryService();

    await expect(service.getIpsConfig()).rejects.toThrow(
      'Direct IPS config RPC is not supported by generated proto. Use local repository or config snapshot push.',
    );
  });
});
