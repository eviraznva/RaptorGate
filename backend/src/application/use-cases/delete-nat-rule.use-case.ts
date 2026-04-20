import { Inject, Injectable, Logger } from "@nestjs/common";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import {
  FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN,
  type IFirewallNatConfigQueryService,
} from "../ports/firewall-nat-config-query-service.interface.js";

@Injectable()
export class DeleteNatRuleUseCase {
  private readonly logger = new Logger(DeleteNatRuleUseCase.name);

  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN)
    private readonly firewallNatConfigQueryService: IFirewallNatConfigQueryService,
  ) {}

  async execute(id: string): Promise<void> {
    const existingRule = await this.natRulesRepository.findById(id);
    if (!existingRule) throw new EntityNotFoundException("Nat rule", id);

    await this.natRulesRepository.delete(id);

    const allNatRules = await this.natRulesRepository.findAll();
    await this.firewallNatConfigQueryService.swapNatConfig(allNatRules);

    this.logger.log({
      event: "nat_rule.delete.succeeded",
      message: "NAT rule deleted",
      natRuleId: existingRule.getId(),
      type: existingRule.getType().getValue(),
    });
  }
}
