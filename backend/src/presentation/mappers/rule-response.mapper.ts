import { FirewallRule } from "src/domain/entities/firewall-rule.entity";
import { RuleItemResponseDto } from "../dtos/rule-item-response.dto";

export class RuleResponseMapper {
	static toDto(rule: FirewallRule): RuleItemResponseDto {
		return {
			id: rule.getId(),
			name: rule.getName(),
			description: rule.getDescription(),
			zonePairId: rule.getZonePairId(),
			isActive: rule.getIsActive(),
			content: rule.getContent(),
			priority: rule.getPriority().getValue(),
			createdBy: rule.getCreatedBy(),
			createdAt: rule.getCreatedAt().toISOString(),
			updatedAt: rule.getUpdatedAt().toISOString(),
		};
	}
}
