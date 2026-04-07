import { NatRuleItemResponseDto } from "./nat-rule-item-response.dto";
import { ApiProperty } from "@nestjs/swagger";

export class EditNatRuleResponseDto {
	@ApiProperty({
		type: () => NatRuleItemResponseDto,
		nullable: false,
		example: {
			id: "07c5b5fb-4304-4997-90e4-115af50098bb",
			type: "SNAT",
			isActive: true,
			sourceIp: "192.168.1.10",
			destinationIp: null,
			sourcePort: null,
			destinationPort: null,
			translatedIp: "172.16.0.20",
			translatedPort: null,
			priority: 10,
			createdAt: "2026-03-23T06:43:47.449Z",
			updatedAt: "2026-03-23T06:51:19.805Z",
		},
		required: true,
	})
	natRule: NatRuleItemResponseDto;
}
