export class CreateRuleDto {
	name: string;
	description?: string;
	zonePairId: string;
	isActive: boolean;
	content: string;
	priority: number;
	accessToken: string;
}
