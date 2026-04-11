export class EditRuleDto {
	id: string;
	name?: string;
	description?: string;
	zonePairId?: string;
	isActive?: boolean;
	content?: string;
	priority?: number;
}
