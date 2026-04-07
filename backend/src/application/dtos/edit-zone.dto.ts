export class EditZoneDto {
	id: string;
	name?: string;
	description?: string | null;
	isActive?: boolean;
	accessToken: string;
}
