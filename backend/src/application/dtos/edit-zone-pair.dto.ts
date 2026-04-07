import { ZonePairPolicy } from "../../domain/entities/zone-pair.entity.js";

export class EditZonePairDto {
	id: string;
	srcZoneId?: string;
	dstZoneId?: string;
	defaultPolicy?: ZonePairPolicy;
	accessToken: string;
}
