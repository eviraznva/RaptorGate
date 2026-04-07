import { ZonePairPolicy } from "../../domain/entities/zone-pair.entity.js";

export class CreateZonePairDto {
	srcZoneId: string;
	dstZoneId: string;
	defaultPolicy: ZonePairPolicy;
	accessToken: string;
}
