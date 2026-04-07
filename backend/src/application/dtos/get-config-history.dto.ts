import { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";

export class GetConfigHistoryDto {
	configHistory: ConfigurationSnapshot[];
}
