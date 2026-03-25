import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';

export class GetConfigHistoryDto {
  configHistory: ConfigurationSnapshot[];
}
