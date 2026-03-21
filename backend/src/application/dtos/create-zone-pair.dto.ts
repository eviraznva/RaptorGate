import { ZonePairPolicy } from 'src/domain/entities/zone-pair.entity';

export class CreateZonePairDto {
  srcZoneId: string;
  dstZoneId: string;
  defaultPolicy: ZonePairPolicy;
  accessToken: string;
}
