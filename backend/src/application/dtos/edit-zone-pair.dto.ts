import { ZonePairPolicy } from 'src/domain/entities/zone-pair.entity';

export class EditZonePairDto {
  id: string;
  srcZoneId?: string;
  dstZoneId?: string;
  defaultPolicy?: ZonePairPolicy;
  accessToken: string;
}
