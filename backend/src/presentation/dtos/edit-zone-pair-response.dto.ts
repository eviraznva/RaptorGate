import { ZonePairItemResponseDto } from './zone-pair-item-response.dto';
import { ApiProperty } from '@nestjs/swagger';

export class EditZonePairResponseDto {
  @ApiProperty({
    type: () => ZonePairItemResponseDto,
    example: {
      id: 'dcb9f221-cc1b-4432-a40d-9890b8a74dd2',
      srcZoneId: 'c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4',
      dstZoneID: 'a0db06f9-5063-4035-aadd-845248db19e4',
      defaultPolicy: 'ALLOW',
      createdAt: '2026-03-20T20:17:17.850Z',
      createdBy: '00000000-0000-4000-8000-000000000001',
    },
  })
  zonePair: ZonePairItemResponseDto;
}
