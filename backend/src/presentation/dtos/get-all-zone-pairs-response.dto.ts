import { ApiProperty } from '@nestjs/swagger';
import { ZonePairItemResponseDto } from './zone-pair-item-response.dto';

export class GetAllZonePairsResponseDto {
  @ApiProperty({
    type: () => [ZonePairItemResponseDto],
  })
  zonePairs: ZonePairItemResponseDto[];
}
