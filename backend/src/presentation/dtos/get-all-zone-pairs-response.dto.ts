import { ZonePairItemResponseDto } from './zone-pair-item-response.dto';
import { ApiProperty } from '@nestjs/swagger';

export class GetAllZonePairsResponseDto {
  @ApiProperty({
    type: () => [ZonePairItemResponseDto],
  })
  zonePairs: ZonePairItemResponseDto[];
}
