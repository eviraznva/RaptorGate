import { ApiProperty } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';

export class EditZoneDto {
  @ApiProperty({
    example: 'Living Room',
  })
  @IsOptional()
  name?: string;

  @ApiProperty({
    example: 'The main living area of the house',
  })
  @IsOptional()
  description?: string | null;

  @ApiProperty({
    example: true,
  })
  @IsOptional()
  isActive?: boolean;
}
