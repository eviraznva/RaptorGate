import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class GetConfigDiffQueryDto {
  @ApiProperty({
    example: 'cb5e59f3-0e31-44ce-963b-adeccf99dd45',
    format: 'uuid',
  })
  @IsUUID()
  baseId: string;

  @ApiProperty({
    example: 'be4de244-4c43-4924-ac8c-16df53be90f1',
    format: 'uuid',
  })
  @IsUUID()
  targetId: string;
}
