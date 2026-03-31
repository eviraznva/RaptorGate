import { ApiProperty } from '@nestjs/swagger';

export class ApplyConfigSnapshotResponseDto {
  @ApiProperty({
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  id: string;

  @ApiProperty({ example: 3 })
  versionNumber: number;

  @ApiProperty({
    example: 'manual_import',
    enum: ['manual_import', 'rollback_point', 'auto_save'],
  })
  snapshotType: string;

  @ApiProperty({
    example: '0374c1e803e24d736cf3794e75a78aa994c10e269f54b07e405f4d52600f12fc',
  })
  checksum: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({
    example: {},
  })
  payloadJson: unknown;

  @ApiProperty({
    example: 'Imported configuration from admin panel',
    required: false,
    nullable: true,
  })
  changesSummary: string | null;

  @ApiProperty({
    example: '2024-06-01T12:00:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    example: '345e4567-e89b-12d3-a456-426614174000',
  })
  createdBy: string;
}
