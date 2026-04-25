import { ApiProperty } from '@nestjs/swagger';

class ConfigDiffSnapshotDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  versionNumber: number;

  @ApiProperty()
  checksum: string;

  @ApiProperty()
  createdAt: string;
}

class ConfigDiffSectionSummaryDto {
  @ApiProperty()
  added: number;

  @ApiProperty()
  removed: number;

  @ApiProperty()
  modified: number;
}

class ConfigDiffSummaryDto extends ConfigDiffSectionSummaryDto {
  @ApiProperty({
    type: 'object',
    additionalProperties: {
      type: 'object',
      properties: {
        added: { type: 'number' },
        removed: { type: 'number' },
        modified: { type: 'number' },
      },
    },
  })
  bySection: Record<string, ConfigDiffSectionSummaryDto>;
}

class ConfigDiffChangeDto {
  @ApiProperty({ enum: ['added', 'removed', 'modified'] })
  type: string;

  @ApiProperty({ example: 'rules' })
  section: string;

  @ApiProperty({
    example: 'bundle.rules.items.a1c6151b-e916-456d-b4f9-2d57d2075aff.priority',
  })
  path: string;

  @ApiProperty({ required: false })
  entityId?: string;

  @ApiProperty({ required: false })
  before?: unknown;

  @ApiProperty({ required: false })
  after?: unknown;
}

export class GetConfigDiffResponseDto {
  @ApiProperty({ type: ConfigDiffSnapshotDto })
  baseSnapshot: ConfigDiffSnapshotDto;

  @ApiProperty({ type: ConfigDiffSnapshotDto })
  targetSnapshot: ConfigDiffSnapshotDto;

  @ApiProperty({ type: ConfigDiffSummaryDto })
  summary: ConfigDiffSummaryDto;

  @ApiProperty({ type: [ConfigDiffChangeDto] })
  changes: ConfigDiffChangeDto[];
}
