import { IsOptional } from 'class-validator';
import { PaginationQueryDto } from './pagination-query.dto';

export class GetUsersQueryDto extends PaginationQueryDto {
  @IsOptional()
  role?: string;
}
