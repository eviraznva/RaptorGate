import { PaginationDto } from './pagination.dto';

export class GetUsersDto extends PaginationDto {
  role?: string;
}
