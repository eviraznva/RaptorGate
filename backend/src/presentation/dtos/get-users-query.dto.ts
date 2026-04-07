import { PaginationQueryDto } from "./pagination-query.dto";

export class GetUsersQueryDto extends PaginationQueryDto {
  role?: string;
}
