import { PaginationDto } from "./pagination.dto";

export class GetNatRulesDto extends PaginationDto {
  type?: string;
  isActive?: boolean;
}
