import { Transform } from "class-transformer";
import { IsBoolean, IsOptional } from "class-validator";
import { PaginationQueryDto } from "./pagination-query.dto";

export class GetRulesQueryDto extends PaginationQueryDto {
  @IsBoolean()
  @Transform(({ value }) => value === "true")
  @IsOptional()
  isActive?: boolean;
}
