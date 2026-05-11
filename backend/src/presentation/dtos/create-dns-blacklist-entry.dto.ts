import { ApiProperty } from "@nestjs/swagger";
import {
  IsBoolean,
  IsFQDN,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from "class-validator";

export class CreateDnsBlacklistEntryDto {
  @ApiProperty({
    example: "example.com",
    minLength: 1,
    maxLength: 255,
  })
  @IsNotEmpty()
  //@IsString()
  // @IsFQDN({
  //   require_tld: true,
  //   allow_underscores: false,
  //   allow_trailing_dot: false,
  //   allow_numeric_tld: false,
  //   allow_wildcard: false,
  // })
  domain: string[];

  @ApiProperty({
    example: "Known malicious domain",
    minLength: 1,
    maxLength: 255,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  reason: string;

  @ApiProperty({
    example: true,
  })
  @IsBoolean()
  isActive: boolean;
}
