import { ApiProperty } from "@nestjs/swagger";

export class ValidateAccessTokenResponseDto {
  @ApiProperty({
    example: true,
  })
  valid: boolean;
}
