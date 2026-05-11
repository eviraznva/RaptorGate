import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator";

export class CreateZoneDto {
  @ApiProperty({
    example: "Living Room",
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  name: string;

  @ApiProperty({
    example: "The main living area of the house",
  })
  @IsString()
  description: string | null;

  @ApiProperty({
    example: true,
  })
  @IsNotEmpty()
  isActive: boolean;
}
