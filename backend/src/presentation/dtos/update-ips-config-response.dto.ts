import { ApiProperty } from "@nestjs/swagger";
import { IpsConfigResponseDto } from "./ips-config-response.dto";

export class UpdateIpsConfigResponseDto {
  @ApiProperty({
    type: IpsConfigResponseDto,
  })
  ipsConfig: IpsConfigResponseDto;
}
