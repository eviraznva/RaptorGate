import { ApiProperty } from "@nestjs/swagger";
import { IpsConfigResponseDto } from "./ips-config-response.dto";

export class GetIpsConfigResponseDto {
  @ApiProperty({
    type: IpsConfigResponseDto,
  })
  ipsConfig: IpsConfigResponseDto;
}
