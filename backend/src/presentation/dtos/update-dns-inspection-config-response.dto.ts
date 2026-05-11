import { ApiProperty } from "@nestjs/swagger";
import { DnsInspectionConfigResponseDto } from "./dns-inspection-config-response.dto.js";

export class UpdateDnsInspectionConfigResponseDto {
  @ApiProperty({ type: DnsInspectionConfigResponseDto })
  dnsInspection: DnsInspectionConfigResponseDto;
}
