import { ApiProperty } from "@nestjs/swagger";
import { DnsBlacklistEntryItemResponseDto } from "./dns-blacklist-item-response.dto";

export class CreateDnsBlacklistEntryResponseDto {
  @ApiProperty({
    type: DnsBlacklistEntryItemResponseDto,
  })
  entry: DnsBlacklistEntryItemResponseDto[];
}
