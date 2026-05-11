import { ApiProperty } from "@nestjs/swagger";
import { Transform, Type } from "class-transformer";
import {
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsIP,
  IsNotEmpty,
  IsNumber,
  IsString,
  Max,
  Min,
  ValidateIf,
  ValidateNested,
} from "class-validator";

class DnsInspectionGeneralDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  enabled: boolean;
}

class DnsInspectionBlocklistDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ type: [String], example: ["example.com"] })
  @IsArray()
  @IsString({ each: true })
  domains: string[];
}

class DnsInspectionDnsTunnelingDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: 40 })
  @IsInt()
  @Min(0)
  maxLabelLength: number;

  @ApiProperty({ example: 3.5 })
  @IsNumber()
  @Min(0)
  entropyThreshold: number;

  @ApiProperty({ example: 60 })
  @IsInt()
  @Min(0)
  windowSeconds: number;

  @ApiProperty({ example: 100 })
  @IsInt()
  @Min(0)
  maxQueriesPerDomain: number;

  @ApiProperty({ example: 20 })
  @IsInt()
  @Min(0)
  maxUniqueSubdomains: number;

  @ApiProperty({ type: [String], example: [] })
  @IsArray()
  @IsString({ each: true })
  ignoreDomains: string[];

  @ApiProperty({ example: 0.6 })
  @IsNumber()
  @Min(0)
  @Max(1)
  alertThreshold: number;

  @ApiProperty({ example: 0.85 })
  @IsNumber()
  @Min(0)
  @Max(1)
  blockThreshold: number;
}

class DnsInspectionDnssecResolverEndpointDto {
  @ApiProperty({ example: "127.0.0.1" })
  @Transform(({ value }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @IsNotEmpty()
  @IsIP()
  address: string;

  @ApiProperty({ example: 53 })
  @IsInt()
  @Min(1)
  @Max(65535)
  port: number;
}

class DnsInspectionDnssecSecondaryResolverEndpointDto {
  @ApiProperty({ example: "", required: false })
  @Transform(({ value }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @ValidateIf((_, value) => value !== "")
  @IsIP()
  address: string;

  @ApiProperty({ example: 53 })
  @IsInt()
  @Min(1)
  @Max(65535)
  port: number;
}

class DnsInspectionDnssecResolverDto {
  @ApiProperty({ type: DnsInspectionDnssecResolverEndpointDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecResolverEndpointDto)
  primary: DnsInspectionDnssecResolverEndpointDto;

  @ApiProperty({ type: DnsInspectionDnssecSecondaryResolverEndpointDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecSecondaryResolverEndpointDto)
  secondary: DnsInspectionDnssecSecondaryResolverEndpointDto;

  @ApiProperty({
    example: "udpWithTcpFallback",
    enum: ["udp", "tcp", "udpWithTcpFallback"],
  })
  @IsIn(["udp", "tcp", "udpWithTcpFallback"])
  transport: "udp" | "tcp" | "udpWithTcpFallback";

  @ApiProperty({ example: 2000 })
  @IsInt()
  @Min(0)
  timeoutMs: number;

  @ApiProperty({ example: 1 })
  @IsInt()
  @Min(0)
  retries: number;
}

class DnsInspectionDnssecCacheTtlDto {
  @ApiProperty({ example: 300 })
  @IsInt()
  @Min(0)
  secure: number;

  @ApiProperty({ example: 300 })
  @IsInt()
  @Min(0)
  insecure: number;

  @ApiProperty({ example: 60 })
  @IsInt()
  @Min(0)
  bogus: number;

  @ApiProperty({ example: 15 })
  @IsInt()
  @Min(0)
  failure: number;
}

class DnsInspectionDnssecCacheDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: 4096 })
  @IsInt()
  @Min(0)
  maxEntries: number;

  @ApiProperty({ type: DnsInspectionDnssecCacheTtlDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecCacheTtlDto)
  ttlSeconds: DnsInspectionDnssecCacheTtlDto;
}

class DnsInspectionDnssecDto {
  @ApiProperty({ example: false })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: 1 })
  @IsInt()
  @Min(0)
  maxLookupsPerPacket: number;

  @ApiProperty({ example: "allow", enum: ["allow", "alert", "block"] })
  @IsIn(["allow", "alert", "block"])
  defaultOnResolverFailure: "allow" | "alert" | "block";

  @ApiProperty({ type: DnsInspectionDnssecResolverDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecResolverDto)
  resolver: DnsInspectionDnssecResolverDto;

  @ApiProperty({ type: DnsInspectionDnssecCacheDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecCacheDto)
  cache: DnsInspectionDnssecCacheDto;
}

export class UpdateDnsInspectionConfigDto {
  @ApiProperty({ type: DnsInspectionGeneralDto })
  @ValidateNested()
  @Type(() => DnsInspectionGeneralDto)
  general: DnsInspectionGeneralDto;

  @ApiProperty({ type: DnsInspectionBlocklistDto })
  @ValidateNested()
  @Type(() => DnsInspectionBlocklistDto)
  blocklist: DnsInspectionBlocklistDto;

  @ApiProperty({ type: DnsInspectionDnsTunnelingDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnsTunnelingDto)
  dnsTunneling: DnsInspectionDnsTunnelingDto;

  @ApiProperty({ type: DnsInspectionDnssecDto })
  @ValidateNested()
  @Type(() => DnsInspectionDnssecDto)
  dnssec: DnsInspectionDnssecDto;
}
