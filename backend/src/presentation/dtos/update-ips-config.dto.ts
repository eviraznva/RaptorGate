import { ApiProperty } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
  IsArray,
  IsBoolean,
  IsIn,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
  ValidateNested,
} from "class-validator";

export type IpsSeverity =
  | "unspecified"
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical"
  | "unrecognized";

const IPS_SEVERITIES: IpsSeverity[] = [
  "unspecified",
  "info",
  "low",
  "medium",
  "high",
  "critical",
  "unrecognized",
];

export type IpsAction = "unspecified" | "alert" | "block" | "unrecognized";

const IPS_ACTIONS: IpsAction[] = [
  "unspecified",
  "alert",
  "block",
  "unrecognized",
];

export type IpsAppProtocol =
  | "http"
  | "tls"
  | "dns"
  | "ssh"
  | "ftp"
  | "smtp"
  | "rdp"
  | "smb"
  | "quic"
  | "unknown";

const IPS_APP_PROTOCOLS: IpsAppProtocol[] = [
  "http",
  "tls",
  "dns",
  "ssh",
  "ftp",
  "smtp",
  "rdp",
  "smb",
  "quic",
  "unknown",
];

export type IpsMatchType = "literal" | "regex";

const IPS_MATCH_TYPES: IpsMatchType[] = ["literal", "regex"];

export type IpsPatternEncoding = "text" | "hex";

const IPS_PATTERN_ENCODINGS: IpsPatternEncoding[] = ["text", "hex"];

export class IpsGeneralConfig {
  @ApiProperty({
    description: "Określa, czy główna usługa IPS jest włączona",
    example: true,
  })
  @IsBoolean()
  enabled: boolean;
}

export class IpsDetectionConfigDto {
  @ApiProperty({
    description: "Określa, czy detekcja IPS jest włączona",
    example: true,
  })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({
    description: "Maksymalny rozmiar payloadu do analizy (w bajtach)",
    example: 8192,
  })
  @IsNumber()
  @Min(0)
  maxPayloadBytes: number;

  @ApiProperty({
    description: "Maksymalna liczba dopasowań na jeden pakiet",
    example: 10,
  })
  @IsNumber()
  @Min(0)
  maxMatchesPerPacket: number;
}

export class IpsSignatureConfigDto {
  @ApiProperty({
    description: "Unikalny identyfikator sygnatury",
    example: "sig-12345",
  })
  @IsString()
  id: string;

  @ApiProperty({
    description: "Nazwa sygnatury",
    example: "SQL Injection Attempt",
  })
  @IsString()
  name: string;

  @ApiProperty({
    description: "Czy sygnatura jest włączona",
    example: true,
  })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({
    description: "Kategoria zagrożenia",
    example: "web-attack",
  })
  @IsString()
  category: string;

  @ApiProperty({
    description: "Wzorzec dopasowania sygnatury (np. Regex)",
    example: "(?i)(UNION.*SELECT)",
  })
  @IsString()
  pattern: string;

  @ApiProperty({
    enum: IPS_MATCH_TYPES,
    description: "Typ dopasowania wzorca",
    example: "regex",
    default: "regex",
  })
  @IsOptional()
  @IsIn(IPS_MATCH_TYPES)
  matchType: IpsMatchType = "regex";

  @ApiProperty({
    enum: IPS_PATTERN_ENCODINGS,
    description: "Kodowanie wzorca",
    example: "text",
    default: "text",
  })
  @IsOptional()
  @IsIn(IPS_PATTERN_ENCODINGS)
  patternEncoding: IpsPatternEncoding = "text";

  @ApiProperty({
    description: "Czy dopasowanie tekstowe ma ignorować wielkość liter",
    example: false,
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  caseInsensitive: boolean = false;

  @ApiProperty({
    enum: IPS_SEVERITIES,
    description: "Poziom krytyczności sygnatury",
    example: "high",
  })
  @IsIn(IPS_SEVERITIES)
  severity: IpsSeverity;

  @ApiProperty({
    enum: IPS_ACTIONS,
    description: "Akcja podejmowana w przypadku dopasowania",
    example: "block",
  })
  @IsIn(IPS_ACTIONS)
  action: IpsAction;

  @ApiProperty({
    enum: IPS_APP_PROTOCOLS,
    isArray: true,
    description: "Lista protokołów aplikacyjnych, których dotyczy sygnatura",
    example: ["http", "tls"],
  })
  @IsArray()
  @IsIn(IPS_APP_PROTOCOLS, { each: true })
  appProtocols: IpsAppProtocol[];

  @ApiProperty({
    type: [Number],
    description: "Lista portów źródłowych. Pusta lista oznacza wszystkie",
    example: [80, 443],
  })
  @IsArray()
  @IsNumber({}, { each: true })
  @Min(1, { each: true })
  @Max(65535, { each: true })
  srcPorts: number[];

  @ApiProperty({
    type: [Number],
    description: "Lista portów docelowych. Pusta lista oznacza wszystkie",
    example: [80, 443],
  })
  @IsArray()
  @IsNumber({}, { each: true })
  @Min(1, { each: true })
  @Max(65535, { each: true })
  dstPorts: number[];
}

export class UpdateIpsConfigDto {
  @ApiProperty({ type: IpsGeneralConfig })
  @ValidateNested()
  @Type(() => IpsGeneralConfig)
  general: IpsGeneralConfig;

  @ApiProperty({ type: IpsDetectionConfigDto })
  @ValidateNested()
  @Type(() => IpsDetectionConfigDto)
  detection: IpsDetectionConfigDto;

  @ApiProperty({ type: [IpsSignatureConfigDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IpsSignatureConfigDto)
  signatures: IpsSignatureConfigDto[];
}
