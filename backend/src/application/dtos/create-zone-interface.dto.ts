export class CreateZoneInterfaceDto {
  parentInterfaceId: string;
  vlanId: number;
  zoneId: string;
  ipv4Address?: string | null;
  ipv4Mask?: number | null;
  ipv6Address?: string | null;
  ipv6Mask?: number | null;
  isActive?: boolean;
  sniffed?: boolean;
  accessToken: string;
}
