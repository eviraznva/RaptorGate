export class EditZoneInterfaceDto {
  id: string;
  zoneId?: string;
  vlanId?: number | null;
  parentInterfaceId?: string | null;
  ipv4Address?: string | null;
  ipv4Mask?: number | null;
  ipv6Address?: string | null;
  ipv6Mask?: number | null;
  isActive?: boolean;
  sniffed?: boolean;
  accessToken: string;
}
