export class EditZoneInterfaceDto {
  id: string;
  zoneId?: string;
  vlanId?: number | null;
  ipv4Address?: string | null;
  ipv4Mask?: number | null;
  ipv6Address?: string | null;
  ipv6Mask?: number | null;
  isActive?: boolean;
  accessToken: string;
}
