export type ZoneInterfaceStatus =
  | "unspecified"
  | "active"
  | "inactive"
  | "missing"
  | "unknown";

export interface ZoneInterface {
  id: string;
  zoneId: string;
  interfaceName: string;
  vlanId: number | null;
  status: ZoneInterfaceStatus;
  addresses: string[];
  sniffed: boolean;
  createdAt: string;
  parentInterfaceId: string | null;
  parentInterfaceName: string | null;
}
