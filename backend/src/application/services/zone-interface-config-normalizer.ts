import { ZoneInterface } from "../../domain/entities/zone-interface.entity.js";

export function normalizeZoneInterfaceAddressesForConfig(
  vlanId: number | null,
  addresses: string[],
): string[] {
  if (vlanId !== null || addresses.length <= 1) {
    return [...addresses];
  }

  const nonLinkLocalAddresses = addresses.filter(
    (address) => !isIpv6LinkLocal(address),
  );
  const candidates =
    nonLinkLocalAddresses.length > 0 ? nonLinkLocalAddresses : addresses;
  const preferredAddress =
    candidates.find(isIpv4Address) ??
    candidates.find(isIpv6Address) ??
    candidates[0];

  return preferredAddress ? [preferredAddress] : [];
}

export function normalizeZoneInterfaceForConfig(
  zoneInterface: ZoneInterface,
): ZoneInterface {
  const normalizedAddresses = normalizeZoneInterfaceAddressesForConfig(
    zoneInterface.getVlanId(),
    zoneInterface.getAddresses(),
  );

  if (
    normalizedAddresses.length === zoneInterface.getAddresses().length &&
    normalizedAddresses.every(
      (address, index) => address === zoneInterface.getAddresses()[index],
    )
  ) {
    return zoneInterface;
  }

  return ZoneInterface.create(
    zoneInterface.getId(),
    zoneInterface.getZoneId(),
    zoneInterface.getInterfaceName(),
    zoneInterface.getVlanId(),
    zoneInterface.getStatus(),
    normalizedAddresses,
    zoneInterface.getCreatedAt(),
    zoneInterface.getSniffed(),
    zoneInterface.getParentInterfaceId(),
  );
}

function isIpv4Address(address: string): boolean {
  return address.includes(".");
}

function isIpv6Address(address: string): boolean {
  return address.includes(":");
}

function isIpv6LinkLocal(address: string): boolean {
  const value = address.split("/")[0]?.toLowerCase() ?? "";
  return /^fe[89ab]/.test(value);
}
