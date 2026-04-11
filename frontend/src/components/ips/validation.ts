import type { IpsConfig } from "../../types/ipsConfig/IpsConfig";

function isValidPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

export function validateIpsConfig(config: IpsConfig): string[] {
  const errors: string[] = [];

  if (
    !Number.isInteger(config.detection.maxPayloadBytes) ||
    config.detection.maxPayloadBytes <= 0
  ) {
    errors.push("Detection: max payload bytes must be a positive integer.");
  }

  if (
    !Number.isInteger(config.detection.maxMatchesPerPacket) ||
    config.detection.maxMatchesPerPacket <= 0
  ) {
    errors.push("Detection: max matches per packet must be a positive integer.");
  }

  const idUsage = new Map<string, number>();

  for (const signature of config.signatures) {
    const id = signature.id.trim();
    const name = signature.name.trim();
    const pattern = signature.pattern.trim();
    const signatureLabel = id || "<empty-id>";

    idUsage.set(id, (idUsage.get(id) ?? 0) + 1);

    if (!id) {
      errors.push("Signatures: each signature must have a non-empty ID.");
    }

    if (!name) {
      errors.push(`Signature '${signatureLabel}': name is required.`);
    }

    if (!pattern) {
      errors.push(`Signature '${signatureLabel}': regex pattern is required.`);
    } else {
      try {
        // Backend validates regex with Rust regex syntax; this is a best-effort client check.
        // eslint-disable-next-line no-new
        new RegExp(pattern);
      } catch {
        errors.push(`Signature '${signatureLabel}': invalid regex pattern.`);
      }
    }

    for (const port of signature.srcPorts) {
      if (!isValidPort(port)) {
        errors.push(
          `Signature '${signatureLabel}': source port '${port}' must be in range 1..65535.`,
        );
      }
    }

    for (const port of signature.dstPorts) {
      if (!isValidPort(port)) {
        errors.push(
          `Signature '${signatureLabel}': destination port '${port}' must be in range 1..65535.`,
        );
      }
    }
  }

  for (const [id, count] of idUsage.entries()) {
    if (id && count > 1) {
      errors.push(`Signatures: duplicate ID '${id}' detected.`);
    }
  }

  return errors;
}

