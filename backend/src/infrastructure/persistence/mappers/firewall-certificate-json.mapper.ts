import { FirewallCertificate } from '../../../domain/entities/firewall-certificate.entity.js';
import { FirewallCertificateRecord } from '../schemas/firewall-certificates.schema.js';

export class FirewallCertificateJsonMapper {
  static toDomain(record: FirewallCertificateRecord): FirewallCertificate {
    return FirewallCertificate.create(
      record.id,
      record.certType as 'CA' | 'TLS_SERVER',
      record.commonName,
      record.fingerprint,
      record.certificatePem,
      record.privateKeyRef,
      record.isActive,
      new Date(record.expiresAt),
      new Date(record.createdAt),
      record.bindAddress,
      record.bindPort,
      record.inspectionBypass,
    );
  }

  static toRecord(
    cert: FirewallCertificate,
    createdBy: string,
  ): FirewallCertificateRecord {
    return {
      id: cert.getId(),
      certType: cert.getCertType(),
      commonName: cert.getCommonName(),
      fingerprint: cert.getFingerprint(),
      certificatePem: cert.getCertificatePem(),
      privateKeyRef: cert.getPrivateKeyRef(),
      isActive: cert.getIsActive(),
      expiresAt: cert.getExpiresAt().toISOString(),
      createdAt: cert.getCreatedAt().toISOString(),
      createdBy,
      bindAddress: cert.getBindAddress(),
      bindPort: cert.getBindPort(),
      inspectionBypass: cert.getInspectionBypass(),
    };
  }
}
