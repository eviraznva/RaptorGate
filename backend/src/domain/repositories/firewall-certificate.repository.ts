import { FirewallCertificate } from '../entities/firewall-certificate.entity.js';

export interface IFirewallCertificateRepository {
  save(cert: FirewallCertificate, createdBy?: string): Promise<void>;
  findById(id: string): Promise<FirewallCertificate | null>;
  findAll(): Promise<FirewallCertificate[]>;
  findActive(): Promise<FirewallCertificate[]>;
  overwriteAll(certs: FirewallCertificate[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const FIREWALL_CERTIFICATE_REPOSITORY_TOKEN = Symbol(
  'FIREWALL_CERTIFICATE_REPOSITORY_TOKEN',
);
