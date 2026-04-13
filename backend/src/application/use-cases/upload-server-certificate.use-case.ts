import { X509Certificate, createPrivateKey } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
} from '@nestjs/common';
import { FirewallCertificate } from '../../domain/entities/firewall-certificate.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import {
  FIREWALL_CERTIFICATE_REPOSITORY_TOKEN,
  type IFirewallCertificateRepository,
} from '../../domain/repositories/firewall-certificate.repository.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { SecretStore } from '../../infrastructure/persistence/secret-store.js';

export interface UploadServerCertificateCommand {
  accessToken: string;
  certificatePem: string;
  privateKeyPem: string;
  bindAddress: string;
  bindPort?: number;
  inspectionBypass?: boolean;
  isActive?: boolean;
}

export interface UploadServerCertificateResult {
  id: string;
  commonName: string;
  fingerprint: string;
  bindAddress: string;
  bindPort: number;
  inspectionBypass: boolean;
}

@Injectable()
export class UploadServerCertificateUseCase {
  constructor(
    @Inject(FIREWALL_CERTIFICATE_REPOSITORY_TOKEN)
    private readonly firewallCertificateRepository: IFirewallCertificateRepository,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
    private readonly secretStore: SecretStore,
  ) {}

  async execute(
    dto: UploadServerCertificateCommand,
  ): Promise<UploadServerCertificateResult> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    if (!this.secretStore.isConfigured()) {
      throw new BadRequestException(
        'BACKEND_SECRET_ENCRYPTION_KEY is required to upload TLS server certificates',
      );
    }

    const certificate = this.parseCertificate(dto.certificatePem);
    const privateKey = this.parsePrivateKey(dto.privateKeyPem);
    this.ensureKeyMatchesCertificate(certificate, privateKey);

    const bindPort = dto.bindPort ?? 443;
    await this.ensureBindAddressIsUnique(dto.bindAddress, bindPort);

    const id = crypto.randomUUID();
    const privateKeyRef = crypto.randomUUID();
    const commonName = this.extractCommonName(certificate) ?? dto.bindAddress;
    const fingerprint = certificate.fingerprint256;
    const inspectionBypass = dto.inspectionBypass ?? false;
    const isActive = dto.isActive ?? true;

    await this.secretStore.save(privateKeyRef, dto.privateKeyPem);

    try {
      const serverCertificate = FirewallCertificate.create(
        id,
        'TLS_SERVER',
        commonName,
        fingerprint,
        dto.certificatePem,
        privateKeyRef,
        isActive,
        new Date(certificate.validTo),
        new Date(),
        dto.bindAddress,
        bindPort,
        inspectionBypass,
      );

      await this.firewallCertificateRepository.save(serverCertificate, claims.sub);
    } catch (error) {
      await this.secretStore.remove(privateKeyRef);
      throw error;
    }

    return {
      id,
      commonName,
      fingerprint,
      bindAddress: dto.bindAddress,
      bindPort,
      inspectionBypass,
    };
  }

  private parseCertificate(certificatePem: string): X509Certificate {
    try {
      return new X509Certificate(certificatePem);
    } catch {
      throw new BadRequestException('Invalid certificate PEM');
    }
  }

  private parsePrivateKey(privateKeyPem: string) {
    try {
      return createPrivateKey(privateKeyPem);
    } catch {
      throw new BadRequestException('Invalid private key PEM');
    }
  }

  private ensureKeyMatchesCertificate(
    certificate: X509Certificate,
    privateKey: ReturnType<typeof createPrivateKey>,
  ): void {
    const candidate = certificate as X509Certificate & {
      checkPrivateKey?: (key: ReturnType<typeof createPrivateKey>) => boolean;
    };

    if (
      typeof candidate.checkPrivateKey === 'function' &&
      !candidate.checkPrivateKey(privateKey)
    ) {
      throw new BadRequestException(
        'Certificate does not match the provided private key',
      );
    }
  }

  private extractCommonName(certificate: X509Certificate): string | null {
    const match = /CN\s*=\s*([^,\n/]+)/i.exec(certificate.subject);
    return match?.[1]?.trim() ?? null;
  }

  private async ensureBindAddressIsUnique(
    bindAddress: string,
    bindPort: number,
  ): Promise<void> {
    const certificates = await this.firewallCertificateRepository.findAll();
    const existing = certificates.find(
      (certificate) =>
        certificate.getBindAddress() === bindAddress &&
        certificate.getBindPort() === bindPort,
    );

    if (existing) {
      throw new ConflictException(
        `TLS server certificate for ${bindAddress}:${bindPort} already exists`,
      );
    }
  }
}
