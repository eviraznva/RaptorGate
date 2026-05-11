export class FirewallCertificate {
  private constructor(
    private readonly id: string,
    private certType: 'CA' | 'TLS_SERVER',
    private commonName: string,
    private fingerprint: string,
    private certificatePem: string,
    private privateKeyRef: string,
    private isActive: boolean,
    private expiresAt: Date,
    private readonly createdAt: Date,
    private bindAddress: string,
    private bindPort: number,
    private inspectionBypass: boolean,
  ) {}

  public static create(
    id: string,
    certType: 'CA' | 'TLS_SERVER',
    commonName: string,
    fingerprint: string,
    certificatePem: string,
    privateKeyRef: string,
    isActive: boolean,
    expiresAt: Date,
    createdAt: Date,
    bindAddress: string = '',
    bindPort: number = 443,
    inspectionBypass: boolean = false,
  ): FirewallCertificate {
    return new FirewallCertificate(
      id,
      certType,
      commonName,
      fingerprint,
      certificatePem,
      privateKeyRef,
      isActive,
      expiresAt,
      createdAt,
      bindAddress,
      bindPort,
      inspectionBypass,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getCertType(): 'CA' | 'TLS_SERVER' {
    return this.certType;
  }

  public getCommonName(): string {
    return this.commonName;
  }

  public getFingerprint(): string {
    return this.fingerprint;
  }

  public getCertificatePem(): string {
    return this.certificatePem;
  }

  public getPrivateKeyRef(): string {
    return this.privateKeyRef;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getExpiresAt(): Date {
    return this.expiresAt;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getBindAddress(): string {
    return this.bindAddress;
  }

  public getBindPort(): number {
    return this.bindPort;
  }

  public getInspectionBypass(): boolean {
    return this.inspectionBypass;
  }
}
