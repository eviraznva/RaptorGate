export class FirewallCertificate {
	private constructor(
		private readonly id: string,
		private certType: "CA" | "TLS_SWERVER",
		private commonName: string,
		private fingerprint: string,
		private certificatePem: string,
		private privateKeyRef: string,
		private isActive: boolean,
		private expiresAt: Date,
		private readonly createdAt: Date,
	) {}

	public static create(
		id: string,
		certType: "CA" | "TLS_SWERVER",
		commonName: string,
		fingerprint: string,
		certificatePem: string,
		privateKeyRef: string,
		isActive: boolean,
		expiresAt: Date,
		createdAt: Date,
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
		);
	}

	public getId(): string {
		return this.id;
	}

	public getCertType(): "CA" | "TLS_SWERVER" {
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
}
