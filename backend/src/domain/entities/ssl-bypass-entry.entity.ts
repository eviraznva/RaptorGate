export class SslBypassEntry {
	private constructor(
		private readonly id: string,
		private domain: string,
		private reason: string,
		private isActive: boolean,
		private readonly createdAt: Date,
	) {}

	public static create(
		id: string,
		domain: string,
		reason: string,
		isActive: boolean,
		createdAt: Date,
	): SslBypassEntry {
		return new SslBypassEntry(id, domain, reason, isActive, createdAt);
	}

	public getId(): string {
		return this.id;
	}

	public getDomain(): string {
		return this.domain;
	}

	public getReason(): string {
		return this.reason;
	}

	public getIsActive(): boolean {
		return this.isActive;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}
}
