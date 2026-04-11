export type ZonePairPolicy = "ALLOW" | "DROP";

export class ZonePair {
	constructor(
		private readonly id: string,
		private srcZoneId: string,
		private dstZoneId: string,
		private defaultPolicy: ZonePairPolicy,
		private createdAt: Date,
		private readonly createdBy: string,
	) {}

	public static create(
		id: string,
		srcZoneId: string,
		dstZoneId: string,
		defaultPolicy: ZonePairPolicy,
		createdAt: Date,
		createdBy: string,
	): ZonePair {
		return new ZonePair(
			id,
			srcZoneId,
			dstZoneId,
			defaultPolicy,
			createdAt,
			createdBy,
		);
	}

	public getId(): string {
		return this.id;
	}

	public getSrcZoneId(): string {
		return this.srcZoneId;
	}

	public getDstZoneId(): string {
		return this.dstZoneId;
	}

	public getDefaultPolicy(): ZonePairPolicy {
		return this.defaultPolicy;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}

	public getCreatedBy(): string {
		return this.createdBy;
	}

	public setSrcZoneId(srcZoneId: string): void {
		this.srcZoneId = srcZoneId;
	}

	public setDstZoneId(dstZoneId: string): void {
		this.dstZoneId = dstZoneId;
	}

	public setDefaultPolicy(defaultPolicy: ZonePairPolicy): void {
		this.defaultPolicy = defaultPolicy;
	}
}
