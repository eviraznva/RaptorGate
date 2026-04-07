export class ZoneAccessPolicy {
	private constructor(
		private readonly id: string,
		private defaultPolicy: "ALLOW" | "DROP",
		private readonly createdAt: Date,
	) {}

	public static create(
		id: string,
		defaultPolicy: "ALLOW" | "DROP",
		createdAt: Date,
	): ZoneAccessPolicy {
		return new ZoneAccessPolicy(id, defaultPolicy, createdAt);
	}

	public getId(): string {
		return this.id;
	}

	public getDefaultPolicy(): "ALLOW" | "DROP" {
		return this.defaultPolicy;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}
}
