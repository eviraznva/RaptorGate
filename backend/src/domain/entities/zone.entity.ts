export class Zone {
	private constructor(
		private readonly id: string,
		private name: string,
		private description: string | null,
		private isActive: boolean,
		private readonly createdAt: Date,
		private readonly createdBy: string,
	) {}

	public static create(
		id: string,
		name: string,
		description: string | null,
		isActive: boolean,
		createdAt: Date,
		createdBy: string,
	): Zone {
		return new Zone(id, name, description, isActive, createdAt, createdBy);
	}

	public getId(): string {
		return this.id;
	}

	public getName(): string {
		return this.name;
	}

	public getDescription(): string | null {
		return this.description;
	}

	public getIsActive(): boolean {
		return this.isActive;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}

	public getCreatedBy(): string {
		return this.createdBy;
	}

	public setName(name: string): void {
		this.name = name;
	}

	public setDescription(description: string | null): void {
		this.description = description;
	}

	public setIsActive(isActive: boolean): void {
		this.isActive = isActive;
	}
}
