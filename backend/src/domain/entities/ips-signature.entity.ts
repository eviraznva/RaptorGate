import { SignatureCategory } from "../value-objects/signature-category.vo.js";
import { RegexPattern } from "../value-objects/regex-pattern.vo.js";

export type SignatureSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export class IpsSignature {
	private constructor(
		private readonly id: string,
		private name: string,
		private category: SignatureCategory,
		private pattern: RegexPattern,
		private severity: SignatureSeverity,
		private isActive: boolean,
		private readonly createdAt: Date,
		private updatedAt: Date,
	) {}

	public static create(
		id: string,
		name: string,
		category: SignatureCategory,
		pattern: RegexPattern,
		severity: SignatureSeverity,
		isActive: boolean,
		createdAt: Date,
		updatedAt: Date,
	): IpsSignature {
		return new IpsSignature(
			id,
			name,
			category,
			pattern,
			severity,
			isActive,
			createdAt,
			updatedAt,
		);
	}

	public getId(): string {
		return this.id;
	}

	public getName(): string {
		return this.name;
	}

	public getCategory(): SignatureCategory {
		return this.category;
	}

	public getPattern(): RegexPattern {
		return this.pattern;
	}

	public getSeverity(): SignatureSeverity {
		return this.severity;
	}

	public getIsActive(): boolean {
		return this.isActive;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}

	public getUpdatedAt(): Date {
		return this.updatedAt;
	}
}
