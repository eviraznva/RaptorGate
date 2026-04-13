export class RuleChangeLog {
	private constructor(
		private readonly id: string,
		private readonly ruleId: string,
		private modifiedAt: Date,
		private content: string,
	) {}

	public static create(
		id: string,
		ruleId: string,
		modifiedAt: Date,
		content: string,
	): RuleChangeLog {
		return new RuleChangeLog(id, ruleId, modifiedAt, content);
	}

	public getId(): string {
		return this.id;
	}

	public getRuleId(): string {
		return this.ruleId;
	}

	public getModifiedAt(): Date {
		return this.modifiedAt;
	}

	public getContent(): string {
		return this.content;
	}
}
