export class UserGroupMember {
	private constructor(
		private readonly id: string,
		private readonly groupId: string,
		private readonly identityUserId: string,
		private joinedAt: Date,
	) {}

	public static create(
		id: string,
		groupId: string,
		identityUserId: string,
		joinedAt: Date,
	): UserGroupMember {
		return new UserGroupMember(id, groupId, identityUserId, joinedAt);
	}

	public getId(): string {
		return this.id;
	}

	public getGroupId(): string {
		return this.groupId;
	}

	public getIdentityUserId(): string {
		return this.identityUserId;
	}

	public getJoinedAt(): Date {
		return this.joinedAt;
	}
}
