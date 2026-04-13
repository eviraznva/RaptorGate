export class UserNotFoundException extends Error {
	constructor(userId: string) {
		super(`User with ID ${userId} not found.`);

		this.name = "UserNotFoundException";
	}
}
