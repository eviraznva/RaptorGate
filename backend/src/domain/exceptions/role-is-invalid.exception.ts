export class RoleIsInvalidException extends Error {
	constructor() {
		super("One or more provided roles are invalid.");

		this.name = "RoleIsInvalidException";
	}
}
