export class AccessTokenIsInvalidException extends Error {
	constructor() {
		super("Access token is invalid.");

		this.name = "AccessTokenIsInvalidException";
	}
}
