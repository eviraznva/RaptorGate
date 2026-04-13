export class InvalidCredentialsException extends Error {
	constructor() {
		super("Invalid email or password.");
		this.name = "InvalidCredentialsException";
	}
}
