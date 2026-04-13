export class RegexPatternIsInvalidException extends Error {
	constructor(pattern: string) {
		super(`Invalid regex pattern: ${pattern}`);

		this.name = "RegexPatternIsInvalidException";
	}
}
