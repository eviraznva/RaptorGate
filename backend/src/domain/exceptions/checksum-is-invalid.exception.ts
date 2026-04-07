export class ChecksumIsInvalidException extends Error {
	constructor(checksum: string) {
		super(
			`Invalid checksum format: ${checksum}. Must be a 64-character hexadecimal string.`,
		);

		this.name = "ChecksumIsInvalidException";
	}
}
