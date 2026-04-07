export class MacAddressIsInvalidException extends Error {
	constructor(macAddress: string) {
		super(`The MAC address "${macAddress}" is invalid.`);
		this.name = "MacAddressIsInvalidException";
	}
}
