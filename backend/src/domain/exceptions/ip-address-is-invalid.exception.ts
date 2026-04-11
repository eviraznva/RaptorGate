export class IpAddressIsInvalidException extends Error {
	constructor(ipAddress: string) {
		super(`The IP address "${ipAddress}" is invalid.`);
		this.name = "IpAddressIsInvalidException";
	}
}
