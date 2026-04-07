import { MacAddressIsInvalidException } from "../exceptions/mac-address-is-invalid.exception.js";

export class MacAddress {
	private readonly value: string;

	private constructor(mac: string) {
		this.value = mac;
	}

	public static create(mac: string): MacAddress {
		if (!this.isValid(mac)) throw new MacAddressIsInvalidException(mac);

		return new MacAddress(mac);
	}

	private static isValid(mac: string): boolean {
		const macRegex =
			/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$/;
		return macRegex.test(mac);
	}

	public get getValue(): string {
		return this.value;
	}
}
