import { PortIsInvalidException } from "../exceptions/port-is-invalid.exception.js";

export class Port {
	private readonly value: number;

	private constructor(port: number) {
		this.value = port;
	}

	public static create(port: number): Port {
		if (!this.isValid(port)) throw new PortIsInvalidException(port);
		return new Port(port);
	}

	private static isValid(port: number): boolean {
		return Number.isInteger(port) && port >= 1 && port <= 65535;
	}

	public get getValue(): number {
		return this.value;
	}

	public isWellKnown(): boolean {
		return this.value >= 1 && this.value <= 1023;
	}

	public isRegistered(): boolean {
		return this.value >= 1024 && this.value <= 49151;
	}

	public isDynamic(): boolean {
		return this.value >= 49152 && this.value <= 65535;
	}
}
