import { IpAddress } from "../value-objects/ip-address.vo.js";

export class NetworkSessionHistory {
	private constructor(
		private readonly id: string,
		private sourceIp: IpAddress,
		private destinationIp: IpAddress,
		private application: string,
		private domain: string,
		private bytesSent: bigint,
		private bytesReceived: bigint,
		private packetsTotal: bigint,
		private startedAt: Date,
		private endedAt: Date | null,
	) {}

	public static create(
		id: string,
		sourceIp: IpAddress,
		destinationIp: IpAddress,
		application: string,
		domain: string,
		bytesSent: bigint,
		bytesReceived: bigint,
		packetsTotal: bigint,
		startedAt: Date,
		endedAt: Date | null,
	): NetworkSessionHistory {
		return new NetworkSessionHistory(
			id,
			sourceIp,
			destinationIp,
			application,
			domain,
			bytesSent,
			bytesReceived,
			packetsTotal,
			startedAt,
			endedAt,
		);
	}

	public getId(): string {
		return this.id;
	}

	public getSourceIp(): IpAddress {
		return this.sourceIp;
	}

	public getDestinationIp(): IpAddress {
		return this.destinationIp;
	}

	public getApplication(): string {
		return this.application;
	}

	public getDomain(): string {
		return this.domain;
	}

	public getBytesSent(): bigint {
		return this.bytesSent;
	}

	public getBytesReceived(): bigint {
		return this.bytesReceived;
	}

	public getPacketsTotal(): bigint {
		return this.packetsTotal;
	}

	public getStartedAt(): Date {
		return this.startedAt;
	}

	public getEndedAt(): Date | null {
		return this.endedAt;
	}

	public endSession(endedAt: Date): void {
		this.endedAt = endedAt;
	}
}
