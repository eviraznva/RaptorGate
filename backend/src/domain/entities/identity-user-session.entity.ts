import { MacAddress } from "../value-objects/mac-address.vo.js";
import { IpAddress } from "../value-objects/ip-address.vo.js";

export class IdentityUserSession {
	private constructor(
		private readonly id: string,
		private radiusUsername: string,
		private readonly macAddress: MacAddress,
		private ipAddress: IpAddress,
		private nasIp: IpAddress,
		private calledStationId: string,
		private authenticatedAt: Date,
		private expiresAt: Date,
		private syncedFromRedisAt: Date | null,
	) {}

	public static create(
		id: string,
		radiusUsername: string,
		macAddress: MacAddress,
		ipAddress: IpAddress,
		nasIp: IpAddress,
		calledStationId: string,
		authenticatedAt: Date,
		expiresAt: Date,
		syncedFromRedisAt: Date | null,
	): IdentityUserSession {
		return new IdentityUserSession(
			id,
			radiusUsername,
			macAddress,
			ipAddress,
			nasIp,
			calledStationId,
			authenticatedAt,
			expiresAt,
			syncedFromRedisAt,
		);
	}

	public getId(): string {
		return this.id;
	}

	public getRadiusUsername(): string {
		return this.radiusUsername;
	}

	public getMacAddress(): MacAddress {
		return this.macAddress;
	}

	public getIpAddress(): IpAddress {
		return this.ipAddress;
	}

	public getNasIp(): IpAddress {
		return this.nasIp;
	}

	public getCalledStationId(): string {
		return this.calledStationId;
	}

	public getAuthenticatedAt(): Date {
		return this.authenticatedAt;
	}

	public getExpiresAt(): Date {
		return this.expiresAt;
	}

	public getSyncedFromRedisAt(): Date | null {
		return this.syncedFromRedisAt;
	}

	public setSyncedFromRedisAt(syncedFromRedisAt: Date): void {
		this.syncedFromRedisAt = syncedFromRedisAt;
	}
}
