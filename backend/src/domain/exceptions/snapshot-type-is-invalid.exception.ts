export class SnapshotTypeIsInvalidException extends Error {
	constructor(snapshotType: string) {
		super(
			`Snapshot type '${snapshotType}' is invalid. Valid types are 'ZONE' and 'POLICY'.`,
		);

		this.name = "SnapshotTypeIsInvalidException";
	}
}
