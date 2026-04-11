import { SnapshotTypeIsInvalidException } from "../exceptions/snapshot-type-is-invalid.exception.js";

export type SnapshotTypeType = "manual_import" | "rollback_point" | "auto_save";

export class SnapshotType {
	private static readonly ALLOWED_VALUES: SnapshotTypeType[] = [
		"manual_import",
		"rollback_point",
		"auto_save",
	];

	private readonly value: SnapshotTypeType;

	private constructor(type: SnapshotTypeType) {
		this.value = type;
	}

	public static create(type: string): SnapshotType {
		if (!this.isValidType(type)) {
			throw new SnapshotTypeIsInvalidException(type);
		}

		return new SnapshotType(type as SnapshotTypeType);
	}

	private static isValidType(type: string): boolean {
		return SnapshotType.ALLOWED_VALUES.includes(type as SnapshotTypeType);
	}

	public getValue(): SnapshotTypeType {
		return this.value;
	}

	public isManualImport(): boolean {
		return this.value === "manual_import";
	}

	public isRollbackPoint(): boolean {
		return this.value === "rollback_point";
	}

	public isAutoSave(): boolean {
		return this.value === "auto_save";
	}
}
