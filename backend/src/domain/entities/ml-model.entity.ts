import { SemanticVersion } from "../value-objects/semantic-version.vo.js";
import { Checksum } from "../value-objects/checksum.vo.js";

export class MlModel {
	private constructor(
		private readonly id: string,
		private name: string,
		private version: SemanticVersion,
		private artifactPath: string,
		private checksum: Checksum,
		private readonly createdAt: Date,
		private activatedAt: Date | null,
	) {}

	public static create(
		id: string,
		name: string,
		version: SemanticVersion,
		artifactPath: string,
		checksum: Checksum,
		createdAt: Date,
		activatedAt: Date | null,
	): MlModel {
		return new MlModel(
			id,
			name,
			version,
			artifactPath,
			checksum,
			createdAt,
			activatedAt,
		);
	}

	public getId(): string {
		return this.id;
	}

	public getName(): string {
		return this.name;
	}

	public getVersion(): SemanticVersion {
		return this.version;
	}

	public getArtifactPath(): string {
		return this.artifactPath;
	}

	public getChecksum(): Checksum {
		return this.checksum;
	}

	public getCreatedAt(): Date {
		return this.createdAt;
	}

	public getActivatedAt(): Date | null {
		return this.activatedAt;
	}

	public setActivatedAt(activatedAt: Date): void {
		this.activatedAt = activatedAt;
	}
}
