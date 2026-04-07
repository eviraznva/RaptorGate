import { promises as fs } from "node:fs";
import { dirname } from "node:path";

export class FileStore {
	async readJson<T>(filePath: string): Promise<T> {
		const raw = await fs.readFile(filePath, "utf8");
		return JSON.parse(raw) as T;
	}

	async readJsonOrDefault<T>(filePath: string, fallback: T): Promise<T> {
		try {
			return await this.readJson<T>(filePath);
		} catch (error: unknown) {
			if (
				typeof error === "object" &&
				error !== null &&
				"code" in error &&
				(error as { code?: string }).code === "ENOENT"
			) {
				return fallback;
			}

			throw error;
		}
	}

	async writeJsonAtomic(filePath: string, data: unknown): Promise<void> {
		const tmpPath = `${filePath}.tmp`;
		const dir = dirname(filePath);
		const payload = JSON.stringify(data, null, 2) + "\n";

		await fs.mkdir(dir, { recursive: true });

		const fh = await fs.open(tmpPath, "w", 0o600);
		try {
			await fh.writeFile(payload, "utf8");
			await fh.sync();
		} finally {
			await fh.close();
		}

		await fs.rename(tmpPath, filePath);

		const dh = await fs.open(dir, "r");
		try {
			await dh.sync();
		} finally {
			await dh.close();
		}
	}
}
