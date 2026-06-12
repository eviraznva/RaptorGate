import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, writeFileSync, readFileSync } from "node:fs";
import { afterEach, afterAll } from "bun:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, "../..");
export const VAGRANT_DIR = path.resolve(REPO_ROOT, "vagrant");

export const KNOWN_HOSTS = ["h1", "h2", "r1", "ldap", "radius", "hvlan10", "hvlan20"] as const;
export type KnownHost = (typeof KNOWN_HOSTS)[number];

export function sshConfigPath(host: KnownHost): string {
	return `/tmp/${host}-ssh-config.txt`;
}

// Backward-compatible aliases for ssh-tunnel.ts (r1-specific)
export const VM_NAME: KnownHost = "r1";
export const SSH_CONFIG_PATH = `/tmp/${VM_NAME}-ssh-config.txt`;

function isVmRunning(vmName: string): Promise<boolean> {
	return new Promise((resolve) => {
		run("vagrant", ["status", vmName], { cwd: VAGRANT_DIR })
			.then(({ stdout, exitCode }) => {
				if (exitCode !== 0) {
					resolve(false);
					return;
				}
				resolve(/^.*running\s+\(libvirt\)/m.test(stdout));
			})
			.catch(() => resolve(false));
	});
}

async function ensureSshConfig(host: KnownHost): Promise<string> {
	const configPath = sshConfigPath(host);
	if (existsSync(configPath)) {
		return configPath;
	}
	const { stdout, exitCode } = await run("vagrant", ["ssh-config", host], {
		cwd: VAGRANT_DIR,
	});

	if (exitCode !== 0 || !stdout.includes("Host ")) {
		throw new Error(`Failed to generate SSH config for ${host}`);
	}
	const configStart = stdout.indexOf("Host ");
	writeFileSync(configPath, stdout.slice(configStart));
	return configPath;
}

function run(
	cmd: string,
	args: string[],
	opts: { cwd?: string; stdin?: "inherit"; timeout?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
	return new Promise((resolve, reject) => {
		const timeout = opts.timeout ?? 30_000;
		const proc = spawn(cmd, args, {
			cwd: opts.cwd,
			shell: false,
			stdio:
				opts.stdin === "inherit"
					? ["inherit", "pipe", "pipe"]
					: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let settled = false;
		const settle = (value: {
			stdout: string;
			stderr: string;
			exitCode: number;
		}) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(value);
		};
		const timer = setTimeout(() => {
			proc.kill("SIGTERM");
			settle({ stdout, stderr, exitCode: 1 });
		}, timeout);
		proc.stdout.on("data", (d) => {
			stdout += d;
		});
		proc.stderr.on("data", (d) => {
			stderr += d;
		});
		proc.on("error", (err) => {
			clearTimeout(timer);
			reject(err);
		});
		proc.on("close", (code) => {
			settle({ stdout, stderr, exitCode: code ?? 1 });
		});
	});
}

export { run };

export async function vagrant_ssh(
	command: string,
): Promise<{ stdout: string; stderr: string }>;
export async function vagrant_ssh(
	host: KnownHost,
	command: string,
): Promise<{ stdout: string; stderr: string }>;
export async function vagrant_ssh(
	hostOrCommand: KnownHost | string,
	command?: string,
): Promise<{ stdout: string; stderr: string }> {
	const host: KnownHost = KNOWN_HOSTS.includes(hostOrCommand as KnownHost)
		? (hostOrCommand as KnownHost)
		: VM_NAME;
	const cmd = command ?? hostOrCommand;
	const { stdout, stderr, exitCode } = await run(
		"vagrant",
		["ssh", host, "-c", cmd],
		{
			cwd: VAGRANT_DIR,
		},
	);
	if (exitCode !== 0) {
		throw new Error(
			`vagrant ssh failed (exit ${exitCode}):\n${stderr || stdout}`,
		);
	}
	return { stdout, stderr };
}

export async function ssh(
	host: KnownHost,
	command: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
	const configPath = await ensureSshConfig(host);

	const { stdout, stderr, exitCode } = await run("ssh", [
		"-F",
		configPath,
		"-o",
		"BatchMode=yes",
		"-o",
		"ConnectTimeout=10",
		host,
		command,
	]);
	if (exitCode !== 0) {
		throw new Error(
			`ssh failed on ${host} (exit ${exitCode}):\n${stderr || stdout}`,
		);
	}
	return { stdout, stderr, exitCode };
}

export type SshWithResultOptions = {
	connectTimeoutSec?: number;
	timeoutMs?: number;
};

export async function sshWithResult(
	host: KnownHost,
	command: string,
	opts: SshWithResultOptions = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
	const configPath = await ensureSshConfig(host);
	const connectTimeoutSec = opts.connectTimeoutSec ?? 10;
	const timeoutMs = opts.timeoutMs ?? 30_000;

	const { stdout, stderr, exitCode } = await run(
		"ssh",
		[
			"-F",
			configPath,
			"-o",
			"BatchMode=yes",
			"-o",
			`ConnectTimeout=${connectTimeoutSec}`,
			host,
			command,
		],
		{ timeout: timeoutMs },
	);
	return { stdout, stderr, exitCode };
}

class SshPolicyCommandBuilder {
	private host: KnownHost;
	private command: string;
	private outputRegexes: RegExp[] | null = null;
	private expectError = false;
	private commandTimeoutMs = 6_000;
	private connectTimeoutSec = 5;
	private maxRetries = 5;

	constructor(host: KnownHost, command: string) {
		this.host = host;
		this.command = command;
	}

	isOk(): this {
		this.expectError = false;
		return this;
	}

	isErr(): this {
		this.expectError = true;
		return this;
	}

	expectOutput(regexes: RegExp[]): this {
		this.outputRegexes = regexes;
		return this;
	}

	commandTimeout(ms: number): this {
		this.commandTimeoutMs = ms;
		return this;
	}

	connectTimeout(sec: number): this {
		this.connectTimeoutSec = sec;
		return this;
	}

	retries(n: number): this {
		this.maxRetries = n;
		return this;
	}

	async run(): Promise<void> {
		let stdout = "";
		let stderr = "";
		let exitCode = 1;
		let aligned = false;

		for (let attempt = 0; attempt < this.maxRetries; attempt++) {
			const result = await sshWithResult(this.host, this.command, {
				timeoutMs: this.commandTimeoutMs,
				connectTimeoutSec: this.connectTimeoutSec,
			});
			stdout = result.stdout;
			stderr = result.stderr;
			exitCode = result.exitCode;
			aligned = (exitCode === 0) === !this.expectError;
			if (aligned) {
				break;
			}
		}

		if (!aligned) {
			throw new Error(
				`SSH policy command did not align after ${this.maxRetries} attempt(s) on ${this.host}: ${this.command} (exit ${exitCode}): ${stderr || stdout}`,
			);
		}

		if (this.outputRegexes) {
			const combined = stdout + stderr;
			const lines = combined.split("\n").filter((l) => l.trim());
			let lineIdx = 0;
			for (const regex of this.outputRegexes) {
				let found = false;
				while (lineIdx < lines.length) {
					const line = lines[lineIdx]!;
					if (regex.test(line)) {
						found = true;
						lineIdx++;
						break;
					}
					lineIdx++;
				}
				if (!found) {
					throw new Error(
						`Output assertion failed: regex ${regex} did not match any line on ${this.host}. Output:\n${combined}`,
					);
				}
			}
		}
	}
}

export function performSshPolicyCommand(
	host: KnownHost,
	command: string,
): SshPolicyCommandBuilder {
	return new SshPolicyCommandBuilder(host, command);
}

// ---------------------------------------------------------------------------
// SshProcessHandle — handle for a single transient SSH process
// ---------------------------------------------------------------------------

export class SshProcessHandle {
	private _proc: ChildProcessWithoutNullStreams;
	private _killed = false;
	private _exitPromise: Promise<number | null>;

	constructor(proc: ChildProcessWithoutNullStreams) {
		this._proc = proc;
		this._exitPromise = new Promise((resolve) => {
			proc.on("close", (code) => resolve(code));
		});
	}

	/** Raw stdout stream (readable). */
	get stdout(): NodeJS.ReadableStream {
		return this._proc.stdout;
	}

	/** Raw stderr stream (readable). */
	get stderr(): NodeJS.ReadableStream {
		return this._proc.stderr;
	}

	/** Collect all stdout into a string (consumes the stream). */
	collectStdout(): Promise<string> {
		return new Promise((resolve) => {
			let data = "";
			this._proc.stdout.on("data", (chunk) => {
				data += chunk;
			});
			this._exitPromise.then(() => resolve(data));
		});
	}

	/** Collect all stderr into a string (consumes the stream). */
	collectStderr(): Promise<string> {
		return new Promise((resolve) => {
			let data = "";
			this._proc.stderr.on("data", (chunk) => {
				data += chunk;
			});
			this._exitPromise.then(() => resolve(data));
		});
	}

	/** Send SIGTERM to the SSH process (kills remote process via connection drop). */
	kill(): void {
		if (this._killed) return;
		this._killed = true;
		this._proc.kill("SIGTERM");
	}

	/** Wait for the process to exit. Returns exit code. */
	waitForExit(): Promise<number | null> {
		return this._exitPromise;
	}

	/** Register automatic cleanup in afterEach/afterAll hooks. */
	defer_cleanup(): this {
		afterEach(() => this.kill());
		afterAll(() => this.kill());
		return this;
	}

	/** Whether the underlying process is still alive. */
	get isActive(): boolean {
		return !this._killed && this._proc.exitCode === null;
	}
}

// ---------------------------------------------------------------------------
// Global tracking for cleanup
// ---------------------------------------------------------------------------

const activeHandles = new Set<SshProcessHandle>();

/** Spawn a one-off SSH command. Returns a handle you can kill/wait on. */
export async function spawnSsh(
	host: KnownHost,
	command: string,
): Promise<SshProcessHandle> {
	const configPath = await ensureSshConfig(host);

	const proc = spawn(
		"ssh",
		[
			"-F",
			configPath,
			"-o",
			"BatchMode=yes",
			"-o",
			"ConnectTimeout=10",
			host,
			command,
		],
		{ shell: false, stdio: ["pipe", "pipe", "pipe"] },
	);

	const handle = new SshProcessHandle(proc);
	activeHandles.add(handle);
	proc.on("close", () => activeHandles.delete(handle));

	return handle;
}

/** Kill all active SSH processes. Use in global teardown. */
export async function closeAllSshProcesses(): Promise<void> {
	for (const handle of activeHandles) {
		handle.kill();
	}
	// Give processes a moment to terminate
	await Promise.all([...activeHandles].map((h) => h.waitForExit()));
	activeHandles.clear();
}

export async function waitForHost(
	host: KnownHost,
	timeoutMs = 30_000,
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		const running = await isVmRunning(host);
		if (running) return;
		await new Promise((r) => setTimeout(r, 2_000));
	}
	throw new Error(`Timed out waiting for ${host} to be running`);
}
