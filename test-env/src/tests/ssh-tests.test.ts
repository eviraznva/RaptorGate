import { beforeAll, describe, test } from "bun:test";
import "../harness";
import {
	getClient,
	getSnapshotClient,
	performCommand,
	resetFirewallState,
} from "../harness";

describe("SSH", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test("h1 can start an ssh session to h2", async () => {
		await performCommand({
			host: "h1",
			command:
				"ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null vagrant@192.168.20.10 hostname",
		})
			.expectOutput([/^h2$/])
			.run();
	});
});
