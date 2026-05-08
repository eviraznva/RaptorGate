import { describe, test, beforeAll } from "bun:test";
import "../harness";
import {
	request,
	performCommand,
	resetFirewallState,
	getClient,
	getSnapshotClient,
} from "../harness";
import {
	createDefaultSnapshotBundle,
	DEFAULT_POLICIES,
} from "../harness/fixtures";

function buildPermissiveSnapshot() {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "allow-all-ipv4",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
			},
		],
	});
}

describe("Email Flow", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test("allows email flow with permissive policy", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "email-flow-permissive-checksum",
				isActive: true,
				changesSummary: "permissive policy for email test",
				createdAt: new Date(),
				createdBy: "email-flow-test",
				bundle: buildPermissiveSnapshot(),
			},
		}).run();
	
		await performCommand({
			host: "h2",
			command:
				"swaks --to user2@test.local --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.expectOutput([/250/])
			.run();
	
		await performCommand({
			host: "h1",
			command: "find /var/mail/vmail/test.local/user2 -type f -name '*' | head -1",
		})
			.expectOutput([/\/var\/mail\/vmail\/test\.local\/user2/])
			.run();
	}, {timeout: 20000});

	test("emits smtp session state events", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "email-flow-events-checksum",
				isActive: true,
				changesSummary: "permissive policy for email test",
				createdAt: new Date(),
				createdBy: "email-flow-test",
				bundle: buildPermissiveSnapshot(),
			},
		}).run();

		await performCommand({
			host: "h2",
			command:
				"swaks --to user2@test.local --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.expectOutput([/250/])
			.expectEvents([
				{ kind: "smtpSessionStateChanged", match: { newState: "GreetingReceived" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "Ready" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "EnvelopeOpen" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "ReciepientSet" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "Data(Await354)" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "Data(Collecting)" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "Data(Complete)" } },
				{ kind: "smtpSessionStateChanged", match: { newState: "Ready" } },
			])
			.run();

		await performCommand({
			host: "h1",
			command: "find /var/mail/vmail/test.local/user2 -type f -name '*' | head -1",
		})
			.expectOutput([/\/var\/mail\/vmail\/test\.local\/user2/])
			.run();
	}, {timeout: 20000});
});
