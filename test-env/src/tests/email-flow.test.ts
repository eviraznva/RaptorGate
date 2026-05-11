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
import type { SmtpMatchers } from "../generated/config/config_models";
import { SmtpMatchAction } from "../generated/config/config_models";

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

function buildSmtpSnapshot(smtpMatchers: SmtpMatchers) {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "smtp-test",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
				smtpMatchers,
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
	}, {timeout: 20_000});

	test("allows sender domain from allow-list and blocks others", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "email-flow-sender-allow",
				isActive: true,
				changesSummary: "sender allow-list policy",
				createdAt: new Date(),
				createdBy: "email-flow-test",
				bundle: buildSmtpSnapshot({
					sender: [{ regex: ".*@test\\.local", onMatch: SmtpMatchAction.SMTP_MATCH_ACTION_ALLOW }],
					recipient: [],
					message: [],
				}),
			},
		}).run();

		// Should allow user1@test.local
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.expectOutput([/250/])
			.run();

		// Should block user1@test.remote
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.remote --server 192.168.10.10 --body 'Test email from h2'",
		})
			.isErr()
			.run();
	}, {timeout: 20_000});

	test("allows recipient domain from allow-list and blocks mixed recipients", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "email-flow-recipient-allow",
				isActive: true,
				changesSummary: "recipient allow-list policy",
				createdAt: new Date(),
				createdBy: "email-flow-test",
				bundle: buildSmtpSnapshot({
					sender: [],
					recipient: [{ regex: ".*@test\\.local", onMatch: SmtpMatchAction.SMTP_MATCH_ACTION_ALLOW }],
					message: [],
				}),
			},
		}).run();
	
		// Should allow user1@test.local
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.expectOutput([/250/])
			.run();
	
		// Should block if recipient is test.remote
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.remote --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.isErr()
			.run();
	
		// Should block mixed recipients (one allowed, one blocked)
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local,user1@test.remote --from user1@test.local --server 192.168.10.10 --body 'Test email from h2'",
		})
			.isErr()
			.run();
	}, {timeout: 30_000});
	
	test("message content allow and deny filters with dotall", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "email-flow-message-allow-deny",
				isActive: true,
				changesSummary: "message allow/deny policy",
				createdAt: new Date(),
				createdBy: "email-flow-test",
				bundle: buildSmtpSnapshot({
					sender: [],
					recipient: [],
					message: [
						{ regex: "(?s).*hello.*", onMatch: SmtpMatchAction.SMTP_MATCH_ACTION_ALLOW },
						{ regex: "(?s).*world.*", onMatch: SmtpMatchAction.SMTP_MATCH_ACTION_DENY },
					],
				}),
			},
		}).run();
	
		// Should allow hello without world
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.local --server 192.168.10.10 --body 'hello there'",
		})
			.expectOutput([/250/])
			.run();
	
		// Should block if world is present (even with hello)
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.local --server 192.168.10.10 --body 'hello world'",
		})
			.isErr()
			.run();
	
		// Should block if neither is present (since allow-list requires hello)
		await performCommand({
			host: "h2",
			command:
				"swaks --to user1@test.local --from user1@test.local --server 192.168.10.10 --body 'testing alone'",
		})
			.isErr()
			.run();
	}, {timeout: 30_000});
});
