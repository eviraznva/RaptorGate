import { beforeAll, describe, test } from "bun:test";
import "../harness";
import {
	applyIdentityPolicy,
	assertLdapAccepts,
	assertLdapGroup,
	assertRadiusAccepts,
	assertRadiusRejects,
	ensureProtectedHttpService,
	expectH1ToH2Allowed,
	expectH1ToH2Blocked,
	revokeIdentitySession,
	upsertIdentitySession,
	verifyIdentityProviderFixtures,
} from "./identity-enforcement-helpers";

beforeAll(async () => {
	await verifyIdentityProviderFixtures();
	await ensureProtectedHttpService();
}, { timeout: 120_000 });

describe("Identity Enforcement RADIUS", () => {
	beforeAll(async () => {
		await applyIdentityPolicy("radius");
		await revokeIdentitySession();
	}, { timeout: 120_000 });

	test("allows users after RADIUS accept with LDAP users group and blocks again after revoke", async () => {
		await expectH1ToH2Blocked();
		await assertRadiusRejects("user", "wrong-password");
		await expectH1ToH2Blocked();

		await assertRadiusAccepts("user", "user123");
		await assertLdapGroup("user", "users");
		await upsertIdentitySession("user", ["users"]);
		await expectH1ToH2Allowed();

		await revokeIdentitySession();
		await expectH1ToH2Blocked();
	}, { timeout: 60_000 });

	test("keeps authenticated RADIUS guests blocked by identity_group", async () => {
		await revokeIdentitySession();
		await assertRadiusAccepts("guest", "guest123");
		await assertLdapGroup("guest", "guests");
		await upsertIdentitySession("guest", ["guests"]);
		await expectH1ToH2Blocked();
		await revokeIdentitySession();
	}, { timeout: 45_000 });
});

describe("Identity Enforcement LDAP", () => {
	beforeAll(async () => {
		await applyIdentityPolicy("ldap");
		await revokeIdentitySession();
	}, { timeout: 120_000 });

	test("allows users after LDAP accept with users group and blocks again after revoke", async () => {
		await expectH1ToH2Blocked();
		await assertLdapAccepts("user", "user123");
		await assertLdapGroup("user", "users");
		await upsertIdentitySession("user", ["users"]);
		await expectH1ToH2Allowed();

		await revokeIdentitySession();
		await expectH1ToH2Blocked();
	}, { timeout: 60_000 });

	test("keeps authenticated LDAP guests blocked by identity_group", async () => {
		await revokeIdentitySession();
		await assertLdapAccepts("guest", "guest123");
		await assertLdapGroup("guest", "guests");
		await upsertIdentitySession("guest", ["guests"]);
		await expectH1ToH2Blocked();
		await revokeIdentitySession();
	}, { timeout: 45_000 });
});
