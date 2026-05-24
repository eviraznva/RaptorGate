import { beforeAll, describe, test } from "bun:test";
import "../harness";
import {
	clearPortalSession,
	configureLdapIdentityEnforcement,
	configureRadiusIdentityEnforcement,
	ensureProtectedHttpService,
	expectBackendIdentityLoginRejected,
	expectH1ToH2Allowed,
	expectH1ToH2Blocked,
	expectNoBackendIdentitySession,
	expectPortalSession,
	portalLogin,
	portalLogout,
	verifyIdentityProviderFixtures,
} from "./identity-enforcement-helpers";

beforeAll(async () => {
	await verifyIdentityProviderFixtures();
	await ensureProtectedHttpService();
}, { timeout: 120_000 });

describe("Identity Enforcement RADIUS", () => {
	beforeAll(async () => {
		await configureRadiusIdentityEnforcement();
	}, { timeout: 120_000 });

	test("allows users after RADIUS login and blocks again after logout", async () => {
		const rejectedSourceIp = "192.168.10.101";

		await clearPortalSession();
		await expectH1ToH2Blocked();
		await expectBackendIdentityLoginRejected(
			"user",
			"wrong-password",
			rejectedSourceIp,
		);
		await expectNoBackendIdentitySession(rejectedSourceIp);
		await expectH1ToH2Blocked();

		await portalLogin("user", "user123");
		await expectPortalSession("user", "users");
		await expectH1ToH2Allowed();

		await portalLogout();
		await expectH1ToH2Blocked();
	}, { timeout: 60_000 });

	test("keeps authenticated RADIUS guests blocked by identity_group", async () => {
		await clearPortalSession();
		await portalLogin("guest", "guest123");
		await expectPortalSession("guest", "guests");
		await expectH1ToH2Blocked();
		await portalLogout();
	}, { timeout: 45_000 });
});

describe("Identity Enforcement LDAP", () => {
	beforeAll(async () => {
		await configureLdapIdentityEnforcement();
	}, { timeout: 120_000 });

	test("allows users after LDAP login and blocks again after logout", async () => {
		const rejectedSourceIp = "192.168.10.102";

		await clearPortalSession();
		await expectH1ToH2Blocked();
		await expectBackendIdentityLoginRejected(
			"user",
			"wrong-password",
			rejectedSourceIp,
		);
		await expectNoBackendIdentitySession(rejectedSourceIp);
		await expectH1ToH2Blocked();

		await portalLogin("user", "user123");
		await expectPortalSession("user", "users");
		await expectH1ToH2Allowed();

		await portalLogout();
		await expectH1ToH2Blocked();
	}, { timeout: 60_000 });

	test("keeps authenticated LDAP guests blocked by identity_group", async () => {
		await clearPortalSession();
		await portalLogin("guest", "guest123");
		await expectPortalSession("guest", "guests");
		await expectH1ToH2Blocked();
		await portalLogout();
	}, { timeout: 45_000 });
});
