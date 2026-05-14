import { describe, test, expect } from "bun:test";
import { EventCollector } from "../harness/event-collector";

describe("EventCollector tcpSessionSubstateChanged", () => {
	test("matches ordered subsequence on payload fields", async () => {
		const c = new EventCollector();
		c.setFence(0);
		const t = 1_900_000_000;
		const mk = (prev: string, next: string, dir: string) => ({
			emittedAt: { seconds: t, nanos: 0 },
			kind: {
				item: "tcpSessionSubstateChanged",
				tcpSessionSubstateChanged: {
					flowId: "7",
					packetDirection: dir,
					previousState: prev,
					newState: next,
					src: { ip: "192.168.10.1", port: 40000 },
					dst: { ip: "192.168.20.10", port: 12345 },
				},
			},
		});
		c.push(
			mk(
				"TCP_SESSION_STATE_SYN_SENT",
				"TCP_SESSION_STATE_SYN_RECV",
				"CONNTRACK_PACKET_DIRECTION_REPLY",
			),
		);
		c.push(
			mk(
				"TCP_SESSION_STATE_SYN_RECV",
				"TCP_SESSION_STATE_ESTABLISHED",
				"CONNTRACK_PACKET_DIRECTION_ORIGINAL",
			),
		);
		const r = await c.waitForSubsequence([
			{
				kind: "tcpSessionSubstateChanged",
				match: {
					newState: "TCP_SESSION_STATE_SYN_RECV",
					previousState: "TCP_SESSION_STATE_SYN_SENT",
					packetDirection: "CONNTRACK_PACKET_DIRECTION_REPLY",
				},
			},
			{
				kind: "tcpSessionSubstateChanged",
				match: { newState: "TCP_SESSION_STATE_ESTABLISHED" },
			},
		]);
		expect(r.matched).toBe(true);
	});
});
