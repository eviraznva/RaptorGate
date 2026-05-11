import { io, type Socket } from "socket.io-client";
import type {
  TcpSessionEndpoint,
  TcpTrackedSession,
  TcpTrackedSessionDestroyReason,
  TcpTrackedSessionDirection,
  TcpTrackedSessionInterfaces,
  TcpTrackedSessionLifecycle,
  TcpTrackedSessionNatInfo,
  TcpTrackedSessionState,
} from "../types/sessions/TcpSession";

export type TcpSessionsPayload = {
  tcpSessions: TcpTrackedSession[];
};

type UnknownRecord = Record<string, unknown>;

const TCP_SESSION_STATES: readonly TcpTrackedSessionState[] = [
  "unspecified",
  "syn_sent",
  "syn_ack_received",
  "established",
  "fin_sent",
  "ack_sent",
  "ack_fin_sent",
  "time_wait",
  "closed",
  "unknown",
];
const TCP_SESSION_LIFECYCLES: readonly TcpTrackedSessionLifecycle[] = [
  "active",
  "destroyed",
  "unspecified",
];
const TCP_SESSION_DIRECTIONS: readonly TcpTrackedSessionDirection[] = [
  "original",
  "reply",
  "unspecified",
];
const TCP_SESSION_DESTROY_REASONS: readonly TcpTrackedSessionDestroyReason[] = [
  "timeout",
  "manual",
  "replaced",
  "shutdown",
  "unspecified",
];

function resolveSessionsUrl(): { url: string; path: string } {
  const envUrl = import.meta.env.RAPTOR_GATE_METRICS_WS_URL;
  if (envUrl) {
    const u = new URL(envUrl);
    return {
      url: `${u.origin}/sessions`,
      path: `${u.pathname}/socket.io`.replace(/\/+/g, "/"),
    };
  }
  return {
    url: `${window.location.origin}/sessions`,
    path: "/sessions/socket.io",
  };
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null;
}

function primitiveNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }

  return null;
}

function toNumber(value: unknown, fallback = 0): number {
  const primitive = primitiveNumber(value);
  if (primitive !== null) return primitive;
  if (!isRecord(value)) return fallback;

  const toNumberMethod = value.toNumber;
  if (typeof toNumberMethod === "function") {
    try {
      const converted = primitiveNumber(toNumberMethod.call(value));
      if (converted !== null) return converted;
    } catch {
      return fallback;
    }
  }

  if ("low" in value || "high" in value) {
    const low = toNumber(value.low, Number.NaN);
    const high = toNumber(value.high, 0);
    const converted = high * 4_294_967_296 + (low >>> 0);
    if (Number.isFinite(converted)) return converted;
  }

  for (const key of ["value", "number", "int", "integer"]) {
    const converted = primitiveNumber(value[key]);
    if (converted !== null) return converted;
  }

  const toStringMethod = value.toString;
  if (
    typeof toStringMethod === "function" &&
    toStringMethod !== Object.prototype.toString
  ) {
    try {
      const converted = primitiveNumber(toStringMethod.call(value));
      if (converted !== null) return converted;
    } catch {
      return fallback;
    }
  }

  return fallback;
}

function toStringValue(value: unknown, fallback: string): string {
  if (typeof value === "string") return value;
  if (
    typeof value === "number" ||
    typeof value === "bigint" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }
  if (!isRecord(value)) return fallback;

  for (const key of ["value", "name", "id"]) {
    const nested = value[key];
    if (
      typeof nested === "string" ||
      typeof nested === "number" ||
      typeof nested === "bigint" ||
      typeof nested === "boolean"
    ) {
      return String(nested);
    }
  }

  return fallback;
}

function toOptionalString(value: unknown): string | undefined {
  const normalized = toStringValue(value, "");
  return normalized.length > 0 ? normalized : undefined;
}

function toBoolean(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "true" || normalized === "1" || normalized === "yes";
  }

  return false;
}

function toEnumValue<T extends string>(
  value: unknown,
  allowed: readonly T[],
  fallback: T,
): T {
  if (typeof value !== "string") return fallback;
  return allowed.includes(value as T) ? (value as T) : fallback;
}

function normalizeEndpoint(value: unknown): TcpSessionEndpoint {
  const endpoint = isRecord(value) ? value : {};

  return {
    ip: toStringValue(endpoint.ip, ""),
    port: toNumber(endpoint.port),
  };
}

function normalizeInterfaces(value: unknown): TcpTrackedSessionInterfaces {
  const interfaces = isRecord(value) ? value : {};

  return {
    originalIngress: toStringValue(interfaces.originalIngress, ""),
    originalEgress: toStringValue(interfaces.originalEgress, ""),
    replyIngress: toStringValue(interfaces.replyIngress, ""),
    replyEgress: toStringValue(interfaces.replyEgress, ""),
  };
}

function normalizeNatInfo(value: unknown): TcpTrackedSessionNatInfo | undefined {
  if (!isRecord(value)) return undefined;

  const natInfo: TcpTrackedSessionNatInfo = {
    ruleId: toStringValue(value.ruleId, ""),
    bindingId: toStringValue(value.bindingId, ""),
    hasSrcNat: toBoolean(value.hasSrcNat),
    hasDstNat: toBoolean(value.hasDstNat),
  };
  const allocatedIp = toOptionalString(value.allocatedIp);
  const srcManipIp = toOptionalString(value.srcManipIp);
  const dstManipIp = toOptionalString(value.dstManipIp);

  if (allocatedIp !== undefined) natInfo.allocatedIp = allocatedIp;
  if (srcManipIp !== undefined) natInfo.srcManipIp = srcManipIp;
  if (dstManipIp !== undefined) natInfo.dstManipIp = dstManipIp;
  if (value.allocatedPort !== undefined) {
    natInfo.allocatedPort = toNumber(value.allocatedPort);
  }
  if (value.srcManipPort !== undefined) {
    natInfo.srcManipPort = toNumber(value.srcManipPort);
  }
  if (value.dstManipPort !== undefined) {
    natInfo.dstManipPort = toNumber(value.dstManipPort);
  }

  return natInfo;
}

function normalizeTcpTrackedSession(value: unknown): TcpTrackedSession {
  const session = isRecord(value) ? value : {};

  return {
    id: toStringValue(session.id, ""),
    endpointA: normalizeEndpoint(session.endpointA),
    endpointB: normalizeEndpoint(session.endpointB),
    state: toEnumValue(session.state, TCP_SESSION_STATES, "unknown"),
    lifecycle: toEnumValue(
      session.lifecycle,
      TCP_SESSION_LIFECYCLES,
      "unspecified",
    ),
    lastDirection: toEnumValue(
      session.lastDirection,
      TCP_SESSION_DIRECTIONS,
      "unspecified",
    ),
    interfaces: normalizeInterfaces(session.interfaces),
    mark: toNumber(session.mark),
    statusBits: toNumber(session.statusBits),
    bytesOriginal: toNumber(session.bytesOriginal),
    bytesReply: toNumber(session.bytesReply),
    packetsOriginal: toNumber(session.packetsOriginal),
    packetsReply: toNumber(session.packetsReply),
    createdAt: toStringValue(session.createdAt, ""),
    lastSeenAt: toStringValue(session.lastSeenAt, ""),
    expiresAt: toStringValue(session.expiresAt, ""),
    destroyedAt: toOptionalString(session.destroyedAt),
    destroyReason: toEnumValue(
      session.destroyReason,
      TCP_SESSION_DESTROY_REASONS,
      "unspecified",
    ),
    natInfo: normalizeNatInfo(session.natInfo),
  };
}

export function normalizeTcpSessionsPayload(
  payload: TcpSessionsPayload,
): TcpSessionsPayload {
  return {
    tcpSessions: payload.tcpSessions.map((session) =>
      normalizeTcpTrackedSession(session),
    ),
  };
}

export function createSessionsSocket(accessToken: string): Socket {
  const { url, path } = resolveSessionsUrl();

  return io(url, {
    auth: { token: accessToken },
    autoConnect: false,
    path,
    transports: ["websocket"],
    withCredentials: true,
  });
}

export function isTcpSessionsPayload(value: unknown): value is TcpSessionsPayload {
  if (!value || typeof value !== "object") return false;

  const payload = value as Partial<TcpSessionsPayload>;
  return Array.isArray(payload.tcpSessions);
}
