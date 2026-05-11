import type { ApiResponse, ApiSuccess } from "../types/ApiResponse";
import type {
  PortalLoginRequest,
  PortalLoginSuccess,
  PortalLogoutResult,
  PortalSession,
} from "../types/portal/PortalSession";

// Portal MVP (Issue 7) korzysta z relatywnego /api, bo nginx vhost na
// interfejsie h1 proxuje /api/identity/* do backendu. Nie uzywamy JWT
// admina; sourceIp na backendzie pochodzi z polaczenia, nie z body.
const PORTAL_API_BASE = "/api/identity";

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${PORTAL_API_BASE}${path}`, {
    method: "POST",
    credentials: "include",
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });

  const payload = (await res.json().catch(() => null)) as ApiResponse<T> | null;
  if (!payload) {
    throw new PortalApiError(res.status, "Empty response from portal API");
  }
  if (!res.ok || payload.statusCode >= 400) {
    const message =
      "message" in payload && payload.message
        ? payload.message
        : "Portal request failed";
    throw new PortalApiError(payload.statusCode ?? res.status, message);
  }
  return (payload as ApiSuccess<T>).data;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${PORTAL_API_BASE}${path}`, {
    method: "GET",
    credentials: "include",
  });

  const payload = (await res.json().catch(() => null)) as ApiResponse<T> | null;
  if (!payload) {
    throw new PortalApiError(res.status, "Empty response from portal API");
  }
  if (!res.ok || payload.statusCode >= 400) {
    const message =
      "message" in payload && payload.message
        ? payload.message
        : "Portal request failed";
    throw new PortalApiError(payload.statusCode ?? res.status, message);
  }
  return (payload as ApiSuccess<T>).data;
}

export class PortalApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "PortalApiError";
    this.status = status;
  }
}

export function fetchPortalSession(): Promise<PortalSession> {
  return getJson<PortalSession>("/session");
}

export function postPortalLogin(
  request: PortalLoginRequest,
): Promise<PortalLoginSuccess> {
  return postJson<PortalLoginSuccess>("/login", request);
}

export function postPortalLogout(): Promise<PortalLogoutResult> {
  return postJson<PortalLogoutResult>("/logout");
}
