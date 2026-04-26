import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { LineArrow } from "../components/lineArrow/LineArrow";
import {
  fetchPortalSession,
  PortalApiError,
  postPortalLogin,
  postPortalLogout,
} from "../services/portal";
import type { PortalSession } from "../types/portal/PortalSession";

type Status =
  | { kind: "loading" }
  | { kind: "anonymous"; reason?: "expired" | "logged-out" | "rejected" | "unavailable"; message?: string }
  | { kind: "authenticated"; session: PortalSession; justLoggedIn: boolean }
  | { kind: "submitting"; mode: "login" | "logout" };

function formatTime(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

// Captive portal MVP (Issue 7): jedna strona, stan zalezy od backendowego
// /identity/session. Stany: loading, anonymous (z opcjonalnym powodem),
// authenticated (z flaga "wlasnie zalogowany"), submitting.
export default function PortalPage() {
  const [status, setStatus] = useState<Status>({ kind: "loading" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const refresh = useCallback(
    async (reason?: "expired" | "logged-out" | "rejected" | "unavailable") => {
      try {
        const session = await fetchPortalSession();
        if (session.authenticated) {
          setStatus({ kind: "authenticated", session, justLoggedIn: false });
          return;
        }
        setStatus({ kind: "anonymous", reason });
      } catch (err) {
        const message =
          err instanceof PortalApiError ? err.message : "Portal unreachable";
        setStatus({ kind: "anonymous", reason: "unavailable", message });
      }
    },
    [],
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (status.kind !== "authenticated") return;
    const expiresAt = status.session.expiresAt
      ? new Date(status.session.expiresAt).getTime()
      : 0;
    const remainingMs = expiresAt - Date.now();
    if (remainingMs <= 0) {
      setStatus({ kind: "anonymous", reason: "expired" });
      return;
    }
    const timer = setTimeout(() => {
      setStatus({ kind: "anonymous", reason: "expired" });
    }, remainingMs);
    return () => clearTimeout(timer);
  }, [status]);

  const handleLogin = async () => {
    if (!username || !password) return;
    setStatus({ kind: "submitting", mode: "login" });
    try {
      const result = await postPortalLogin({ username, password });
      setUsername("");
      setPassword("");
      const session: PortalSession = {
        authenticated: true,
        sourceIp: result.sourceIp,
        sessionId: result.sessionId,
        username: result.username,
        authenticatedAt: result.authenticatedAt,
        expiresAt: result.expiresAt,
      };
      setStatus({ kind: "authenticated", session, justLoggedIn: true });
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        setStatus({ kind: "anonymous", reason: "rejected", message: err.message });
        return;
      }
      const message =
        err instanceof PortalApiError ? err.message : "Portal unreachable";
      setStatus({ kind: "anonymous", reason: "unavailable", message });
    }
  };

  const handleLogout = async () => {
    setStatus({ kind: "submitting", mode: "logout" });
    try {
      await postPortalLogout();
      setStatus({ kind: "anonymous", reason: "logged-out" });
    } catch (err) {
      const message =
        err instanceof PortalApiError ? err.message : "Portal unreachable";
      await refresh("unavailable");
      setStatus((prev) =>
        prev.kind === "anonymous" ? { ...prev, message } : prev,
      );
    }
  };

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-xl"
        >
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <LineArrow width={250} className="w-full" />
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <div className="text-center mb-10">
            <h1 className="text-4xl tracking-[0.3em] font-light">RAPTORGATE</h1>
            <p className="text-[#8a8a8a] text-sm mt-3">
              Captive portal — identity session for this device
            </p>
          </div>

          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {status.kind === "loading" && <PortalCard><Spinner label="Checking session..." /></PortalCard>}

          {status.kind === "submitting" && (
            <PortalCard>
              <Spinner
                label={status.mode === "login" ? "Authenticating..." : "Logging out..."}
              />
            </PortalCard>
          )}

          {status.kind === "anonymous" && (
            <PortalCard>
              <PortalBanner status={status} />
              <div className="space-y-5">
                <div>
                  <div className="text-xs text-[#8a8a8a] mb-2">Username</div>
                  <input
                    type="text"
                    value={username}
                    autoComplete="username"
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                  />
                </div>
                <div>
                  <div className="text-xs text-[#8a8a8a] mb-2">Password</div>
                  <input
                    type="password"
                    value={password}
                    autoComplete="current-password"
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void handleLogin();
                    }}
                    className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => void handleLogin()}
                  className="w-full bg-[#06b6d4] text-black py-3 tracking-widest font-medium hover:bg-[#0891b2] transition"
                >
                  Sign in
                </button>
              </div>
            </PortalCard>
          )}

          {status.kind === "authenticated" && (
            <PortalCard>
              <div className="mb-5">
                {status.justLoggedIn ? (
                  <div className="border border-[#06b6d4]/40 bg-[#06b6d4]/10 text-[#a7f3f8] text-sm px-4 py-3">
                    Authenticated. Traffic from this device is now allowed.
                  </div>
                ) : (
                  <div className="border border-[#262626] text-[#8a8a8a] text-sm px-4 py-3">
                    You already have an active session on this device.
                  </div>
                )}
              </div>

              <dl className="text-sm space-y-2 mb-6">
                <PortalRow label="Username" value={status.session.username ?? "—"} />
                <PortalRow label="Source IP" value={status.session.sourceIp} />
                <PortalRow
                  label="Authenticated at"
                  value={formatTime(status.session.authenticatedAt)}
                />
                <PortalRow
                  label="Expires at"
                  value={formatTime(status.session.expiresAt)}
                />
                {status.session.groups && status.session.groups.length > 0 && (
                  <PortalRow
                    label="Groups"
                    value={status.session.groups.join(", ")}
                  />
                )}
              </dl>

              <button
                type="button"
                onClick={() => void handleLogout()}
                className="w-full border border-[#ef4444] text-[#ef4444] py-3 tracking-widest font-medium hover:bg-[#ef4444]/10 transition"
              >
                Log out
              </button>
            </PortalCard>
          )}

          <div className="mt-6 text-center text-xs text-[#4a4a4a]">
            Identity session is bound to this device's IP.
          </div>
        </motion.div>
      </div>
    </div>
  );
}

function PortalCard({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="bg-[#161616] border border-[#262626] p-6"
    >
      {children}
    </motion.div>
  );
}

function PortalRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-[#1f1f1f] py-2">
      <dt className="text-[#8a8a8a] text-xs tracking-wide uppercase">{label}</dt>
      <dd className="text-[#f5f5f5] text-right break-all">{value}</dd>
    </div>
  );
}

function Spinner({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-4 text-[#8a8a8a]">
      <span className="h-3 w-3 border border-[#06b6d4] border-t-transparent rounded-full animate-spin" />
      <span className="text-sm tracking-wide">{label}</span>
    </div>
  );
}

function PortalBanner({
  status,
}: {
  status: Extract<Status, { kind: "anonymous" }>;
}) {
  if (!status.reason) return null;
  const map: Record<NonNullable<Status & { kind: "anonymous" }>["reason"] & string, { tone: string; text: string }> = {
    expired: {
      tone: "border-[#f59e0b]/40 bg-[#f59e0b]/10 text-[#fde68a]",
      text: "Your previous session expired. Sign in again to restore access.",
    },
    "logged-out": {
      tone: "border-[#262626] text-[#8a8a8a]",
      text: "Logged out. Network access for this device is blocked until you sign in.",
    },
    rejected: {
      tone: "border-[#ef4444]/40 bg-[#ef4444]/10 text-[#fecaca]",
      text: status.message ?? "Invalid credentials.",
    },
    unavailable: {
      tone: "border-[#ef4444]/40 bg-[#ef4444]/10 text-[#fecaca]",
      text: status.message ?? "Portal API unreachable. Try again in a moment.",
    },
  };
  const entry = map[status.reason];
  if (!entry) return null;
  return (
    <div className={`mb-5 border text-sm px-4 py-3 ${entry.tone}`}>
      {entry.text}
    </div>
  );
}
