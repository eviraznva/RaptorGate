import {
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { Socket } from "socket.io-client";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import ConnectionInspector from "../components/connections/ConnectionInspector";
import ConnectionsFooter from "../components/connections/ConnectionsFooter";
import ConnectionsPageHeader from "../components/connections/ConnectionsPageHeader";
import ConnectionStats from "../components/connections/ConnectionStats";
import ConnectionsStatusBar from "../components/connections/ConnectionsStatusBar";
import ConnectionsTable from "../components/connections/ConnectionsTable";
import "../components/connections/ConnectionsStyles.css";
import { setTcpSessions } from "../features/sessionsSlice";
import {
  createSessionsSocket,
  isTcpSessionsPayload,
  normalizeTcpSessionsPayload,
} from "../services/sessions";
import type {
  TcpTrackedSession,
  TcpTrackedSessionState,
} from "../types/sessions/TcpSession";

export default function ConnectionTracking() {
  const dispatch = useAppDispatch();
  const sessions = useAppSelector((state) => state.sessions.tcpSessions);
  const accessToken = useAppSelector((state) => state.user.accessToken);
  const socketRef = useRef<Socket | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [isError, setIsError] = useState(false);
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<
    TcpTrackedSessionState | "all"
  >("all");
  const [selectedIndex, setSelectedIndex] = useState<number | null>(0);
  const deferredSearch = useDeferredValue(search);

  useEffect(() => {
    if (!accessToken) {
      setIsFetching(false);
      setIsError(true);
      dispatch(setTcpSessions([]));
      return;
    }

    const socket = createSessionsSocket(accessToken);
    socketRef.current = socket;
    setIsFetching(true);
    setIsError(false);

    socket.on("connect", () => {
      setIsFetching(false);
      setIsError(false);
    });
    socket.on("connect_error", () => {
      setIsFetching(false);
      setIsError(true);
    });
    socket.on("disconnect", () => {
      setIsFetching(false);
    });
    socket.on("tcpSessions", (payload: unknown) => {
      if (!isTcpSessionsPayload(payload)) return;
      const normalizedPayload = normalizeTcpSessionsPayload(payload);
      dispatch(setTcpSessions(normalizedPayload.tcpSessions));
      setIsFetching(false);
      setIsError(false);
    });

    socket.connect();

    return () => {
      socketRef.current = null;
      socket.disconnect();
    };
  }, [accessToken, dispatch]);

  const filteredSessions = useMemo(() => {
    const normalizedSearch = deferredSearch.trim().toLowerCase();

    return sessions.filter((session) => {
      if (stateFilter !== "all" && session.state !== stateFilter) return false;
      if (normalizedSearch.length === 0) return true;

      return [
        session.id,
        session.endpointA.ip,
        session.endpointA.port,
        session.endpointB.ip,
        session.endpointB.port,
        session.state,
        session.lifecycle,
        session.lastDirection,
        session.interfaces.originalIngress,
        session.interfaces.originalEgress,
        session.interfaces.replyIngress,
        session.interfaces.replyEgress,
        session.natInfo?.ruleId,
        session.natInfo?.bindingId,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalizedSearch);
    });
  }, [deferredSearch, sessions, stateFilter]);

  const selectedSession = useMemo<TcpTrackedSession | null>(() => {
    if (selectedIndex === null) return null;

    return filteredSessions[selectedIndex] ?? filteredSessions[0] ?? null;
  }, [filteredSessions, selectedIndex]);

  const handleRefresh = useCallback(() => {
    const socket = socketRef.current;
    if (!socket) return;

    setIsFetching(true);
    if (socket.connected) socket.disconnect();
    socket.connect();
  }, []);

  const handleSelect = useCallback((index: number) => {
    setSelectedIndex(index);
  }, []);

  const handleExport = useCallback(() => {
    const payload = JSON.stringify({ tcpSessions: filteredSessions }, null, 2);

    navigator.clipboard?.writeText(payload);
  }, [filteredSessions]);

  useEffect(() => {
    if (filteredSessions.length === 0) {
      setSelectedIndex(null);
      return;
    }

    setSelectedIndex((current) =>
      current === null || current >= filteredSessions.length ? 0 : current,
    );
  }, [filteredSessions.length]);

  return (
    <div className="connections-page">
      <div className="connections-shell">
        <ConnectionsPageHeader />
        <ConnectionsStatusBar sessions={sessions} isFetching={isFetching} />
        {isError ? (
          <div className="connections-error">
            Could not load TCP sessions from /sessions
          </div>
        ) : null}
        <ConnectionStats
          sessions={sessions}
          isFetching={isFetching}
          onRefresh={handleRefresh}
        />
        <section className="connections-workspace-grid">
          <ConnectionsTable
            sessions={filteredSessions}
            selectedIndex={selectedIndex}
            search={search}
            stateFilter={stateFilter}
            onSearchChange={setSearch}
            onStateFilterChange={setStateFilter}
            onSelect={handleSelect}
            onExport={handleExport}
          />
          <ConnectionInspector
            session={selectedSession}
            selectedIndex={selectedIndex}
          />
        </section>
        <ConnectionsFooter />
      </div>
    </div>
  );
}
