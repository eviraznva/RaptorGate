import { useCallback, useDeferredValue, useEffect, useMemo, useState } from "react";
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
  useGetTcpSessionsQuery,
  type TcpSessionsPayload,
} from "../services/sessions";
import type { ApiSuccess } from "../types/ApiResponse";
import type {
  TcpTrackedSession,
  TcpTrackedSessionState,
} from "../types/sessions/TcpSession";

export default function ConnectionTracking() {
  const dispatch = useAppDispatch();
  const sessions = useAppSelector((state) => state.sessions.tcpSessions);
  const { data, isFetching, isError, refetch } = useGetTcpSessionsQuery();
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<
    TcpTrackedSessionState | "all"
  >("all");
  const [selectedIndex, setSelectedIndex] = useState<number | null>(0);
  const deferredSearch = useDeferredValue(search);

  useEffect(() => {
    if (!data || "error" in data) return;

    const payload = data as ApiSuccess<TcpSessionsPayload>;

    dispatch(setTcpSessions(payload.data.tcpSessions));
  }, [data, dispatch]);

  const filteredSessions = useMemo(() => {
    const normalizedSearch = deferredSearch.trim().toLowerCase();

    return sessions.filter((session) => {
      if (stateFilter !== "all" && session.state !== stateFilter) return false;
      if (normalizedSearch.length === 0) return true;

      return [
        session.endpointA.ip,
        session.endpointA.port,
        session.endpointB.ip,
        session.endpointB.port,
        session.state,
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
    refetch();
  }, [refetch]);

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
            Could not load TCP sessions from /tcp-sessions
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
