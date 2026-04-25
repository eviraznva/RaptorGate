import {
  formatSnapshotDate,
  shortenChecksum,
  shortenId,
} from "./mockData";
import type { ConfigSnapshot, SnapshotType } from "./types";

type ConfigControlHistoryPanelProps = {
  snapshots: ConfigSnapshot[];
  selectedSnapshotId: string;
};

const typeBadgeClassName: Record<SnapshotType, string> = {
  manual_import:
    "text-[#06b6d4] border border-[#06b6d430] bg-[#06b6d410] px-2 py-0.5",
  rollback_point:
    "text-[#f59e0b] border border-[#f59e0b40] bg-[#f59e0b12] px-2 py-0.5",
  auto_save: "text-[#9ca3af] border border-[#9ca3af35] bg-[#9ca3af12] px-2 py-0.5",
};

export default function ConfigControlHistoryPanel({
  snapshots,
  selectedSnapshotId,
}: ConfigControlHistoryPanelProps) {
  return (
    <section className="bg-[#161616] border border-[#262626] min-w-0">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#262626]">
        <span className="text-[12px] tracking-[0.22em] uppercase">
          Snapshot History
        </span>
        <span className="text-[10px] text-[#4a4a4a] tracking-[0.12em]">
          GET /config/history
        </span>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-[#262626]">
        <div className="flex overflow-x-auto">
          <button
            type="button"
            className="text-[10px] uppercase tracking-[0.14em] px-3 py-1.5 border border-[#06b6d450] bg-[#06b6d410] text-[#06b6d4]"
          >
            All
          </button>
          <button
            type="button"
            className="text-[10px] uppercase tracking-[0.14em] px-3 py-1.5 border-y border-r border-[#262626] text-[#8a8a8a]"
          >
            manual_import
          </button>
          <button
            type="button"
            className="text-[10px] uppercase tracking-[0.14em] px-3 py-1.5 border-y border-r border-[#262626] text-[#8a8a8a]"
          >
            rollback_point
          </button>
          <button
            type="button"
            className="text-[10px] uppercase tracking-[0.14em] px-3 py-1.5 border-y border-r border-[#262626] text-[#8a8a8a]"
          >
            auto_save
          </button>
        </div>

        <input
          className="bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-base text-[#f5f5f5] min-w-[240px]"
          placeholder="Search by id, checksum, actor"
          readOnly
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px]">
          <thead>
            <tr className="border-b border-[#262626]">
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                Version
              </th>
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                Type
              </th>
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                Checksum
              </th>
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                State
              </th>
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                Created
              </th>
              <th className="text-left p-3 text-[10px] uppercase tracking-[0.2em] text-[#4a4a4a] font-medium">
                Actor
              </th>
            </tr>
          </thead>
          <tbody>
            {snapshots.map((snapshot) => (
              <tr
                key={snapshot.id}
                className={`border-b border-[#262626] transition-colors ${
                  snapshot.id === selectedSnapshotId
                    ? "bg-[#06b6d410]"
                    : "hover:bg-[#1b1b1b]"
                }`}
              >
                <td className="p-3 text-base font-mono text-[#f5f5f5]">
                  v{snapshot.versionNumber}
                </td>
                <td className="p-3">
                  <span
                    className={`inline-block text-[10px] tracking-[0.14em] uppercase ${typeBadgeClassName[snapshot.snapshotType]}`}
                  >
                    {snapshot.snapshotType}
                  </span>
                </td>
                <td className="p-3 text-[12px] font-mono text-[#8a8a8a]" title={snapshot.checksum}>
                  {shortenChecksum(snapshot.checksum)}
                </td>
                <td className="p-3 text-[11px] uppercase tracking-[0.13em]">
                  <span
                    className={`inline-flex items-center gap-2 ${
                      snapshot.isActive ? "text-[#10b981]" : "text-[#4a4a4a]"
                    }`}
                  >
                    <span
                      className={`h-2 w-2 rounded-full ${
                        snapshot.isActive
                          ? "bg-[#10b981] shadow-[0_0_6px_rgba(16,185,129,0.7)]"
                          : "bg-[#4a4a4a]"
                      }`}
                    />
                    {snapshot.isActive ? "active" : "inactive"}
                  </span>
                </td>
                <td className="p-3 text-[12px] font-mono text-[#8a8a8a]">
                  {formatSnapshotDate(snapshot.createdAt)}
                </td>
                <td className="p-3 text-[12px] font-mono text-[#8a8a8a]" title={snapshot.createdBy}>
                  {shortenId(snapshot.createdBy)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
