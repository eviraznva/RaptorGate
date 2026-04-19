import type { Zone } from "../../types/zones/Zone";
import type { ZonePair } from "../../types/zones/ZonePair";

type ZonePairsTableProps = {
  zonePairs: ZonePair[];
  zones: Zone[];
  confirmDeleteId: string | null;
  onNew: () => void;
  onEdit: (pair: ZonePair) => void;
  onDeleteClick: (id: string) => void;
  onDeleteConfirm: (id: string) => void;
  onDeleteCancel: () => void;
};

function shortId(id: string) {
  return id.length > 8 ? id.slice(0, 8) + "…" : id;
}

function fmtDate(iso: string) {
  return new Date(iso).toISOString().split("T")[0];
}

function zoneName(zones: Zone[], id: string) {
  return zones.find((z) => z.id === id)?.name ?? shortId(id);
}

function PolicyBadge({ policy }: { policy: "ALLOW" | "DROP" }) {
  const isAllow = policy === "ALLOW";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.15em] border ${
        isAllow
          ? "text-[#10b981] border-[#10b981]/30 bg-[#10b981]/10"
          : "text-[#f43f5e] border-[#f43f5e]/30 bg-[#f43f5e]/10"
      }`}
    >
      {policy}
    </span>
  );
}

function EmptyState({ onNew }: { onNew: () => void }) {
  return (
    <tr>
      <td colSpan={7} className="px-4 py-16 text-center">
        <div className="text-[#4a4a4a] text-sm tracking-[0.25em] uppercase mb-2">
          No zone pairs configured
        </div>
        <div className="text-[#3a3a3a] text-xs mb-4">
          Define traffic flow between zones to enforce access policies
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New Zone Pair
        </button>
      </td>
    </tr>
  );
}

const TABLE_HEADERS = [
  "Flow",
  "Default Policy",
  "Src Zone ID",
  "Dst Zone ID",
  "Pair ID",
  "Created",
  "Actions",
];

export default function ZonePairsTable({
  zonePairs,
  zones,
  confirmDeleteId,
  onNew,
  onEdit,
  onDeleteClick,
  onDeleteConfirm,
  onDeleteCancel,
}: ZonePairsTableProps) {
  return (
    <>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="text-[11px] tracking-[0.25em] uppercase">Zone Pair List</span>
          <span className="text-[10px] text-[#4a4a4a] font-mono">
            [{zonePairs.length} {zonePairs.length === 1 ? "entry" : "entries"}]
          </span>
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New Zone Pair
        </button>
      </div>

      <div className="bg-[#161616] border border-[#262626] overflow-x-auto">
        <table className="w-full min-w-[760px]">
          <thead>
            <tr className="border-b border-[#262626]">
              {TABLE_HEADERS.map((h, i) => (
                <th
                  key={h}
                  className={`text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium whitespace-nowrap ${
                    i === 6 ? "w-28 text-right" : ""
                  }`}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {zonePairs.length === 0 && <EmptyState onNew={onNew} />}

            {zonePairs.map((pair) => (
              <tr
                key={pair.id}
                className="border-b border-[#262626] last:border-b-0 hover:bg-[#1b1b1b] transition-colors"
              >
                {/* Flow: SRC → DST */}
                <td className="p-4">
                  <div className="flex items-center gap-2 whitespace-nowrap">
                    <span className="text-[#f5f5f5] text-sm font-mono font-bold">
                      {zoneName(zones, pair.srcZoneId)}
                    </span>
                    <span className="text-[#06b6d4] text-xs">→</span>
                    <span className="text-[#f5f5f5] text-sm font-mono font-bold">
                      {zoneName(zones, pair.dstZoneId)}
                    </span>
                  </div>
                </td>
                {/* Policy badge */}
                <td className="p-4">
                  <PolicyBadge policy={pair.defaultPolicy} />
                </td>
                {/* Src zone ID */}
                <td className="p-4">
                  <span
                    className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                    style={{ borderColor: "#06b6d430", backgroundColor: "#06b6d408" }}
                    title={pair.srcZoneId}
                  >
                    {shortId(pair.srcZoneId)}
                  </span>
                </td>
                {/* Dst zone ID */}
                <td className="p-4">
                  <span
                    className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                    style={{ borderColor: "#06b6d430", backgroundColor: "#06b6d408" }}
                    title={pair.dstZoneId}
                  >
                    {shortId(pair.dstZoneId)}
                  </span>
                </td>
                {/* Pair ID */}
                <td className="p-4">
                  <span
                    className="text-xs font-mono text-[#4a4a4a] tracking-wider"
                    title={pair.id}
                  >
                    {shortId(pair.id)}
                  </span>
                </td>
                {/* Created */}
                <td className="p-4">
                  <span className="text-[#4a4a4a] text-xs font-mono">
                    {fmtDate(pair.createdAt)}
                  </span>
                </td>
                {/* Actions */}
                <td className="p-4 text-right">
                  {confirmDeleteId === pair.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => onDeleteConfirm(pair.id)}
                        className="text-xs text-[#f43f5e] hover:text-[#ff6b6b] tracking-wider uppercase font-bold"
                      >
                        Confirm
                      </button>
                      <span className="text-[#4a4a4a] text-xs">│</span>
                      <button
                        type="button"
                        onClick={onDeleteCancel}
                        className="text-xs text-[#8a8a8a] hover:text-[#f5f5f5] tracking-wider uppercase font-bold"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center justify-end gap-4">
                      <button
                        type="button"
                        onClick={() => onEdit(pair)}
                        className="text-[#8a8a8a] hover:text-[#06b6d4] transition-colors text-lg"
                        title="Edit"
                      >
                        ✎
                      </button>
                      <button
                        type="button"
                        onClick={() => onDeleteClick(pair.id)}
                        className="text-[#8a8a8a] hover:text-[#f43f5e] transition-colors text-lg"
                        title="Delete"
                      >
                        ✕
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
