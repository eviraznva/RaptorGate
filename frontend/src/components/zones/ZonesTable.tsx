import type { Zone } from "../../types/zones/Zone";

type ZonesTableProps = {
  zones: Zone[];
  confirmDeleteId: string | null;
  onNew: () => void;
  onEdit: (zone: Zone) => void;
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

function ZoneStatusDot({ isActive }: { isActive: boolean }) {
  return (
    <span
      className={`flex items-center gap-2 ${isActive ? "text-[#10b981]" : "text-[#8a8a8a]"}`}
    >
      <span className="relative flex h-2 w-2 flex-shrink-0">
        {isActive && (
          <span
            className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
            style={{ animation: "pingSlow 2.4s ease-in-out infinite" }}
          />
        )}
        <span
          className={`relative inline-flex h-2 w-2 rounded-full ${
            isActive ? "bg-[#10b981]" : "bg-[#8a8a8a]"
          }`}
        />
      </span>
      <span className="text-xs uppercase tracking-[0.1em] font-medium">
        {isActive ? "Active" : "Inactive"}
      </span>
    </span>
  );
}

function EmptyState({ onNew }: { onNew: () => void }) {
  return (
    <tr>
      <td colSpan={6} className="px-4 py-16 text-center">
        <div className="text-[#4a4a4a] text-sm tracking-[0.25em] uppercase mb-2">
          No zones configured
        </div>
        <div className="text-[#3a3a3a] text-xs mb-4">
          Define network zones to start building your segmentation policy
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New Zone
        </button>
      </td>
    </tr>
  );
}

const TABLE_HEADERS = ["Status", "Name", "Description", "ID", "Created", "Actions"];

export default function ZonesTable({
  zones,
  confirmDeleteId,
  onNew,
  onEdit,
  onDeleteClick,
  onDeleteConfirm,
  onDeleteCancel,
}: ZonesTableProps) {
  return (
    <>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="text-[11px] tracking-[0.25em] uppercase">Zone List</span>
          <span className="text-[10px] text-[#4a4a4a] font-mono">
            [{zones.length} {zones.length === 1 ? "entry" : "entries"}]
          </span>
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New Zone
        </button>
      </div>

      <div className="bg-[#161616] border border-[#262626]">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#262626]">
              {TABLE_HEADERS.map((h, i) => (
                <th
                  key={h}
                  className={`text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium ${
                    i === 2 ? "hidden lg:table-cell" : ""
                  } ${i === 5 ? "w-28 text-right" : ""}`}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {zones.length === 0 && <EmptyState onNew={onNew} />}

            {zones.map((zone) => (
              <tr
                key={zone.id}
                className="border-b border-[#262626] last:border-b-0 hover:bg-[#1b1b1b] transition-colors"
              >
                <td className="p-4">
                  <ZoneStatusDot isActive={zone.isActive} />
                </td>
                <td className="p-4">
                  <div className="text-[#f5f5f5] text-sm font-mono">{zone.name}</div>
                </td>
                <td className="p-4 hidden lg:table-cell">
                  <div
                    className="text-[#8a8a8a] text-xs max-w-[280px] truncate"
                    title={zone.description}
                  >
                    {zone.description}
                  </div>
                </td>
                <td className="p-4">
                  <span
                    className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                    style={{
                      borderColor: "#06b6d430",
                      backgroundColor: "#06b6d408",
                    }}
                    title={zone.id}
                  >
                    {shortId(zone.id)}
                  </span>
                </td>
                <td className="p-4">
                  <span className="text-[#4a4a4a] text-xs font-mono">
                    {fmtDate(zone.createdAt)}
                  </span>
                </td>
                <td className="p-4 text-right">
                  {confirmDeleteId === zone.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => onDeleteConfirm(zone.id)}
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
                        onClick={() => onEdit(zone)}
                        className="text-[#8a8a8a] hover:text-[#06b6d4] transition-colors text-lg"
                        title="Edit"
                      >
                        ✎
                      </button>
                      <button
                        type="button"
                        onClick={() => onDeleteClick(zone.id)}
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
