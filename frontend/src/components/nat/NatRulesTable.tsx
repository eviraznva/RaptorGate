import type { NatRule, NatType } from "../../types/nat/NatRule";

// ── Sub-components defined at module level (rerender-no-inline-components) ──

function priorityColor(p: number) {
  return p <= 3 ? "#f43f5e" : p <= 7 ? "#f59e0b" : "#06b6d4";
}

function PriorityBar({ priority }: { priority: number }) {
  const color = priorityColor(priority);
  return (
    <div className="flex items-center gap-2">
      <div
        className="w-[2px] h-7 flex-shrink-0 rounded-sm"
        style={{ backgroundColor: color }}
      />
      <span
        className="font-mono text-sm font-bold tabular-nums w-5 text-right"
        style={{ color }}
      >
        {priority}
      </span>
    </div>
  );
}

const TYPE_COLORS: Record<NatType, { text: string; border: string; bg: string }> = {
  SNAT: { text: "#06b6d4", border: "rgba(6,182,212,0.35)",  bg: "rgba(6,182,212,0.08)"  },
  DNAT: { text: "#f59e0b", border: "rgba(245,158,11,0.35)", bg: "rgba(245,158,11,0.08)" },
  PAT:  { text: "#10b981", border: "rgba(16,185,129,0.35)", bg: "rgba(16,185,129,0.08)" },
};

function TypeBadge({ type }: { type: NatType }) {
  const { text, border, bg } = TYPE_COLORS[type];
  return (
    <span
      className="inline-block px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.15em] border"
      style={{ color: text, borderColor: border, backgroundColor: bg }}
    >
      {type}
    </span>
  );
}

function StatusCell({ isActive }: { isActive: boolean }) {
  return (
    <span className={`flex items-center gap-2 ${isActive ? "text-[#10b981]" : "text-[#8a8a8a]"}`}>
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

function NetCell({ ip, port }: { ip: string | null; port: number | null }) {
  if (!ip && !port) {
    return <span className="text-[#4a4a4a] text-xs italic">—</span>;
  }
  return (
    <span className="font-mono text-xs">
      {ip !== null ? <span className="text-[#f5f5f5]">{ip}</span> : null}
      {ip !== null && port !== null ? (
        <span className="text-[#4a4a4a]">:</span>
      ) : null}
      {port !== null ? <span className="text-[#8a8a8a]">{port}</span> : null}
    </span>
  );
}

function EmptyState({ onNew }: { onNew: () => void }) {
  return (
    <tr>
      <td colSpan={10} className="px-4 py-16 text-center">
        <div className="text-[#4a4a4a] text-sm tracking-[0.25em] uppercase mb-2">
          No NAT rules configured
        </div>
        <div className="text-[#3a3a3a] text-xs mb-4">
          Create a rule to start translating network addresses
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New NAT Rule
        </button>
      </td>
    </tr>
  );
}

// ── Filter pills ──
export type NatFilter = "all" | NatType;

type FilterPillsProps = {
  activeFilter: NatFilter;
  onFilterChange: (f: NatFilter) => void;
};

const FILTER_OPTIONS: { key: NatFilter; label: string }[] = [
  { key: "all",  label: "All"  },
  { key: "SNAT", label: "SNAT" },
  { key: "DNAT", label: "DNAT" },
  { key: "PAT",  label: "PAT"  },
];

function FilterPills({ activeFilter, onFilterChange }: FilterPillsProps) {
  return (
    <div className="flex">
      {FILTER_OPTIONS.map((opt) => (
        <button
          key={opt.key}
          type="button"
          onClick={() => onFilterChange(opt.key)}
          className={`px-3 py-1.5 text-[9px] letter-spacing-[0.15em] uppercase border transition-colors first:border-r-0 last:border-l-0
            ${opt.key !== "all" && opt.key !== "SNAT" ? "border-l-0" : ""}
            ${
              activeFilter === opt.key
                ? "text-[#06b6d4] border-[#06b6d4] bg-[#06b6d4]/10"
                : "text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5] hover:border-[#4a4a4a]"
            }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// ── Table headers ──
const TABLE_HEADERS = [
  "Priority", "Type", "Status",
  "Source IP:Port", "", "Translated IP:Port", "Destination IP:Port",
  "ID", "Updated", "Actions",
];

// ── Main table ──
type NatRulesTableProps = {
  rules: NatRule[];
  activeFilter: NatFilter;
  onFilterChange: (f: NatFilter) => void;
  confirmDeleteId: string | null;
  onNew: () => void;
  onEdit: (rule: NatRule) => void;
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

export default function NatRulesTable({
  rules,
  activeFilter,
  onFilterChange,
  confirmDeleteId,
  onNew,
  onEdit,
  onDeleteClick,
  onDeleteConfirm,
  onDeleteCancel,
}: NatRulesTableProps) {
  const filtered =
    activeFilter === "all" ? rules : rules.filter((r) => r.type === activeFilter);

  return (
    <>
      {/* Toolbar */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-4">
          <span className="text-[11px] tracking-[0.25em] uppercase">NAT Rule List</span>
          <span className="text-[10px] text-[#4a4a4a] font-mono">
            [{filtered.length} {filtered.length === 1 ? "entry" : "entries"}]
          </span>
          <FilterPills activeFilter={activeFilter} onFilterChange={onFilterChange} />
        </div>
        <button
          type="button"
          onClick={onNew}
          className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
        >
          + New NAT Rule
        </button>
      </div>

      {/* Table */}
      <div className="bg-[#161616] border border-[#262626] overflow-x-auto">
        <table className="w-full min-w-[960px]">
          <thead>
            <tr className="border-b border-[#262626]">
              {TABLE_HEADERS.map((h, i) => (
                <th
                  key={i}
                  className={`text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium whitespace-nowrap
                    ${i === 4 ? "w-6 px-0" : ""}
                    ${i === 9 ? "text-right w-28" : ""}`}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <EmptyState onNew={onNew} />
            ) : (
              filtered.map((rule) => (
                <tr
                  key={rule.id}
                  className="border-b border-[#262626] last:border-b-0 hover:bg-[#1b1b1b] transition-colors"
                >
                  {/* Priority */}
                  <td className="p-4">
                    <PriorityBar priority={rule.priority} />
                  </td>
                  {/* Type */}
                  <td className="p-4">
                    <TypeBadge type={rule.type} />
                  </td>
                  {/* Status */}
                  <td className="p-4">
                    <StatusCell isActive={rule.isActive} />
                  </td>
                  {/* Source IP:Port */}
                  <td className="p-4">
                    <NetCell ip={rule.sourceIp} port={rule.sourcePort} />
                  </td>
                  {/* Arrow */}
                  <td className="px-0 text-[#06b6d4] text-sm">→</td>
                  {/* Translated IP:Port */}
                  <td className="p-4">
                    <NetCell ip={rule.translatedIp} port={rule.translatedPort} />
                  </td>
                  {/* Destination IP:Port */}
                  <td className="p-4">
                    <NetCell ip={rule.destinationIp} port={rule.destinationPort} />
                  </td>
                  {/* ID */}
                  <td className="p-4">
                    <span
                      className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                      style={{ borderColor: "#06b6d430", backgroundColor: "#06b6d408" }}
                      title={rule.id}
                    >
                      {shortId(rule.id)}
                    </span>
                  </td>
                  {/* Updated */}
                  <td className="p-4">
                    <span className="text-[#4a4a4a] text-xs font-mono">{fmtDate(rule.updatedAt)}</span>
                  </td>
                  {/* Actions */}
                  <td className="p-4 text-right">
                    {confirmDeleteId === rule.id ? (
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => onDeleteConfirm(rule.id)}
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
                          onClick={() => onEdit(rule)}
                          className="text-[#8a8a8a] hover:text-[#06b6d4] transition-colors text-lg"
                          title="Edit"
                        >
                          ✎
                        </button>
                        <button
                          type="button"
                          onClick={() => onDeleteClick(rule.id)}
                          className="text-[#8a8a8a] hover:text-[#f43f5e] transition-colors text-lg"
                          title="Delete"
                        >
                          ✕
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
