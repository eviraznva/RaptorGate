import type { NatRule, NatType } from "../../types/nat/NatRule";
import { getNatRuleType, protocolLabel } from "../../types/nat/NatRule";

function priorityColor(p: number) {
  return p <= 3 ? "#f43f5e" : p <= 7 ? "#f59e0b" : "#06b6d4";
}

function PriorityBar({ priority }: { priority: number }) {
  const color = priorityColor(priority);
  return (
    <div className="flex items-center gap-2">
      <div className="w-[2px] h-7 flex-shrink-0 rounded-sm" style={{ backgroundColor: color }} />
      <span className="font-mono text-sm font-bold tabular-nums w-5 text-right" style={{ color }}>
        {priority}
      </span>
    </div>
  );
}

const TYPE_COLORS: Record<NatType, { text: string; border: string; bg: string }> = {
  SNAT: { text: "#06b6d4", border: "rgba(6,182,212,0.35)", bg: "rgba(6,182,212,0.08)" },
  DNAT: { text: "#f59e0b", border: "rgba(245,158,11,0.35)", bg: "rgba(245,158,11,0.08)" },
  PAT: { text: "#10b981", border: "rgba(16,185,129,0.35)", bg: "rgba(16,185,129,0.08)" },
  MASQUERADE: { text: "#a855f7", border: "rgba(168,85,247,0.35)", bg: "rgba(168,85,247,0.08)" },
};

function TypeBadge({ type }: { type: NatType }) {
  const { text, border, bg } = TYPE_COLORS[type];
  return (
    <span
      className="inline-block px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.15em] border"
      style={{ color: text, borderColor: border, backgroundColor: bg }}
    >
      {type === "MASQUERADE" ? "MASQ" : type}
    </span>
  );
}

function StatusCell({ isActive }: { isActive: boolean }) {
  return (
    <span className={`flex items-center gap-2 ${isActive ? "text-[#10b981]" : "text-[#8a8a8a]"}`}>
      <span className="relative flex h-2 w-2 flex-shrink-0">
        {isActive ? (
          <span
            className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
            style={{ animation: "pingSlow 2.4s ease-in-out infinite" }}
          />
        ) : null}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${isActive ? "bg-[#10b981]" : "bg-[#8a8a8a]"}`} />
      </span>
      <span className="text-xs uppercase tracking-[0.1em] font-medium">
        {isActive ? "Active" : "Inactive"}
      </span>
    </span>
  );
}

function EmptyText() {
  return <span className="text-[#4a4a4a] text-xs italic">—</span>;
}

function RangeText({ min, max }: { min: number | null | undefined; max: number | null | undefined }) {
  if (min == null && max == null) return <EmptyText />;
  return (
    <span className="font-mono text-xs text-[#f5f5f5]">
      {min ?? "*"}<span className="text-[#4a4a4a]">–</span>{max ?? "*"}
    </span>
  );
}

function ScopeCell({ rule }: { rule: NatRule }) {
  const entries = [
    ["if", rule.inInterface, rule.outInterface],
    ["zone", rule.inZone, rule.outZone],
  ].filter(([, from, to]) => from || to);

  if (entries.length === 0) return <EmptyText />;

  return (
    <div className="space-y-1 font-mono text-xs">
      {entries.map(([label, from, to]) => (
        <div key={label}>
          <span className="text-[#4a4a4a]">{label}</span>{" "}
          <span className="text-[#f5f5f5]">{from || "*"}</span>
          <span className="text-[#4a4a4a]"> → </span>
          <span className="text-[#f5f5f5]">{to || "*"}</span>
        </div>
      ))}
    </div>
  );
}

function MatchCell({ rule }: { rule: NatRule }) {
  const hasSrc = rule.matchSrcPortMin != null || rule.matchSrcPortMax != null;
  const hasDst = rule.matchDstPortMin != null || rule.matchDstPortMax != null;
  if (!hasSrc && !hasDst) return <EmptyText />;

  return (
    <div className="space-y-1">
      {hasSrc ? (
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] uppercase tracking-[0.15em] text-[#4a4a4a]">src</span>
          <RangeText min={rule.matchSrcPortMin} max={rule.matchSrcPortMax} />
        </div>
      ) : null}
      {hasDst ? (
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] uppercase tracking-[0.15em] text-[#4a4a4a]">dst</span>
          <RangeText min={rule.matchDstPortMin} max={rule.matchDstPortMax} />
        </div>
      ) : null}
    </div>
  );
}

function ActionCell({ rule }: { rule: NatRule }) {
  switch (rule.action.$case) {
    case "snat":
      return (
        <div className="font-mono text-xs">
          <span className="text-[#f5f5f5]">{rule.action.snat.srcCidr}</span>
          <span className="text-[#4a4a4a]"> → </span>
          <span className="text-[#06b6d4]">{rule.action.snat.translatedIp}</span>
          {rule.action.snat.srcPortMin != null || rule.action.snat.srcPortMax != null ? (
            <div className="mt-1 text-[#8a8a8a]">
              src ports <RangeText min={rule.action.snat.srcPortMin} max={rule.action.snat.srcPortMax} />
            </div>
          ) : null}
        </div>
      );
    case "dnat":
      return (
        <div className="font-mono text-xs">
          <span className="text-[#f5f5f5]">{rule.action.dnat.dstCidr}</span>
          <span className="text-[#4a4a4a]"> → </span>
          <span className="text-[#f59e0b]">
            {rule.action.dnat.translatedIp}
            {rule.action.dnat.translatedPort != null ? `:${rule.action.dnat.translatedPort}` : ""}
          </span>
        </div>
      );
    case "pat":
      return (
        <div className="font-mono text-xs">
          <span className="text-[#f5f5f5]">{rule.action.pat.dstIp}:{rule.action.pat.dstPort}</span>
          <span className="text-[#4a4a4a]"> → </span>
          <span className="text-[#10b981]">{rule.action.pat.translatedIp}:{rule.action.pat.translatedPort}</span>
        </div>
      );
    case "masquerade":
      return (
        <div className="font-mono text-xs">
          {rule.action.masquerade.srcCidr ? (
            <span className="text-[#f5f5f5]">{rule.action.masquerade.srcCidr}</span>
          ) : (
            <EmptyText />
          )}
          {rule.action.masquerade.srcPortMin != null || rule.action.masquerade.srcPortMax != null ? (
            <div className="mt-1 text-[#8a8a8a]">
              src ports <RangeText min={rule.action.masquerade.srcPortMin} max={rule.action.masquerade.srcPortMax} />
            </div>
          ) : null}
        </div>
      );
  }
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
        <button type="button" onClick={onNew} className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase">
          + New NAT Rule
        </button>
      </td>
    </tr>
  );
}

export type NatFilter = "all" | NatType;

type FilterPillsProps = {
  activeFilter: NatFilter;
  onFilterChange: (f: NatFilter) => void;
};

const FILTER_OPTIONS: { key: NatFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "SNAT", label: "SNAT" },
  { key: "DNAT", label: "DNAT" },
  { key: "PAT", label: "PAT" },
  { key: "MASQUERADE", label: "MASQ" },
];

function FilterPills({ activeFilter, onFilterChange }: FilterPillsProps) {
  return (
    <div className="flex">
      {FILTER_OPTIONS.map((opt, index) => (
        <button
          key={opt.key}
          type="button"
          onClick={() => onFilterChange(opt.key)}
          className={`px-3 py-1.5 text-[9px] uppercase border transition-colors
            ${index > 0 ? "border-l-0" : ""}
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

const TABLE_HEADERS = [
  "Priority",
  "Type",
  "Protocol",
  "Status",
  "Scope",
  "Port Match",
  "Action",
  "ID",
  "Updated",
  "Actions",
];

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
  const filtered = activeFilter === "all" ? rules : rules.filter((r) => getNatRuleType(r) === activeFilter);

  return (
    <>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-4">
          <span className="text-[11px] tracking-[0.25em] uppercase">NAT Rule List</span>
          <span className="text-[10px] text-[#4a4a4a] font-mono">
            [{filtered.length} {filtered.length === 1 ? "entry" : "entries"}]
          </span>
          <FilterPills activeFilter={activeFilter} onFilterChange={onFilterChange} />
        </div>
        <button type="button" onClick={onNew} className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase">
          + New NAT Rule
        </button>
      </div>

      <div className="bg-[#161616] border border-[#262626] overflow-x-auto">
        <table className="w-full min-w-[1120px]">
          <thead>
            <tr className="border-b border-[#262626]">
              {TABLE_HEADERS.map((h, i) => (
                <th
                  key={h}
                  className={`text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium whitespace-nowrap ${
                    i === 9 ? "text-right w-28" : ""
                  }`}
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
              filtered.map((rule) => {
                const type = getNatRuleType(rule);
                return (
                  <tr key={rule.id} className="border-b border-[#262626] last:border-b-0 hover:bg-[#1b1b1b] transition-colors">
                    <td className="p-4">
                      <PriorityBar priority={rule.priority} />
                    </td>
                    <td className="p-4">
                      <TypeBadge type={type} />
                    </td>
                    <td className="p-4">
                      <span className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider border-[#262626]">
                        {protocolLabel(rule.protocol)}
                      </span>
                    </td>
                    <td className="p-4">
                      <StatusCell isActive={rule.isActive} />
                    </td>
                    <td className="p-4">
                      <ScopeCell rule={rule} />
                    </td>
                    <td className="p-4">
                      <MatchCell rule={rule} />
                    </td>
                    <td className="p-4">
                      <ActionCell rule={rule} />
                    </td>
                    <td className="p-4">
                      <span
                        className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                        style={{ borderColor: "#06b6d430", backgroundColor: "#06b6d408" }}
                        title={rule.id}
                      >
                        {shortId(rule.id)}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="text-[#4a4a4a] text-xs font-mono">{fmtDate(rule.updatedAt)}</span>
                    </td>
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
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
