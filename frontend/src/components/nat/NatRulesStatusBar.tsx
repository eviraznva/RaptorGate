import type { NatRule } from "../../types/nat/NatRule";

type NatRulesStatusBarProps = {
  rules: NatRule[];
};

function ActiveDot() {
  return (
    <span className="relative flex items-center gap-1.5 text-[#10b981]">
      <span className="relative flex h-1.5 w-1.5">
        <span
          className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
          style={{ animation: "pingSlow 2s ease-in-out infinite" }}
        />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-[#10b981]" />
      </span>
      ACTIVE
    </span>
  );
}

export default function NatRulesStatusBar({ rules }: NatRulesStatusBarProps) {
  const activeCount = rules.filter((r) => r.isActive).length;
  const snatCount   = rules.filter((r) => r.type === "SNAT").length;
  const dnatCount   = rules.filter((r) => r.type === "DNAT").length;
  const patCount    = rules.filter((r) => r.type === "PAT").length;

  return (
    <div className="bg-[#161616] border border-[#262626] px-5 py-3 mb-4 flex flex-wrap items-center gap-5 text-[11px]">
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a] uppercase tracking-[0.2em]">Module</span>
        <ActiveDot />
      </div>
      <span className="text-[#262626]">│</span>
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a]">Total</span>
        <span className="text-[#f5f5f5] font-mono tabular-nums">{rules.length}</span>
      </div>
      <span className="text-[#262626]">│</span>
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a]">Active</span>
        <span className="text-[#10b981] font-mono tabular-nums">{activeCount}</span>
      </div>
      <span className="text-[#262626]">│</span>
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a]">SNAT</span>
        <span className="text-[#06b6d4] font-mono tabular-nums">{snatCount}</span>
      </div>
      <span className="text-[#262626]">│</span>
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a]">DNAT</span>
        <span className="text-[#f59e0b] font-mono tabular-nums">{dnatCount}</span>
      </div>
      <span className="text-[#262626]">│</span>
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a]">PAT</span>
        <span className="text-[#10b981] font-mono tabular-nums">{patCount}</span>
      </div>
    </div>
  );
}
