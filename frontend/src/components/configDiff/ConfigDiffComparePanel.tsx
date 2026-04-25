import type { ConfigSnapshot } from "../../types/config/Config";

type ConfigDiffComparePanelProps = {
  snapshots: ConfigSnapshot[];
  baseId: string;
  targetId: string;
  onBaseChange: (id: string) => void;
  onTargetChange: (id: string) => void;
};

function toShortId(value: string) {
  if (value.length < 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

export default function ConfigDiffComparePanel({
  snapshots,
  baseId,
  targetId,
  onBaseChange,
  onTargetChange,
}: ConfigDiffComparePanelProps) {
  const endpointPreview = baseId && targetId
    ? `/config/diff?baseId=${baseId}&targetId=${targetId}`
    : '/config/diff?baseId=-&targetId=-';

  return (
    <section className="bg-[#161616] border border-[#262626]">
      <div className="flex items-center justify-between px-3.5 py-3 border-b border-[#262626]">
        <h2 className="text-[10px] tracking-[0.24em] uppercase font-medium">Compare Snapshots</h2>
        <span className="text-[9px] tracking-[0.11em] text-[#4a4a4a]">baseId + targetId</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[minmax(260px,1fr)_minmax(260px,1fr)_minmax(320px,1.2fr)] gap-3 p-3.5">
        <label className="grid gap-1.5">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Base Snapshot</span>
          <select
            value={baseId}
            onChange={(e) => onBaseChange(e.target.value)}
            className="w-full bg-[#0c0c0c] border border-[#262626] text-[#f5f5f5] text-[12px] px-[11px] py-2.5 outline-none focus:border-[#06b6d4] transition-colors"
          >
            {snapshots.map((s) => (
              <option key={s.id} value={s.id}>
                v{s.versionNumber} | {toShortId(s.id)}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1.5">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Target Snapshot</span>
          <select
            value={targetId}
            onChange={(e) => onTargetChange(e.target.value)}
            className="w-full bg-[#0c0c0c] border border-[#262626] text-[#f5f5f5] text-[12px] px-[11px] py-2.5 outline-none focus:border-[#06b6d4] transition-colors"
          >
            {snapshots.map((s) => (
              <option key={s.id} value={s.id}>
                v{s.versionNumber} | {toShortId(s.id)}
              </option>
            ))}
          </select>
        </label>

        <div className="grid gap-1.5 min-w-0">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Request</span>
          <div className="min-h-[37px] bg-[#101010] border border-[#262626] text-[#06b6d4] text-[11px] font-medium px-[11px] py-2.5 overflow-hidden text-ellipsis whitespace-nowrap">
            {endpointPreview}
          </div>
        </div>
      </div>
    </section>
  );
}
