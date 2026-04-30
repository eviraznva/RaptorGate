import type { ConfigDiffSummary } from "../../types/config/ConfigDiff";

type TypeFilter = 'all' | 'added' | 'removed' | 'modified';

type ConfigDiffSummaryPanelProps = {
  summary: ConfigDiffSummary | null;
  totalChanges: number;
  typeFilter: TypeFilter;
  sectionFilter: string;
  onTypeFilter: (type: TypeFilter) => void;
  onSectionFilter: (section: string) => void;
};

export default function ConfigDiffSummaryPanel({
  summary,
  totalChanges,
  typeFilter,
  sectionFilter,
  onTypeFilter,
  onSectionFilter,
}: ConfigDiffSummaryPanelProps) {
  const added = summary?.added ?? 0;
  const modified = summary?.modified ?? 0;
  const removed = summary?.removed ?? 0;
  const bySection = summary?.bySection ?? {};

  const totalCards: { type: TypeFilter; label: string; count: number; activeColor: string }[] = [
    { type: 'added', label: 'Added', count: added, activeColor: 'border-[#10b98170]' },
    { type: 'modified', label: 'Modified', count: modified, activeColor: 'border-[#06b6d470]' },
    { type: 'removed', label: 'Removed', count: removed, activeColor: 'border-[#f43f5e70]' },
  ];

  return (
    <aside className="bg-[#161616] border border-[#262626] min-w-0">
      <div className="flex items-center justify-between px-3.5 py-3 border-b border-[#262626]">
        <h2 className="text-[10px] tracking-[0.24em] uppercase font-medium">Summary</h2>
        <span className="text-[9px] tracking-[0.11em] text-[#4a4a4a]">ConfigDiffSummaryDto</span>
      </div>

      <div className="grid grid-cols-3 gap-2 p-3.5 border-b border-[#262626]">
        {totalCards.map(({ type, label, count, activeColor }) => (
          <button
            key={type}
            type="button"
            onClick={() => onTypeFilter(typeFilter === type ? 'all' : type)}
            className={`bg-[#101010] border text-left grid gap-1.5 p-2.5 transition-colors text-[#8a8a8a] hover:border-[#06b6d450] ${
              typeFilter === type ? activeColor : 'border-[#262626]'
            }`}
          >
            <span className="text-[9px] tracking-[0.16em] uppercase">{label}</span>
            <strong className="text-[#f5f5f5] text-[22px] font-medium">{count}</strong>
          </button>
        ))}
      </div>

      <div className="grid gap-2 p-3.5">
        <button
          type="button"
          onClick={() => onSectionFilter('all')}
          className={`w-full border bg-[#101010] text-left grid grid-cols-[minmax(0,1fr)_auto] gap-2.5 px-[11px] py-2.5 transition-colors ${
            sectionFilter === 'all' ? 'border-[#06b6d445]' : 'border-[#262626] hover:border-[#06b6d445]'
          }`}
        >
          <strong className="text-[#f5f5f5] text-[11px] font-medium tracking-[0.12em] uppercase overflow-hidden text-ellipsis whitespace-nowrap">
            All sections
          </strong>
          <span className="text-[#4a4a4a] text-[10px]">{totalChanges} total</span>
        </button>

        {Object.entries(bySection)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([section, counts]) => (
            <button
              key={section}
              type="button"
              onClick={() => onSectionFilter(sectionFilter === section ? 'all' : section)}
              className={`w-full border bg-[#101010] text-left grid grid-cols-[minmax(0,1fr)_auto] gap-2.5 px-[11px] py-2.5 transition-colors ${
                sectionFilter === section ? 'border-[#06b6d445]' : 'border-[#262626] hover:border-[#06b6d445]'
              }`}
            >
              <strong className="text-[#f5f5f5] text-[11px] font-medium tracking-[0.12em] uppercase overflow-hidden text-ellipsis whitespace-nowrap">
                {section}
              </strong>
              <div className="flex gap-1.5">
                <span className="border border-[#262626] px-1.5 py-0.5 text-[9px] text-[#10b981]">+{counts.added}</span>
                <span className="border border-[#262626] px-1.5 py-0.5 text-[9px] text-[#06b6d4]">~{counts.modified}</span>
                <span className="border border-[#262626] px-1.5 py-0.5 text-[9px] text-[#f43f5e]">-{counts.removed}</span>
              </div>
            </button>
          ))}
      </div>
    </aside>
  );
}
