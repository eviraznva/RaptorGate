import type { ConfigDiffChange } from "../../types/config/ConfigDiff";

type TypeFilter = 'all' | 'added' | 'removed' | 'modified';

type ConfigDiffChangesPanelProps = {
  changes: ConfigDiffChange[];
  typeFilter: TypeFilter;
  search: string;
  selectedIndex: number;
  onTypeFilter: (type: TypeFilter) => void;
  onSearch: (value: string) => void;
  onSelectChange: (index: number) => void;
};

const badgeClass: Record<string, string> = {
  added: 'text-[#10b981] border-[#10b98145] bg-[#10b98115]',
  modified: 'text-[#06b6d4] border-[#06b6d445] bg-[#06b6d412]',
  removed: 'text-[#f43f5e] border-[#f43f5e45] bg-[#f43f5e10]',
};

const chipFilters: { type: TypeFilter; label: string }[] = [
  { type: 'all', label: 'All' },
  { type: 'added', label: 'Added' },
  { type: 'modified', label: 'Modified' },
  { type: 'removed', label: 'Removed' },
];

export default function ConfigDiffChangesPanel({
  changes,
  typeFilter,
  search,
  selectedIndex,
  onTypeFilter,
  onSearch,
  onSelectChange,
}: ConfigDiffChangesPanelProps) {
  return (
    <main className="bg-[#161616] border border-[#262626] min-w-0">
      <div className="flex items-center justify-between px-3.5 py-3 border-b border-[#262626]">
        <h2 className="text-[10px] tracking-[0.24em] uppercase font-medium">Changes</h2>
        <span className="text-[9px] tracking-[0.11em] text-[#4a4a4a]">{changes.length} rows</span>
      </div>

      <div className="flex items-center justify-between gap-3 px-3.5 py-3 border-b border-[#262626] flex-wrap">
        <div className="flex">
          {chipFilters.map(({ type, label }, idx) => (
            <button
              key={type}
              type="button"
              onClick={() => onTypeFilter(type)}
              className={`border bg-[#101010] text-[9px] uppercase tracking-[0.14em] px-2.5 py-1.5 transition-colors ${
                idx < chipFilters.length - 1 ? 'border-r-0' : ''
              } ${
                typeFilter === type
                  ? 'text-[#06b6d4] border-[#06b6d450] bg-[#06b6d412]'
                  : 'text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by section, path, entity id"
          className="bg-[#0c0c0c] border border-[#262626] text-[#f5f5f5] text-[12px] px-3 h-9 outline-none focus:border-[#06b6d4] transition-colors min-w-[280px] max-w-[380px] w-full"
        />
      </div>

      <div className="overflow-auto">
        <table className="w-full min-w-[860px] border-collapse">
          <thead>
            <tr className="bg-[#151515] border-b border-[#262626]">
              {['Type', 'Section', 'Entity', 'Path'].map((h) => (
                <th key={h} className="text-left px-3 py-2.5 text-[9px] tracking-[0.18em] uppercase text-[#4a4a4a] font-medium whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {changes.length === 0 ? (
              <tr className="border-b border-[#262626]">
                <td colSpan={4} className="px-3 py-3 text-[11px] font-mono text-[#4a4a4a]">
                  No changes for current filter
                </td>
              </tr>
            ) : (
              changes.map((change, index) => (
                <tr
                  key={`${change.path}-${index}`}
                  onClick={() => onSelectChange(index)}
                  className={`border-b border-[#262626] cursor-pointer transition-colors ${
                    index === selectedIndex
                      ? 'bg-[#06b6d410]'
                      : 'hover:bg-[#1f1f1f]'
                  }`}
                >
                  <td className="px-3 py-[11px] align-middle">
                    <span className={`inline-block border px-2 py-0.5 text-[9px] uppercase tracking-[0.14em] ${badgeClass[change.type]}`}>
                      {change.type}
                    </span>
                  </td>
                  <td className="px-3 py-[11px] text-[11px] font-mono text-[#8a8a8a]">{change.section}</td>
                  <td className="px-3 py-[11px] text-[11px] font-mono text-[#8a8a8a]">{change.entityId ?? '-'}</td>
                  <td className="px-3 py-[11px] text-[11px] font-mono text-[#b9c7cc] max-w-[520px] overflow-hidden text-ellipsis whitespace-nowrap" title={change.path}>
                    {change.path}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </main>
  );
}
