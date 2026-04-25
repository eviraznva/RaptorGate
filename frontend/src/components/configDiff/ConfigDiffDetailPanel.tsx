import { useMemo } from "react";
import type { ConfigDiffChange } from "../../types/config/ConfigDiff";

type ConfigDiffDetailPanelProps = {
  change: ConfigDiffChange | null;
};

function toJson(value: unknown): string {
  if (value === undefined) return 'No value';
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

type DiffLineType = 'added' | 'removed' | 'context' | 'empty';

type DiffLine = {
  lineType: DiffLineType;
  marker: string;
  content: string;
};

function buildUnifiedDiff(change: ConfigDiffChange): DiffLine[] {
  const beforeLines = change.before === undefined ? [] : toJson(change.before).split('\n');
  const afterLines = change.after === undefined ? [] : toJson(change.after).split('\n');

  if (change.type === 'added') {
    return afterLines.map((line) => ({ lineType: 'added', marker: '+', content: line }));
  }

  if (change.type === 'removed') {
    return beforeLines.map((line) => ({ lineType: 'removed', marker: '-', content: line }));
  }

  const rows: DiffLine[] = [];
  const maxLen = Math.max(beforeLines.length, afterLines.length);

  for (let i = 0; i < maxLen; i++) {
    const before = beforeLines[i];
    const after = afterLines[i];

    if (before === after) {
      rows.push({ lineType: 'context', marker: '', content: before ?? '' });
      continue;
    }
    if (before !== undefined) {
      rows.push({ lineType: 'removed', marker: '-', content: before });
    }
    if (after !== undefined) {
      rows.push({ lineType: 'added', marker: '+', content: after });
    }
  }

  return rows;
}

const lineStyles: Record<DiffLineType, string> = {
  added: 'bg-[#10b98115] text-[#8ee7c3]',
  removed: 'bg-[#f43f5e1a] text-[#ff9cad]',
  context: 'text-[#b9c7cc]',
  empty: 'text-[#4a4a4a]',
};

export default function ConfigDiffDetailPanel({ change }: ConfigDiffDetailPanelProps) {
  const diffLines = useMemo(() => (change ? buildUnifiedDiff(change) : []), [change]);

  return (
    <section className="bg-[#161616] border border-[#262626] pb-3.5">
      <div className="flex items-center justify-between px-3.5 py-3 border-b border-[#262626]">
        <h2 className="text-[10px] tracking-[0.24em] uppercase font-medium">Change Detail</h2>
        <span className="text-[9px] tracking-[0.11em] text-[#4a4a4a] overflow-hidden text-ellipsis whitespace-nowrap max-w-[60%]">
          {change ? change.path : 'No change selected'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[150px_190px_minmax(0,1fr)] gap-2.5 p-3.5">
        {[
          { label: 'Type', value: change?.type ?? '-' },
          { label: 'Section', value: change?.section ?? '-' },
          { label: 'Entity ID', value: change?.entityId ?? '-' },
        ].map(({ label, value }) => (
          <div key={label} className="bg-[#111] border border-[#262626] px-[11px] py-2.5 grid gap-1 min-w-0">
            <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">{label}</span>
            <strong className="text-[#f5f5f5] text-[12px] font-medium overflow-hidden text-ellipsis whitespace-nowrap">{value}</strong>
          </div>
        ))}
      </div>

      <div className="px-3.5">
        <div className="flex justify-between bg-[#111] border border-[#262626] border-b-0 px-2.5 py-2">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">unified diff</span>
        </div>
        <div className="bg-[#101010] border border-[#262626] min-h-[240px] max-h-[420px] overflow-auto text-[10px] leading-[1.55]">
          {diffLines.length === 0 ? (
            <div className="grid grid-cols-[42px_minmax(0,1fr)] border-b border-[#26262645]">
              <span className="text-[#4a4a4a] bg-[#ffffff05] border-r border-[#262626] px-2 py-0.5 text-right select-none" />
              <code className="px-2.5 py-0.5 whitespace-pre-wrap break-words text-[#4a4a4a]">No value</code>
            </div>
          ) : (
            diffLines.map((line, idx) => {
              const isEmpty = line.content === 'No value';
              return (
                <div
                  key={idx}
                  className={`grid grid-cols-[42px_minmax(0,1fr)] border-b border-[#26262645] last:border-b-0 ${lineStyles[isEmpty ? 'empty' : line.lineType]}`}
                >
                  <span className="bg-[#ffffff03] border-r border-[#262626] px-2 py-0.5 text-right select-none">
                    {line.marker}
                  </span>
                  <code className="px-2.5 py-0.5 whitespace-pre-wrap break-words">{line.content}</code>
                </div>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}
