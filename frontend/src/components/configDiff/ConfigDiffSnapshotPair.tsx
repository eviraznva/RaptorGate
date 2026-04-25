import type { ConfigDiffSnapshotMeta } from "../../types/config/ConfigDiff";

type ConfigDiffSnapshotPairProps = {
  base: ConfigDiffSnapshotMeta | null;
  target: ConfigDiffSnapshotMeta | null;
};

function toShortId(value: string) {
  if (value.length < 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function toShortChecksum(value: string) {
  if (value.length < 20) return value;
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function toHumanDate(value: string) {
  return new Date(value).toLocaleString('pl-PL', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function SnapshotCard({ snapshot, label, isTarget }: {
  snapshot: ConfigDiffSnapshotMeta | null;
  label: string;
  isTarget?: boolean;
}) {
  return (
    <article className={`bg-[#161616] border ${isTarget ? 'border-[#06b6d450]' : 'border-[#262626]'}`}>
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-[#262626]">
        <h2 className="text-[10px] tracking-[0.24em] uppercase font-medium">{label}</h2>
        <span className="text-[9px] tracking-[0.11em] text-[#4a4a4a] overflow-hidden text-ellipsis whitespace-nowrap">
          {snapshot ? toShortId(snapshot.id) : '-'}
        </span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-[120px_170px_minmax(0,1fr)] gap-2.5 p-3">
        <div className="bg-[#111] border border-[#262626] px-[11px] py-2.5 grid gap-1 min-w-0">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Version</span>
          <strong className="text-[#f5f5f5] text-[12px] font-medium overflow-hidden text-ellipsis whitespace-nowrap">
            {snapshot ? `v${snapshot.versionNumber}` : '-'}
          </strong>
        </div>
        <div className="bg-[#111] border border-[#262626] px-[11px] py-2.5 grid gap-1 min-w-0">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Created</span>
          <strong className="text-[#f5f5f5] text-[12px] font-medium overflow-hidden text-ellipsis whitespace-nowrap">
            {snapshot ? toHumanDate(snapshot.createdAt) : '-'}
          </strong>
        </div>
        <div className="bg-[#111] border border-[#262626] px-[11px] py-2.5 grid gap-1 min-w-0">
          <span className="text-[9px] text-[#4a4a4a] tracking-[0.16em] uppercase">Checksum</span>
          <strong
            className="text-[#f5f5f5] text-[12px] font-medium overflow-hidden text-ellipsis whitespace-nowrap"
            title={snapshot?.checksum}
          >
            {snapshot ? toShortChecksum(snapshot.checksum) : '-'}
          </strong>
        </div>
      </div>
    </article>
  );
}

export default function ConfigDiffSnapshotPair({ base, target }: ConfigDiffSnapshotPairProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <SnapshotCard snapshot={base} label="Base" />
      <SnapshotCard snapshot={target} label="Target" isTarget />
    </div>
  );
}
