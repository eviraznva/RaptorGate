type UsersListMetaBarProps = {
  visibleCount: number;
};

export default function UsersListMetaBar({ visibleCount }: UsersListMetaBarProps) {
  return (
    <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-[#262626] flex-wrap">
      <div className="text-[12px] tracking-[0.2em] text-[#8a8a8a] uppercase">
        Users List / Selectable Rows And Row Actions
      </div>
      <div className="text-[11px] tracking-[0.15em] text-[#4a4a4a] uppercase">
        Visible Entries: <span className="text-[#8a8a8a] font-mono">{visibleCount}</span>
      </div>
    </div>
  );
}
