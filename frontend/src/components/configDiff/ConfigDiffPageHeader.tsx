export default function ConfigDiffPageHeader() {
  return (
    <header className="text-center pb-4 pt-1">
      <div className="text-[10px] tracking-[0.38em] text-[#4a4a4a] uppercase mb-2">
        RaptorGate
      </div>
      <div className="flex items-center justify-center gap-3 mb-2">
        <div className="w-[90px] h-px bg-gradient-to-r from-transparent to-[#06b6d4]" />
        <span className="text-[13px] tracking-[0.32em] text-[#06b6d4] uppercase">
          Configuration Diff
        </span>
        <div className="w-[90px] h-px bg-gradient-to-l from-transparent to-[#06b6d4]" />
      </div>
      <div className="text-[10px] tracking-[0.22em] text-[#8a8a8a] uppercase">
        Snapshot Comparison View
      </div>
    </header>
  );
}
