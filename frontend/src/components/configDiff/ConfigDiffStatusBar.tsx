type ConfigDiffStatusBarProps = {
  baseVersion: number | null;
  targetVersion: number | null;
};

export default function ConfigDiffStatusBar({ baseVersion, targetVersion }: ConfigDiffStatusBarProps) {
  return (
    <section className="bg-[#161616] border border-[#262626] flex flex-wrap items-center gap-3.5 px-4 py-2.5 text-[10px] tracking-[0.14em] uppercase">
      <div className="flex items-center gap-2 mr-auto text-[#f5f5f5]">
        <span className="w-[7px] h-[7px] rounded-full bg-[#10b981] shadow-[0_0_8px_rgba(16,185,129,0.75)]" />
        <span>Diff Endpoint Ready</span>
      </div>
      <span className="text-[#4a4a4a]">|</span>
      <div className="flex items-center gap-2 text-[#8a8a8a]">
        <span>Route</span>
        <span className="text-[#f5f5f5]">GET /config/diff</span>
      </div>
      <span className="text-[#4a4a4a]">|</span>
      <div className="flex items-center gap-2 text-[#8a8a8a]">
        <span>Base</span>
        <span className="text-[#f5f5f5]">{baseVersion != null ? `v${baseVersion}` : '-'}</span>
      </div>
      <span className="text-[#4a4a4a]">|</span>
      <div className="flex items-center gap-2 text-[#8a8a8a]">
        <span>Target</span>
        <span className="text-[#f5f5f5]">{targetVersion != null ? `v${targetVersion}` : '-'}</span>
      </div>
    </section>
  );
}
