type DnsActionsBarProps = {
  canApply: boolean;
  onApply: () => void;
  onResetTab: () => void;
  onResetAll: () => void;
};

export default function DnsActionsBar({
  canApply,
  onApply,
  onResetTab,
  onResetAll,
}: DnsActionsBarProps) {
  return (
    <div className="flex flex-wrap gap-3 mb-10">
      <button
        onClick={onApply}
        disabled={!canApply}
        className={`px-4 py-2 text-sm font-medium transition ${
          canApply
            ? "bg-[#06b6d4] text-black hover:bg-[#0891b2]"
            : "bg-[#2a2a2a] text-[#6a6a6a] cursor-not-allowed"
        }`}
      >
        APPLY LOCAL CHANGES
      </button>

      <button
        onClick={onResetTab}
        className="px-4 py-2 text-sm border border-[#262626] text-[#8a8a8a] hover:text-white"
      >
        RESET TAB
      </button>

      <button
        onClick={onResetAll}
        className="px-4 py-2 text-sm border border-[#262626] text-[#8a8a8a] hover:text-white"
      >
        RESET ALL
      </button>
    </div>
  );
}
