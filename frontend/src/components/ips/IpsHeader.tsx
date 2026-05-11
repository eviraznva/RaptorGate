type IpsHeaderProps = {
  enabled: boolean;
  signatureCount: number;
  hasChanges: boolean;
};

export default function IpsHeader({
  enabled,
  signatureCount,
  hasChanges,
}: IpsHeaderProps) {
  return (
    <div className="bg-[#161616] border border-[#262626] p-4 mb-6">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="text-[#8a8a8a] uppercase tracking-widest">
          Module status
        </span>
        <span className={enabled ? "text-[#10b981]" : "text-[#f43f5e]"}>
          ● {enabled ? "ENABLED" : "DISABLED"}
        </span>
        <span className="text-[#4a4a4a]">|</span>
        <span className="text-[#8a8a8a]">Signatures:</span>
        <span className="text-[#06b6d4]">{signatureCount}</span>
        <span className="text-[#4a4a4a]">|</span>
        <span className="text-[#8a8a8a]">Draft changes:</span>
        <span className={hasChanges ? "text-[#06b6d4]" : "text-[#4a4a4a]"}>
          {hasChanges ? "YES" : "NO"}
        </span>
      </div>
    </div>
  );
}

