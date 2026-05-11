export default function NatRulesPageHeader() {
  return (
    <div className="flex items-center gap-4 mb-10">
      <div className="flex-shrink-0 w-full items-center justify-center text-center px-2">
        <div className="text-[9px] text-[#4a4a4a] tracking-[0.45em] uppercase mb-0.5">
          RaptorGate
        </div>
        <div className="text-[13px] tracking-[0.35em] uppercase">NAT Rules</div>
        <div className="text-[9px] text-[#06b6d4] tracking-[0.25em] mt-0.5">
          Network Address Translation Management
        </div>
      </div>
    </div>
  );
}
