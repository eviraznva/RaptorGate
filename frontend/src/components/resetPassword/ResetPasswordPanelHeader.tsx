export function ResetPasswordPanelHeader() {
  return (
    <div className="flex flex-col gap-4 border-b border-[#262626] pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <div className="text-[11px] uppercase tracking-[0.24em] text-[#4a4a4a]">
          Recovery request
        </div>
        <h2 className="mt-2 text-xl tracking-[0.14em] text-[#f5f5f5]">
          Reset Password
        </h2>
      </div>

      <div className="min-w-[140px] border border-[#262626] bg-[#0c0c0c] px-3 py-2 text-right">
        <div className="text-[10px] uppercase tracking-[0.24em] text-[#4a4a4a]">
          Password signal
        </div>
        <div className="mt-1 text-sm tracking-[0.16em] text-[#06b6d4]">
          Standby
        </div>
      </div>
    </div>
  );
}