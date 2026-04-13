import type { ReactNode } from "react";
import { LineArrow } from "../lineArrow/LineArrow";

type ResetPasswordShellProps = {
  children: ReactNode;
};

export function ResetPasswordShell({
  children,
}: ResetPasswordShellProps) {
  return (
    <div className="min-h-screen overflow-hidden bg-[#0c0c0c] text-[#f5f5f5]">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(6,182,212,0.12),transparent_28%),radial-gradient(circle_at_bottom_right,rgba(6,182,212,0.08),transparent_22%)]" />
        <div className="absolute inset-y-0 left-[7%] w-px bg-gradient-to-b from-transparent via-[#06b6d4]/35 to-transparent" />
        <div className="absolute inset-y-0 right-[9%] w-px bg-gradient-to-b from-transparent via-[#262626] to-transparent" />
        <div className="absolute left-0 right-0 top-[16%] h-px bg-gradient-to-r from-transparent via-[#06b6d4]/25 to-transparent" />
        <div className="absolute bottom-[14%] left-[12%] h-24 w-24 rounded-full border border-[#06b6d4]/10" />
      </div>

      <div className="relative flex min-h-screen items-center justify-center px-6 py-10 sm:px-8">
        <div className="w-full max-w-6xl">
          <div className="mb-8 flex items-center justify-center">
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <LineArrow width={220} className="w-full max-w-[220px]" />
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <div className="border border-[#262626] bg-[#111111]/95 shadow-[0_0_0_1px_rgba(6,182,212,0.05),0_30px_90px_rgba(0,0,0,0.55)] backdrop-blur-sm">
            {children}
          </div>

          <div className="mt-5 flex items-center justify-between gap-4 text-[11px] uppercase tracking-[0.24em] text-[#4a4a4a]">
            <span>Credential recovery interface</span>
            <span className="text-[#06b6d4]">RaptorGate Security Layer</span>
          </div>
        </div>
      </div>
    </div>
  );
}