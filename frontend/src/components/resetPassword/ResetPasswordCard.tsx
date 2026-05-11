import { ResetPasswordField } from "./ResetPasswordField";
import { ResetPasswordPanelHeader } from "./ResetPasswordPanelHeader";

export function ResetPasswordCard() {
  return (
    <section className="border border-[#262626] bg-[#161616] p-6 sm:p-8">
      <ResetPasswordPanelHeader />

      <div className="mt-6 space-y-5">
        <div className="grid gap-5 md:grid-cols-2">
          <ResetPasswordField
            label="Username"
            placeholder="jankowal"
            type="text"
          />
          <ResetPasswordField
            label="New password"
            placeholder="StrongPass123!"
            type="password"
          />
        </div>

        <ResetPasswordField
          label="Recovery token"
          placeholder="a3f9c1e7d4b2f0a8c6e4d2b0a9f7e5c3a1b9d7f5e3c1a8b6d4f2e0c8a6b4d2f0"
          as="textarea"
        />

        <ResetPasswordField
          label="Confirm new password"
          placeholder="Repeat new password"
          type="password"
        />

        <div className="border border-[#262626] bg-[#0f0f0f] px-4 py-4">
          <div className="mb-2 text-[11px] uppercase tracking-[0.24em] text-[#4a4a4a]">
            Status area
          </div>
          <p className="text-sm leading-6 text-[#8a8a8a]">
            Miejsce na komunikat walidacji, błędu albo sukcesu.
          </p>
        </div>

        <div className="flex flex-col gap-3 border-t border-[#262626] pt-5 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            className="border border-[#262626] px-5 py-3 text-xs uppercase tracking-[0.22em] text-[#8a8a8a] transition hover:border-[#06b6d4] hover:text-[#f5f5f5]"
          >
            Back to login
          </button>

          <button
            type="button"
            className="min-w-[220px] bg-[#06b6d4] px-6 py-3 text-sm font-medium uppercase tracking-[0.24em] text-black transition hover:bg-[#0891b2]"
          >
            Reset password
          </button>
        </div>
      </div>
    </section>
  );
}