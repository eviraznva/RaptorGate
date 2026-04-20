import type { DashboardUser } from "../../types/users/User";
import { formatDate } from "./usersUtils";

type UsersDetailsPanelProps = {
  user: DashboardUser | null;
};

export default function UsersDetailsPanel({ user }: UsersDetailsPanelProps) {
  if (!user) {
    return (
      <aside className="border-l border-[#262626] bg-black/8 p-5">
        <div className="text-[11px] tracking-[0.22em] uppercase text-[#4a4a4a] mb-3">
          Selected User
        </div>
        <div className="border border-[#262626] bg-[#121212] p-4 text-[12px] uppercase tracking-[0.1em] text-[#8a8a8a]">
          Select Row To Preview Details
        </div>
      </aside>
    );
  }

  return (
    <aside className="border-l border-[#262626] bg-black/8">
      <div className="p-5 border-b border-[#262626]">
        <div className="text-[11px] tracking-[0.22em] uppercase text-[#4a4a4a] mb-3">
          Selected User
        </div>
        <div className="border border-[#262626] bg-[#121212] p-4">
          <div className="flex items-center gap-2.5 mb-3.5">
            <div>
              <div className="text-sm text-[#f5f5f5] font-bold">
                {user.username}
              </div>
            </div>
          </div>

          <div className="space-y-0">
            <DetailRow label="Roles" value={user.roles.join(", ")} />
            <DetailRow
              label="Status"
              value={user.isFirstLogin ? "First login" : "Active"}
            />
            <DetailRow label="Created" value={formatDate(user.createdAt)} />
            <DetailRow label="Updated" value={formatDate(user.updatedAt)} />
            <DetailRow label="ID" value={user.id} mono />
          </div>
        </div>
      </div>
    </aside>
  );
}

type DetailRowProps = {
  label: string;
  value: string;
  mono?: boolean;
};

function DetailRow({ label, value, mono = false }: DetailRowProps) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 border-t border-[#262626] first:border-t-0">
      <span className="text-[11px] tracking-[0.15em] uppercase text-[#4a4a4a]">
        {label}
      </span>
      <span
        className={`text-[12px] text-right text-[#f5f5f5] leading-relaxed ${mono ? "font-mono break-all" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}
