import { Icon } from "@iconify/react";
import type { DashboardUser, UserRole } from "../../types/users/User";
import { formatDate } from "./usersUtils";

type UsersTableProps = {
  users: DashboardUser[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
};

const TABLE_HEADERS = [
  "User",
  "Roles",
  "Status",
  "Created",
  "Updated",
  "ID",
  "Actions",
];

function roleBadgeClass(role: UserRole) {
  if (role === "admin")
    return "text-[#06b6d4] border-[#06b6d45a] bg-[#06b6d4]/10";
  if (role === "super_admin")
    return "text-[#f59e0b] border-[#f59e0b5a] bg-[#f59e0b]/10";
  if (role === "operator")
    return "text-[#10b981] border-[#10b9815a] bg-[#10b981]/10";
  return "text-[#f5f5f5] border-[#262626] bg-[#121212]";
}

function statusClass(status: DashboardUser["isFirstLogin"]) {
  console.log(status);
  if (status === false) return "status-active text-[#10b981]";
  if (status === true) return "status-pending text-[#f59e0b]";
  return "status-locked text-[#f43f5e]";
}

function statusLabel(status: DashboardUser["isFirstLogin"]) {
  console.log(status);

  if (status === false) return "Active";
  if (status === true) return "First Login";
  return "Unknown";
}

function EmptyRows() {
  return (
    <tr>
      <td colSpan={7} className="px-5 py-16 text-center">
        <div className="text-[#8a8a8a] text-[13px] tracking-[0.2em] uppercase mb-2">
          No Users In Current Filter
        </div>
        <div className="text-[#4a4a4a] text-[12px] tracking-[0.1em] uppercase">
          Switch Filter Or Create New User
        </div>
      </td>
    </tr>
  );
}

export default function UsersTable({
  users,
  selectedId,
  onSelect,
  onEdit,
  onDelete,
}: UsersTableProps) {
  console.log(users);

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[920px]">
        <thead>
          <tr className="border-b border-[#262626]">
            {TABLE_HEADERS.map((header, index) => (
              <th
                key={header}
                className={`p-4 text-left text-[11px] tracking-[0.2em] uppercase text-[#4a4a4a] font-normal
                  ${index === TABLE_HEADERS.length - 1 ? "text-right" : ""}`}
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {users.length === 0 ? (
            <EmptyRows />
          ) : (
            users.map((user) => (
              <tr
                key={user.id}
                onClick={() => onSelect(user.id)}
                className={`border-b border-[#262626] last:border-b-0 hover:bg-[#1c1c1c] transition-colors cursor-pointer
                  ${selectedId === user.id ? "bg-[#06b6d4]/6" : ""}`}
              >
                <td className="p-4">
                  <div className="flex items-center gap-2.5">
                    <div>
                      <div className="text-[#f5f5f5] font-bold text-sm">
                        {user.username}
                      </div>
                    </div>
                  </div>
                </td>

                <td className="p-4">
                  <div className="flex items-center flex-wrap gap-1.5">
                    {user.roles.map((role) => (
                      <span
                        key={role}
                        className={`inline-block px-2 py-0.5 border text-[11px] tracking-[0.12em] uppercase ${roleBadgeClass(role)}`}
                      >
                        {role}
                      </span>
                    ))}
                  </div>
                </td>

                <td className="p-4">
                  <span
                    className={`inline-flex items-center gap-2 text-[12px] tracking-[0.1em] uppercase ${statusClass(user.isFirstLogin)}`}
                  >
                    <span className="w-2 h-2 rounded-full bg-current shadow-[0_0_6px_currentColor]" />
                    {statusLabel(user.isFirstLogin)}
                  </span>
                </td>

                <td className="p-4 text-[12px] text-[#8a8a8a] whitespace-nowrap">
                  {formatDate(user.createdAt)}
                </td>
                <td className="p-4 text-[12px] text-[#8a8a8a] whitespace-nowrap">
                  {formatDate(user.updatedAt)}
                </td>

                <td className="p-4">
                  <span className="text-[12px] text-[#4a4a4a] font-mono">
                    {user.id}
                  </span>
                </td>

                <td className="p-4">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onEdit(user.id);
                      }}
                      className="text-[#8a8a8a] hover:text-[#06b6d4] transition-colors text-lg"
                      title="Edit"
                    >
                      <Icon icon="lucide:edit" width="16" height="16" />
                    </button>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onDelete(user.id);
                      }}
                      className="text-[#8a8a8a] hover:text-[#f43f5e] transition-colors text-lg"
                      title="Delete"
                    >
                      <Icon icon="lucide:x" width="16" height="16" />
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
