import { useEffect, useState } from "react";
import type { DashboardUser, UserRole } from "../../types/users/User";
import { USER_ROLE_OPTIONS } from "./usersMockData";
import type { CreateUserBody } from "../../services/users";

interface UsersFormState {
  username: string;
  password: string;
  confirmPassword: string;
  roles: UserRole[];
}

type UsersFormDrawerProps = {
  isOpen: boolean;
  mode: "create" | "edit" | null;
  user: DashboardUser | null;
  onClose: () => void;
  onSave: (userData: CreateUserBody, mode: "create" | "edit" | null) => void;
};

const EMPTY: UsersFormState = {
  username: "",
  password: "",
  confirmPassword: "",
  roles: [],
};

export default function UsersFormDrawer({
  isOpen,
  mode,
  user,
  onClose,
  onSave,
}: UsersFormDrawerProps) {
  const [form, setForm] = useState<UsersFormState>(EMPTY);

  const isEdit = mode === "edit" && user !== null;

  useEffect(() => {
    if (isOpen) {
      setForm(
        user
          ? {
              username: user.username,
              password: "",
              confirmPassword: "",
              roles: user.roles,
            }
          : EMPTY,
      );
    }
  }, [isOpen, user]);

  return (
    <>
      <div
        className={`fixed inset-0 bg-black/65 transition-opacity z-[100] ${isOpen ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none"}`}
        onClick={onClose}
      />

      <aside
        className={`fixed top-0 right-0 bottom-0 w-[480px] max-w-full bg-[#161616] border-l border-[#262626] z-[101] flex flex-col transition-transform
          ${isOpen ? "translate-x-0" : "translate-x-full"}`}
      >
        <div className="p-6 border-b border-[#262626] flex items-start justify-between gap-4">
          <div>
            <div className="text-[12px] tracking-[0.25em] uppercase text-[#06b6d4]">
              {isEdit ? "Edit User" : "Create User"}
            </div>
            <div className="text-[11px] text-[#8a8a8a] tracking-[0.1em] uppercase mt-1 leading-relaxed">
              Static form aligned to create and edit dto fields
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="bg-transparent border-none text-[#4a4a4a] hover:text-[#f5f5f5] text-base leading-none px-1.5 cursor-pointer"
          >
            ×
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-5">
          <section>
            <div className="text-[11px] tracking-[0.25em] uppercase text-[#4a4a4a] border-b border-[#262626] pb-1.5 mb-3">
              Identity
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="flex flex-col gap-2">
                <span className="text-[11px] tracking-[0.2em] uppercase text-[#4a4a4a]">
                  Username
                </span>
                <input
                  value={form.username}
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2.5 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#06b6d4]"
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, username: e.target.value }))
                  }
                />
              </label>

              <label className="flex flex-col gap-2">
                <span className="text-[11px] tracking-[0.2em] uppercase text-[#4a4a4a]">
                  Password
                </span>
                <input
                  value={form.password}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, password: e.target.value }))
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2.5 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#06b6d4]"
                />
              </label>

              <label className="flex flex-col gap-2">
                <span className="text-[11px] tracking-[0.2em] uppercase text-[#4a4a4a]">
                  Configrm Password
                </span>
                <input
                  value={form.confirmPassword}
                  onChange={(e) =>
                    setForm((prev) => ({
                      ...prev,
                      confirmPassword: e.target.value,
                    }))
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2.5 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#06b6d4]"
                />
              </label>
            </div>
          </section>

          <section>
            <div className="text-[11px] tracking-[0.25em] uppercase text-[#4a4a4a] border-b border-[#262626] pb-1.5 mb-3">
              Roles
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {USER_ROLE_OPTIONS.map((roleOption) => {
                const isActive = form.roles.includes(roleOption.role);

                return (
                  <div
                    key={roleOption.role}
                    className={`border px-3 py-2.5 transition-colors
                      ${isActive ? "border-[#06b6d4] bg-[#06b6d4]/10" : "border-[#262626] bg-[#121212]"}`}
                    onClick={() => {
                      const next = isActive
                        ? form.roles.filter((role) => role !== roleOption.role)
                        : [...form.roles, roleOption.role];

                      setForm((prev) => ({ ...prev, roles: next }));
                    }}
                  >
                    <div className="text-[12px] tracking-[0.15em] uppercase text-[#f5f5f5] mb-1">
                      {roleOption.role}
                    </div>
                    <div className="text-[11px] leading-relaxed tracking-[0.08em] uppercase text-[#8a8a8a]">
                      {roleOption.description}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <div className="p-5 border-t border-[#262626] flex items-center justify-end gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#262626] text-[#8a8a8a] hover:border-[#8a8a8a] hover:text-[#f5f5f5] transition-colors"
          >
            Cancel
          </button>
          <button
            disabled={
              form.username.trim() === "" ||
              form.password !== form.confirmPassword
            }
            type="button"
            onClick={() => {
              onSave(
                {
                  username: form.username,
                  password: form.password,
                  roles: form.roles,
                },
                mode,
              );
            }}
            className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#06b6d4] text-[#06b6d4] hover:bg-[#06b6d4] hover:text-black transition-colors"
          >
            Save User
          </button>
        </div>
      </aside>
    </>
  );
}
