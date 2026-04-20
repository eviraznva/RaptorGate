import type { DashboardUser } from "../../types/users/User";

type UsersDeleteModalProps = {
  isOpen: boolean;
  user: DashboardUser | null;
  onCancel: () => void;
  onConfirm: (id: string) => void;
};

export default function UsersDeleteModal({
  isOpen,
  user,
  onCancel,
  onConfirm,
}: UsersDeleteModalProps) {
  if (!user) return null;

  return (
    <>
      <div
        className={`fixed inset-0 bg-black/65 transition-opacity z-[101] ${isOpen ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none"}`}
        onClick={onCancel}
      />

      <div
        className={`fixed top-1/2 left-1/2 w-[520px] max-w-[calc(100vw-32px)] bg-[#161616] border border-[#262626] z-[102] transition-all
          ${isOpen ? "opacity-100 -translate-x-1/2 -translate-y-1/2" : "opacity-0 -translate-x-1/2 -translate-y-[46%] pointer-events-none"}`}
      >
        <div className="p-5 border-b border-[#262626]">
          <div className="text-[12px] tracking-[0.2em] uppercase text-[#f43f5e] mb-2">
            Delete User Confirmation
          </div>
          <div className="text-[12px] leading-relaxed tracking-[0.08em] uppercase text-[#8a8a8a]">
            Delete confirmation for user "{user.username}" prepared for
            destructive action flow.
          </div>
        </div>

        <div className="p-5">
          <div className="border border-[#262626] bg-[#121212] p-4">
            <ModalRow label="Username" value={user.username} />
            <ModalRow label="Roles" value={user.roles.join(", ")} />
            <ModalRow label="ID" value={user.id} mono />
          </div>
        </div>

        <div className="p-5 border-t border-[#262626] flex items-center justify-end gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#262626] text-[#8a8a8a] hover:border-[#8a8a8a] hover:text-[#f5f5f5] transition-colors"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={() => {
              onConfirm(user.id);
            }}
            className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#f43f5e] text-[#f43f5e] hover:bg-[#f43f5e] hover:text-white transition-colors"
          >
            Delete User
          </button>
        </div>
      </div>
    </>
  );
}

type ModalRowProps = {
  label: string;
  value: string;
  mono?: boolean;
};

function ModalRow({ label, value, mono = false }: ModalRowProps) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 border-t border-[#262626] first:border-t-0">
      <span className="text-[11px] tracking-[0.15em] uppercase text-[#4a4a4a]">
        {label}
      </span>
      <span
        className={`text-[12px] text-right text-[#f5f5f5] ${mono ? "font-mono break-all" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}
