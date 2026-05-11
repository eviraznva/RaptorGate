export type UsersFilter = "all" | "admins" | "pending" | "locked";

type UsersToolbarProps = {
  activeFilter: UsersFilter;
  onFilterChange: (filter: UsersFilter) => void;
  onCreate: () => void;
};

const FILTERS: { key: UsersFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "admins", label: "Admins" },
  { key: "pending", label: "Pending" },
  { key: "locked", label: "Locked" },
];

export default function UsersToolbar({ activeFilter, onFilterChange, onCreate }: UsersToolbarProps) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-4 border-b border-[#262626] flex-wrap">
      <div className="text-[12px] tracking-[0.2em] text-[#8a8a8a] uppercase">
        Users Directory / List And Operator Actions
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex">
          {FILTERS.map((filter, index) => (
            <button
              key={filter.key}
              type="button"
              onClick={() => onFilterChange(filter.key)}
              className={`px-3 py-1.5 text-[11px] uppercase tracking-[0.15em] border transition-colors
                ${index > 0 ? "border-l-0" : ""}
                ${
                  activeFilter === filter.key
                    ? "text-[#06b6d4] border-[#06b6d4] bg-[#06b6d4]/10"
                    : "text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5] hover:border-[#8a8a8a]"
                }`}
            >
              {filter.label}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={onCreate}
          className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#06b6d4] text-[#06b6d4] hover:bg-[#06b6d4] hover:text-black transition-colors"
        >
          Add User
        </button>
      </div>
    </div>
  );
}
