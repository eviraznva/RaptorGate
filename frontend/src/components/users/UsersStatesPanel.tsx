export type UsersUiState = "loading" | "empty" | "error" | "success";

type UsersStatesPanelProps = {
  activeState: UsersUiState;
  onStateChange: (state: UsersUiState) => void;
  onCreate: () => void;
};

const STATE_OPTIONS: { key: UsersUiState; label: string }[] = [
  { key: "loading", label: "Loading" },
  { key: "empty", label: "Empty" },
  { key: "error", label: "Error" },
  { key: "success", label: "Success" },
];

export default function UsersStatesPanel({
  activeState,
  onStateChange,
  onCreate,
}: UsersStatesPanelProps) {
  return (
    <div className="px-5 pt-4 pb-5 border-t border-[#262626]">
      <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
        <div className="text-[12px] tracking-[0.2em] text-[#8a8a8a] uppercase">
          UI States Gallery
        </div>

        <div className="flex">
          {STATE_OPTIONS.map((option, index) => (
            <button
              key={option.key}
              type="button"
              onClick={() => onStateChange(option.key)}
              className={`px-3 py-1.5 text-[11px] uppercase tracking-[0.15em] border transition-colors
                ${index > 0 ? "border-l-0" : ""}
                ${
                  activeState === option.key
                    ? "text-[#06b6d4] border-[#06b6d4] bg-[#06b6d4]/10"
                    : "text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5] hover:border-[#8a8a8a]"
                }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      <div className="border border-dashed border-[#262626] min-h-[180px] bg-black/10 px-6 py-8 flex items-center justify-center text-center">
        {activeState === "loading" ? (
          <StateLoading />
        ) : activeState === "empty" ? (
          <StateEmpty onCreate={onCreate} />
        ) : activeState === "error" ? (
          <StateError />
        ) : (
          <StateSuccess />
        )}
      </div>
    </div>
  );
}

function StateLoading() {
  return (
    <div className="max-w-[520px]">
      <div className="w-9 h-9 mx-auto mb-4 rounded-full border-2 border-[#06b6d4]/20 border-t-[#06b6d4] animate-spin" />
      <div className="text-sm tracking-[0.16em] uppercase text-[#f5f5f5] mb-2">
        Loading Users
      </div>
      <div className="text-[12px] tracking-[0.08em] uppercase text-[#8a8a8a] leading-relaxed">
        Placeholder for request in progress while dashboard shell remains
        stable.
      </div>
    </div>
  );
}

type StateEmptyProps = {
  onCreate: () => void;
};

function StateEmpty({ onCreate }: StateEmptyProps) {
  return (
    <div className="max-w-[520px]">
      <div className="w-[52px] h-[52px] mx-auto mb-4 border border-[#262626] text-[#8a8a8a] flex items-center justify-center text-lg">
        []
      </div>
      <div className="text-sm tracking-[0.16em] uppercase text-[#f5f5f5] mb-2">
        No Users Found
      </div>
      <div className="text-[12px] tracking-[0.08em] uppercase text-[#8a8a8a] leading-relaxed mb-4">
        Empty state prepared for clean deployment or filters without match.
      </div>
      <button
        type="button"
        onClick={onCreate}
        className="px-4 py-2 text-[12px] uppercase tracking-[0.15em] border border-[#06b6d4] text-[#06b6d4] hover:bg-[#06b6d4] hover:text-black transition-colors"
      >
        Create First User
      </button>
    </div>
  );
}

export function StateError({
  error,
  message,
}: {
  error?: string;
  message?: string;
}) {
  return (
    <div className="px-5 pt-4 pb-5 self-center border-t border-[#262626]">
      <div className="max-w-[520px]">
        <div className="w-[52px] h-[52px] mx-auto mb-4 border border-[#f43f5e]/40 text-[#f43f5e] flex items-center justify-center text-lg">
          !
        </div>
        <div className="text-sm tracking-[0.16em] uppercase text-[#f5f5f5] mb-2">
          {error || "Directory Unavailable"}
        </div>
        <div className="text-[12px] tracking-[0.08em] uppercase text-[#8a8a8a] leading-relaxed mb-4">
          {message || ""}
        </div>
      </div>
    </div>
  );
}

function StateSuccess() {
  return (
    <div className="max-w-[520px]">
      <div className="border border-dashed border-[#262626] min-h-[180px] bg-black/10 px-6 py-8 flex items-center justify-center text-center">
        <div className="w-[52px] h-[52px] mx-auto mb-4 border border-[#10b981]/40 text-[#10b981] flex items-center justify-center text-sm font-bold">
          OK
        </div>
        <div className="text-sm tracking-[0.16em] uppercase text-[#f5f5f5] mb-2">
          User Saved
        </div>
        <div className="text-[12px] tracking-[0.08em] uppercase text-[#8a8a8a] leading-relaxed">
          Success presentation for create and edit flow without changing screen
          structure.
        </div>
      </div>
    </div>
  );
}
