type ToggleProps = {
  label: string;
  checked: boolean;
  onToggle: (next: boolean) => void;
};

export default function Toggle({ label, checked, onToggle }: ToggleProps) {
  return (
    <div className="flex items-center justify-between border border-[#262626] bg-[#101010] px-4 py-3">
      <span className="text-sm">{label}</span>
      <button
        type="button"
        onClick={() => onToggle(!checked)}
        className={`relative h-6 w-12 rounded-full border transition ${
          checked
            ? "border-[#06b6d4] bg-[#06b6d4]/20"
            : "border-[#3a3a3a] bg-[#1c1c1c]"
        }`}
      >
        <span
          className={`absolute top-[1px] h-4 w-4 rounded-full bg-[#f5f5f5] transition ${
            checked ? "left-[26px]" : "left-[3px]"
          }`}
        />
      </button>
    </div>
  );
}

