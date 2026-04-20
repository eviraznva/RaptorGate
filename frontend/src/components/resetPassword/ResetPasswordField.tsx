type ResetPasswordFieldProps = {
  label: string;
  placeholder: string;
  type?: string;
  as?: "input" | "textarea";
};

export function ResetPasswordField({
  label,
  placeholder,
  type = "text",
  as = "input",
}: ResetPasswordFieldProps) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs text-[#8a8a8a]">{label}</span>

      {as === "textarea" ? (
        <textarea
          placeholder={placeholder}
          className="min-h-[132px] w-full resize-none border border-[#262626] bg-[#0c0c0c] px-4 py-3 font-mono text-sm leading-7 tracking-[0.08em] text-[#06b6d4] outline-none transition placeholder:text-[#3f3f3f] focus:border-[#06b6d4]"
        />
      ) : (
        <input
          type={type}
          placeholder={placeholder}
          className="w-full border border-[#262626] bg-[#0c0c0c] px-4 py-3 text-white outline-none transition placeholder:text-[#3f3f3f] focus:border-[#06b6d4]"
        />
      )}
    </label>
  );
}