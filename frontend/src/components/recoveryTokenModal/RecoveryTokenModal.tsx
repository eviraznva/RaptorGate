import { useState, useEffect } from "react";
import { Icon } from "@iconify/react";

type RecoveryTokenModalProps = {
  token: string;
  onConfirm: () => void;
};

export const RecoveryTokenModal = ({
  token,
  onConfirm,
}: RecoveryTokenModalProps) => {
  const [copied, setCopied] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy", err);
    }
  };

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 transition-all duration-300 ${
        mounted ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-[#0c0c0c]/90 backdrop-blur-sm" />

      {/* Modal */}
      <div
        className={`relative w-full max-w-lg transition-all duration-300 ${
          mounted ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0"
        }`}
      >
        {/* Glowing border effect */}
        <div className="absolute -inset-px bg-gradient-to-b from-[#06b6d4]/40 to-transparent pointer-events-none" />

        <div className="relative bg-[#0e0e0e] border border-[#06b6d4]/30">
          {/* Header bar */}
          <div className="flex items-center justify-center border-b border-[#262626] px-5 py-3">
            <div className="flex items-center gap-1.5">
              <span className="text-[#f43f5e] text-xs text-center tracking-widest uppercase">
                one-time display
              </span>
            </div>
          </div>

          {/* Body */}
          <div className="px-6 pt-8 pb-6">
            {/* Icon + title */}
            <div className="flex flex-col items-center text-center mb-7">
              <h2 className="text-base tracking-[0.2em] uppercase font-light text-[#f5f5f5] mb-2">
                Recovery Token Generated
              </h2>
              <p className="text-xs text-[#8a8a8a] leading-relaxed max-w-sm">
                Store this token in a secure location. It will not be shown
                again and is required to recover access to your account.
              </p>
            </div>

            {/* Divider */}
            <div className="flex items-center gap-3 mb-6">
              <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#262626] to-transparent" />
              <span className="text-[#4a4a4a] text-[10px] tracking-widest uppercase">
                token
              </span>
              <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#262626] to-transparent" />
            </div>

            {/* Token display */}
            <div className="relative mb-6">
              <div className="bg-[#0c0c0c] border border-[#262626] px-4 py-4 pr-14">
                <p className="text-[#06b6d4] text-sm break-all leading-relaxed tracking-wider font-mono">
                  {token}
                </p>
              </div>

              {/* Copy button */}
              <button
                onClick={handleCopy}
                className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 text-[#4a4a4a] hover:text-[#06b6d4] transition-colors"
                title="Copy token"
              >
                <Icon
                  icon={copied ? "lucide:check" : "lucide:copy"}
                  width={16}
                  height={16}
                  className={copied ? "text-[#10b981]" : ""}
                />
              </button>
            </div>

            {/* Copy feedback */}
            <div
              className={`flex items-center gap-2 mb-6 transition-opacity duration-200 ${
                copied ? "opacity-100" : "opacity-0"
              }`}
            >
              <Icon
                icon="lucide:check-circle"
                width={12}
                height={12}
                className="text-[#10b981]"
              />
              <span className="text-[10px] text-[#10b981] tracking-widest uppercase">
                Copied to clipboard
              </span>
            </div>

            {/* Warning notice */}
            <div className="flex gap-3 bg-[#f43f5e]/5 border border-[#f43f5e]/20 px-4 py-3 mb-7">
              <Icon
                icon="lucide:triangle-alert"
                width={14}
                height={14}
                className="text-[#f43f5e] mt-0.5 shrink-0"
              />
              <p className="text-xs text-[#8a8a8a] leading-relaxed">
                This token provides full account recovery access. Treat it like
                a password — do not share it or store it in plaintext.
              </p>
            </div>

            {/* Confirm button */}
            <button
              onClick={onConfirm}
              className="w-full bg-[#06b6d4] text-black py-3 tracking-widest text-sm font-medium hover:bg-[#0891b2] transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
