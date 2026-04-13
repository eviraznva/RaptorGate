import { useNavigate } from "react-router-dom";
import { LineArrow } from "../components/lineArrow/LineArrow";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import { useEffect, useState } from "react";
import {
  setNewPassword,
  setRecoveryToken,
  setUsername,
} from "../features/resetPasswordSlice";
import { useResetPasswordMutation } from "../services/auth";
import type { ApiFailure } from "../types/ApiResponse";

export default function ResetPasswordPage() {
  const navigate = useNavigate();

  const dispatch = useAppDispatch();
  const resetPasswordData = useAppSelector((state) => state.resetPassword);

  const [confirmPassword, setConfirmPassword] = useState("");
  const [response, setResponse] = useState<ApiFailure>();

  const [resetPassword, { isError, isSuccess }] = useResetPasswordMutation();

  const handleResetPassword = async function () {
    try {
      await resetPassword(resetPasswordData).unwrap();
    } catch (err) {
      setResponse(err as ApiFailure);
    }
  };

  useEffect(() => {
    if (isSuccess) {
      navigate("/login", { replace: true });
    }
  }, [isSuccess, navigate]);

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-xl">
          {/**/}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <LineArrow width={250} className="w-full" />
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* LOGO */}
          <div className="text-center mb-10">
            <h1 className="text-4xl tracking-[0.3em] font-light">RAPTORGATE</h1>

            <p className="text-[#8a8a8a] text-sm mt-3">Reset Password</p>
          </div>
          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* RESET PANEL */}
          <div className="bg-[#161616] border border-[#262626] p-6">
            <div className="space-y-5">
              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">Username</div>

                <input
                  type="text"
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                  value={resetPasswordData.username}
                  placeholder="jankowal"
                  onChange={(e) => {
                    dispatch(setUsername(e.target.value));
                  }}
                />
              </div>

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">
                  Recovery token
                </div>

                <textarea
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4] min-h-[120px] resize-none font-mono text-sm"
                  placeholder="a3f9c1e7d4b2f0a8c6e4d2b0a9f7e5c3a1b9d7f5e3c1a8b6d4f2e0c8a6b4d2f0"
                  value={resetPasswordData.recoveryToken}
                  onChange={(e) => {
                    dispatch(setRecoveryToken(e.target.value));
                  }}
                />
              </div>

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">New password</div>

                <input
                  type="password"
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                  placeholder="StrongPass123!"
                  value={resetPasswordData.newPassword}
                  onChange={(e) => {
                    dispatch(setNewPassword(e.target.value));
                  }}
                />
              </div>

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">
                  Confirm new password
                </div>

                <input
                  type="password"
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                  placeholder="Repeat new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
              </div>
              {isError && (
                <p className="text-[#ef4444] text-xs mt-[0.1rem] mb-[0.55rem]">
                  {response?.message}
                </p>
              )}
              <button
                className={`${confirmPassword !== resetPasswordData.newPassword ? "cursor-not-allowed" : "cursor-pointer"} w-full bg-[#06b6d4] text-black py-3 tracking-widest font-medium hover:bg-[#0891b2] transition`}
                type="button"
                disabled={confirmPassword !== resetPasswordData.newPassword}
                onClick={handleResetPassword}
              >
                Reset password
              </button>

              <button
                onClick={() => navigate("/login")}
                className="w-full border border-[#262626] py-3 text-sm tracking-[0.22em] text-[#8a8a8a] transition hover:border-[#06b6d4] hover:text-[#f5f5f5]"
                type="button"
              >
                Back to login
              </button>
            </div>
          </div>

          {/* FOOTER */}
          <div className="mt-6 text-center text-xs text-[#4a4a4a]">
            Version: pre-alpha
            <span className="text-[#06b6d4] mx-3">|</span>
            Session timeout: 60 min
          </div>
        </div>
      </div>
    </div>
  );
}
