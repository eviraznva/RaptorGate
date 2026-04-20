import { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import { clearLoginData, setLoginData } from "../features/loginDataSlice";
import { useLoginMutation } from "../services/auth";
import { setUser } from "../features/userSlice";
import type { ApiFailure, ApiSuccess } from "../types/ApiResponse";
import type { LoginResponse } from "../types/authApi/LoginResponse";
import { LineArrow } from "../components/lineArrow/LineArrow";

export default function LoginPage() {
  const loginData = useAppSelector((state) => state.loginData);
  const dispatch = useAppDispatch();
  const [login, { isError }] = useLoginMutation();
  const [response, setResponse] = useState<ApiFailure>();
  const navigate = useNavigate();

  const handleLogin = async () => {
    try {
      const res = await login({
        username: loginData.username,
        password: loginData.password,
      }).unwrap();

      dispatch(
        setUser({
          ...(res as ApiSuccess<LoginResponse>).data,
        }),
      );

      navigate("/dashboard");
    } catch (err) {
      setResponse(err as ApiFailure);
    }

    dispatch(clearLoginData());
  };

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-xl"
        >
          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <LineArrow width={250} className="w-full" />
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* LOGO */}
          <div className="text-center mb-10">
            <h1 className="text-4xl tracking-[0.3em] font-light">RAPTORGATE</h1>

            <p className="text-[#8a8a8a] text-sm mt-3">
              Next-Generation Firewall
            </p>
          </div>

          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* LOGIN PANEL */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <div className="space-y-5">
              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">Username</div>

                <input
                  type="text"
                  value={loginData.username}
                  onChange={(e) =>
                    dispatch(
                      setLoginData({
                        ...loginData,
                        username: e.target.value,
                      }),
                    )
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                />
              </div>

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">Password</div>

                <input
                  type="password"
                  value={loginData.password}
                  onChange={(e) =>
                    dispatch(
                      setLoginData({
                        ...loginData,
                        password: e.target.value,
                      }),
                    )
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                />
              </div>
              {isError && (
                <p className="text-[#ef4444] text-xs mt-[0.1rem] mb-[0.55rem]">
                  {response?.message}
                </p>
              )}
              <button
                onClick={handleLogin}
                className="w-full bg-[#06b6d4] text-black py-3 tracking-widest font-medium hover:bg-[#0891b2] transition"
                type="button"
              >
                Login
              </button>
              <button
                onClick={() => navigate("/reset-password")}
                className="w-full border border-[#262626] py-3 text-sm tracking-[0.22em] text-[#8a8a8a] transition hover:border-[#06b6d4] hover:text-[#f5f5f5]"
                type="button"
              >
                Reset password
              </button>
            </div>
          </motion.div>

          {/* FOOTER */}
          <div className="mt-6 text-center text-xs text-[#4a4a4a]">
            Version: pre-alpha
            <span className="text-[#06b6d4] mx-3">|</span>
            Session timeout: 60 min
          </div>
        </motion.div>
      </div>
    </div>
  );
}
