import { useState } from "react"
import { motion } from "framer-motion"
import Navbar from "../components/Navbar"

export default function LoginPage() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [macStatus] = useState("AUTHORIZED")

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">

      <Navbar />

      <div className="flex-1 flex items-center justify-center p-8">

        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-xl"
        >

          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4]">
              ◄──────────────────────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* LOGO */}
          <div className="text-center mb-10">
            <h1 className="text-4xl tracking-[0.3em] font-light">
              RAPTORGATE
            </h1>

            <p className="text-[#8a8a8a] text-sm mt-3">
              Next-Generation Firewall
            </p>
          </div>

          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* INTERFACE VERIFICATION */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[#161616] border border-[#262626] p-6 mb-6"
          >
            <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
              Interface Verification
            </div>

            <div className="flex items-center gap-4 text-sm">

              <span className="text-[#06b6d4]">◄</span>

              <span>enp0s8 (MGMT)</span>

              <span className="text-[#06b6d4]">────</span>

              <span className="font-mono text-xs">
                AA:BB:CC:DD:EE:FF
              </span>

              <span className="text-[#06b6d4]">────</span>

              <span className="flex items-center gap-2 text-[#10b981]">
                <span className="w-2 h-2 rounded-full bg-[#10b981]" />
                {macStatus}
              </span>

              <span className="text-[#06b6d4]">►</span>

            </div>
          </motion.div>

          {/* LOGIN PANEL */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <div className="space-y-5">

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">
                  Username
                </div>

                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                />
              </div>

              <div>
                <div className="text-xs text-[#8a8a8a] mb-2">
                  Password
                </div>

                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
                />
              </div>

              <button
                className="w-full bg-[#06b6d4] text-black py-3 tracking-widest font-medium hover:bg-[#0891b2] transition"
              >
                AUTHENTICATE
              </button>

            </div>
          </motion.div>

          {/* FOOTER */}
          <div className="mt-6 text-center text-xs text-[#4a4a4a]">
            Version 2.4.1
            <span className="text-[#06b6d4] mx-3">|</span>
            Session timeout: 30 min
            <span className="text-[#06b6d4] mx-3">|</span>
            SSL: TLS 1.3
          </div>

        </motion.div>
      </div>

      {/* BOTTOM BAR */}
      <div className="bg-[#1e293b] text-[#94a3b8] text-xs px-6 py-2 flex justify-between">
        <span>
          Accent: <span className="text-[#06b6d4]">#06b6d4</span>
        </span>
        <span>Style: Flow visualization</span>
        <span>Click screen tabs to navigate</span>
      </div>

    </div>
  )
}