import { useState } from "react"
import { motion } from "framer-motion"
import Navbar from "../components/Navbar"

interface NetworkInterface {
  name: string
  type: string
  ip: string
  mac: string
  status: boolean
}

const interfaces: NetworkInterface[] = [
  { name: "enp0s8", type: "MGMT", ip: "192.168.1.1/24", mac: "AA:BB:CC:DD:EE:FF", status: true },
  { name: "enp0s9", type: "LAN", ip: "10.0.0.1/24", mac: "AA:BB:CC:DD:EE:00", status: true },
  { name: "enp0s10", type: "DMZ", ip: "172.16.0.1/24", mac: "AA:BB:CC:DD:EE:01", status: false },
  { name: "enp0s11", type: "WAN", ip: "dhcp", mac: "AA:BB:CC:DD:EE:02", status: true },
]

export default function Settings() {
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.72)
  const [confidenceReq, setConfidenceReq] = useState(0.85)

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">

      <Navbar />

      <div className="flex-1 flex justify-center p-8">

        <div className="w-full max-w-6xl">

          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── SETTINGS ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* NETWORK INTERFACES */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#161616] border border-[#262626] p-6 mb-6"
          >
            <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
              Network Interfaces
            </div>

            {/* FLOW */}
            <div className="flex items-center justify-center gap-2 mb-6">
              {interfaces.map((iface, i) => (
                <div key={iface.name} className="flex items-center">
                  <div className={`border px-6 py-4 text-center ${
                    iface.status
                      ? "border-[#10b981] bg-[#10b981]/10"
                      : "border-[#262626] bg-[#202020]"
                  }`}>
                    <div>{iface.name}</div>
                    <div className="text-xs text-[#8a8a8a] mt-1">({iface.type})</div>
                    <div className={`text-xs mt-1 ${
                      iface.status ? "text-[#10b981]" : "text-[#4a4a4a]"
                    }`}>
                      ● {iface.status ? "UP" : "DOWN"}
                    </div>
                  </div>

                  {i < interfaces.length - 1 && (
                    <span className="text-[#06b6d4] mx-2">────►</span>
                  )}
                </div>
              ))}
            </div>

            {/* DETAILS */}
            <div className="grid grid-cols-2 gap-4">
              {interfaces.map((iface) => (
                <motion.div
                  key={iface.name}
                  className="bg-[#202020] border border-[#262626] p-4"
                >
                  <div className="flex justify-between mb-2">
                    <span>{iface.name} ({iface.type})</span>
                    <span className={`text-xs ${
                      iface.status ? "text-[#10b981]" : "text-[#4a4a4a]"
                    }`}>
                      ● {iface.status ? "UP" : "DOWN"}
                    </span>
                  </div>

                  <div className="text-xs text-[#8a8a8a]">
                    IP: <span className="text-white">{iface.ip}</span>
                  </div>
                  <div className="text-xs text-[#8a8a8a]">
                    MAC: <span className="text-white">{iface.mac}</span>
                  </div>
                </motion.div>
              ))}
            </div>

            <button className="w-full mt-4 py-2 border border-dashed border-[#262626] text-[#8a8a8a] hover:text-[#06b6d4] hover:border-[#06b6d4]">
              + ADD INTERFACE
            </button>
          </motion.div>

          {/* GRID */}
          <div className="grid grid-cols-2 gap-6">

            {/* ML CONFIG */}
            <motion.div className="bg-[#161616] border border-[#262626] p-6">

              <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
                ML Model Configuration
              </div>

              <div className="space-y-6">

                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-[#8a8a8a] text-sm">Anomaly Threshold</span>
                    <span className="text-[#06b6d4] text-sm">{anomalyThreshold.toFixed(2)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={anomalyThreshold}
                    onChange={(e) => setAnomalyThreshold(parseFloat(e.target.value))}
                    className="w-full accent-[#06b6d4]"
                  />
                </div>

                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-[#8a8a8a] text-sm">Confidence Required</span>
                    <span className="text-[#06b6d4] text-sm">{confidenceReq.toFixed(2)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={confidenceReq}
                    onChange={(e) => setConfidenceReq(parseFloat(e.target.value))}
                    className="w-full accent-[#06b6d4]"
                  />
                </div>

              </div>

            </motion.div>

            {/* SYSTEM */}
            <motion.div className="bg-[#161616] border border-[#262626] p-6">

              <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
                System Maintenance
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between border-b border-[#262626] py-2">
                  <span className="text-[#8a8a8a]">Version</span>
                  <span>v2.4.1</span>
                </div>
                <div className="flex justify-between border-b border-[#262626] py-2">
                  <span className="text-[#8a8a8a]">Uptime</span>
                  <span>14d 7h</span>
                </div>
                <div className="flex justify-between border-b border-[#262626] py-2">
                  <span className="text-[#8a8a8a]">CPU</span>
                  <span>78%</span>
                </div>
                <div className="flex justify-between border-b border-[#262626] py-2">
                  <span className="text-[#8a8a8a]">Memory</span>
                  <span>65%</span>
                </div>

                <button className="w-full mt-4 py-2 bg-[#06b6d4] text-black font-medium hover:bg-[#0891b2]">
                  UPDATE SYSTEM
                </button>
              </div>

            </motion.div>

          </div>

          {/* FOOTER */}
          <div className="mt-10 text-center text-xs text-[#4a4a4a]">
            Settings module
            <span className="text-[#06b6d4] mx-3">|</span>
            System configuration
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>

        </div>
      </div>

      {/* BOTTOM BAR */}
      <div className="bg-[#1e293b] text-[#94a3b8] text-xs px-6 py-2 flex justify-between">
        <span>Accent: <span className="text-[#06b6d4]">#06b6d4</span></span>
        <span>Style: Flow visualization</span>
        <span>Settings</span>
      </div>

    </div>
  )
}