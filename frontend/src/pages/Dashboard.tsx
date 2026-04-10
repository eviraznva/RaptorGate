import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer } from "recharts";
import Navbar from "../components/Navbar";

const trafficData = Array.from({ length: 60 }, (_, i) => ({
  time: i,
  ingress: Math.floor(Math.random() * 1000000 + 500000),
  egress: Math.floor(Math.random() * 500000 + 200000),
}));

const liveFeed = [
  {
    time: "14:32:01",
    src: "10.0.0.5",
    dst: "8.8.8.8:443",
    proto: "TLS",
    dir: "→",
  },
  {
    time: "14:32:01",
    src: "10.0.0.8",
    dst: "1.1.1.1:80",
    proto: "HTTP",
    dir: "→",
  },
  { time: "14:32:00", src: "10.0.0.1", dst: "ext:53", proto: "DNS", dir: "→" },
  { time: "14:32:00", src: "ext", dst: "10.0.0.5:22", proto: "SSH", dir: "←" },
  { time: "14:31:59", src: "10.0.0.3", dst: "ext:22", proto: "SSH", dir: "→" },
];

const alerts = [
  { level: "CRITICAL", msg: "Port scan detected", src: "192.168.1.1" },
  { level: "HIGH", msg: "DNS tunneling", src: "internal" },
  { level: "HIGH", msg: "ML anomaly (94%)", src: "10.0.0.5" },
  { level: "MEDIUM", msg: "Unusual pattern", src: "LAN" },
];

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <Navbar />

      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── INGRESS ──────────── EGRESS ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* METRICS */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <motion.div className="bg-[#161616] border border-[#262626] p-6">
              <div className="text-xs text-[#8a8a8a] mb-2 uppercase tracking-widest">
                Packets/Second
              </div>
              <div className="text-3xl font-light">1,247,832</div>
              <div className="text-[#10b981] text-sm mt-1">▲ 12.3%</div>
            </motion.div>

            <motion.div className="bg-[#161616] border border-[#262626] p-6">
              <div className="text-xs text-[#8a8a8a] mb-2 uppercase tracking-widest">
                Throughput
              </div>
              <div className="text-3xl font-light">892 MB/s</div>
              <div className="text-[#10b981] text-sm mt-1">▲ 5.2%</div>
            </motion.div>

            <motion.div className="bg-[#161616] border border-[#262626] p-6">
              <div className="text-xs text-[#8a8a8a] mb-2 uppercase tracking-widest">
                Connections
              </div>
              <div className="text-3xl font-light">4,521</div>
              <div className="text-[#f43f5e] text-sm mt-1">▼ 2.1%</div>
            </motion.div>
          </div>

          {/* CHART */}
          <motion.div className="bg-[#161616] border border-[#262626] p-6 mb-6">
            <div className="flex justify-between mb-4 text-sm">
              <span>TRAFFIC FLOW - 60 MINUTES</span>
              <span className="text-[#8a8a8a]">INGRESS / EGRESS</span>
            </div>

            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficData}>
                  <XAxis dataKey="time" stroke="#4a4a4a" />
                  <YAxis stroke="#4a4a4a" />
                  <Area dataKey="ingress" stroke="#06b6d4" fill="#06b6d420" />
                  <Area
                    dataKey="egress"
                    stroke="#8a8a8a"
                    strokeDasharray="5 5"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {/* BOTTOM GRID */}
          <div className="grid grid-cols-2 gap-6">
            {/* TRAFFIC FLOW */}
            <motion.div className="bg-[#161616] border border-[#262626] p-4">
              <div className="flex items-center mb-4 text-sm">
                <span className="text-[#06b6d4] mr-2">◄</span>
                TRAFFIC FLOW
                <span className="ml-auto text-[#06b6d4]">►</span>
              </div>

              <div className="space-y-2 text-xs">
                {liveFeed.map((item, i) => (
                  <div key={i} className="flex items-center">
                    <span className="text-[#4a4a4a] w-16">{item.time}</span>
                    <span>{item.src}</span>
                    <span className="mx-2 text-[#06b6d4]">{item.dir}</span>
                    <span>{item.dst}</span>
                    <span className="ml-auto text-[#06b6d4]">{item.proto}</span>
                  </div>
                ))}
              </div>

              <div className="mt-4 text-[#4a4a4a] text-xs">
                ▓▓▓ LIVE STREAM ◄──────────────►
              </div>
            </motion.div>

            {/* ALERTS */}
            <motion.div className="bg-[#161616] border border-[#262626] p-4">
              <div className="flex items-center mb-4 text-sm">
                ALERTS
                <span className="ml-auto text-[#06b6d4]">──────────────►</span>
              </div>

              <div className="space-y-3">
                {alerts.map((a, i) => (
                  <div key={i} className="border-l-2 border-[#f43f5e] pl-3">
                    <div className="text-sm">
                      ⚠ {a.level} — {a.msg}
                    </div>
                    <div className="text-xs text-[#8a8a8a]">from {a.src}</div>
                  </div>
                ))}
              </div>

              <div className="mt-4 text-xs text-[#8a8a8a] text-center hover:text-[#06b6d4] cursor-pointer">
                VIEW ALL ─────────►
              </div>
            </motion.div>
          </div>

          {/* FOOTER (jak w login) */}
          <div className="mt-10 text-center text-xs text-[#4a4a4a]">
            Dashboard module
            <span className="text-[#06b6d4] mx-3">|</span>
            Live traffic monitoring
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}

