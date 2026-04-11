import { motion } from "framer-motion";
import Navbar from "../components/Navbar";

interface Connection {
  proto: string;
  src: string;
  sport: number;
  dst: string;
  dport: number;
  state: "ESTABLISHED" | "NEW" | "RELATED" | "INVALID";
}

const connections: Connection[] = [
  {
    proto: "TCP",
    src: "10.0.0.5",
    sport: 52341,
    dst: "8.8.8.8",
    dport: 443,
    state: "ESTABLISHED",
  },
  {
    proto: "TCP",
    src: "10.0.0.8",
    sport: 48201,
    dst: "1.1.1.1",
    dport: 80,
    state: "ESTABLISHED",
  },
  {
    proto: "UDP",
    src: "10.0.0.1",
    sport: 53,
    dst: "ANY",
    dport: 53,
    state: "NEW",
  },
  {
    proto: "TCP",
    src: "192.168.1.100",
    sport: 22,
    dst: "10.0.0.5",
    dport: 22,
    state: "INVALID",
  },
  {
    proto: "ICMP",
    src: "10.0.0.5",
    sport: 0,
    dst: "8.8.8.8",
    dport: 0,
    state: "RELATED",
  },
];

const stateColors = {
  ESTABLISHED: "text-[#10b981] bg-[#10b981]/10",
  NEW: "text-[#06b6d4] bg-[#06b6d4]/10",
  RELATED: "text-[#eab308] bg-[#eab308]/10",
  INVALID: "text-[#f43f5e] bg-[#f43f5e]/10",
};

export default function ConnectionTracking() {
  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <Navbar />

      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          {/* FLOW LINE */}
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── CONNECTION TRACKING ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* TIMELINE */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#161616] border border-[#262626] p-6 mb-6"
          >
            <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
              Connection Timeline
            </div>

            <div className="flex items-center justify-center gap-8">
              {/* NEW */}
              <div className="text-center">
                <div className="w-24 h-24 bg-[#06b6d4]/20 border border-[#06b6d4] rounded-full flex items-center justify-center">
                  <div>
                    <div className="text-xl">289</div>
                    <div className="text-xs text-[#06b6d4]">NEW</div>
                  </div>
                </div>
              </div>

              <span className="text-[#06b6d4]">────────►</span>

              {/* ESTABLISHED */}
              <div className="text-center">
                <div className="w-24 h-24 bg-[#10b981]/20 border border-[#10b981] rounded-full flex items-center justify-center">
                  <div>
                    <div className="text-xl">4,102</div>
                    <div className="text-xs text-[#10b981]">ESTAB</div>
                  </div>
                </div>
              </div>

              <span className="text-[#06b6d4]">────────►</span>

              {/* CLOSED */}
              <div className="text-center">
                <div className="w-24 h-24 bg-[#8a8a8a]/20 border border-[#8a8a8a] rounded-full flex items-center justify-center">
                  <div>
                    <div className="text-xl">127</div>
                    <div className="text-xs text-[#8a8a8a]">CLOSED</div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* FILTERS */}
          <div className="flex gap-4 mb-4 text-sm">
            <select className="bg-[#161616] border border-[#262626] px-4 py-2">
              <option>All States</option>
            </select>

            <select className="bg-[#161616] border border-[#262626] px-4 py-2">
              <option>All Protocols</option>
            </select>

            <select className="bg-[#161616] border border-[#262626] px-4 py-2">
              <option>Last 5 minutes</option>
            </select>

            <div className="flex-1" />

            <button className="px-4 py-2 border border-[#262626] text-[#8a8a8a] hover:text-white">
              REFRESH
            </button>

            <button className="px-4 py-2 border border-[#262626] text-[#8a8a8a] hover:text-white">
              EXPORT
            </button>
          </div>

          {/* TABLE */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-[#161616] border border-[#262626]"
          >
            <table className="w-full text-sm">
              <thead className="text-xs text-[#8a8a8a] border-b border-[#262626]">
                <tr>
                  <th className="text-left p-4">PROTO</th>
                  <th className="text-left p-4">SOURCE</th>
                  <th className="text-left p-4">SPORT</th>
                  <th className="text-left p-4">DEST</th>
                  <th className="text-left p-4">DPORT</th>
                  <th className="text-left p-4">STATE</th>
                </tr>
              </thead>

              <tbody>
                {connections.map((c, i) => (
                  <motion.tr
                    key={i}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.03 }}
                    className="border-b border-[#262626] hover:bg-[#202020]"
                  >
                    <td className="p-4 text-[#06b6d4]">{c.proto}</td>
                    <td className="p-4">{c.src}</td>
                    <td className="p-4 text-[#8a8a8a]">{c.sport}</td>
                    <td className="p-4">{c.dst}</td>
                    <td className="p-4 text-[#8a8a8a]">{c.dport}</td>
                    <td className="p-4">
                      <span
                        className={`px-3 py-1 text-xs ${stateColors[c.state]}`}
                      >
                        {c.state}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </motion.div>

          {/* FOOTER */}
          <div className="mt-10 text-center text-xs text-[#4a4a4a]">
            Connection tracking module
            <span className="text-[#06b6d4] mx-3">|</span>
            Live session monitoring
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}

