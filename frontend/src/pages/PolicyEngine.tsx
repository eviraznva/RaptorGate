import { motion } from "framer-motion";
import { LineArrow } from "../components/lineArrow/LineArrow";

interface Rule {
  id: number;
  priority: number;
  name: string;
  source: string;
  dest: string;
  service: string;
  action: "ALLOW" | "DROP" | "REJECT" | "LOG";
  status: boolean;
}

const rules: Rule[] = [
  {
    id: 1,
    priority: 100,
    name: "mgmt_ssh",
    source: "MGMT",
    dest: "LOCAL",
    service: "TCP/22",
    action: "ALLOW",
    status: true,
  },
  {
    id: 2,
    priority: 200,
    name: "lan_wan",
    source: "LAN",
    dest: "WAN",
    service: "ANY",
    action: "ALLOW",
    status: true,
  },
  {
    id: 3,
    priority: 300,
    name: "dmz_http",
    source: "WAN",
    dest: "DMZ",
    service: "TCP/80",
    action: "ALLOW",
    status: true,
  },
  {
    id: 4,
    priority: 400,
    name: "block_all",
    source: "ANY",
    dest: "ANY",
    service: "ANY",
    action: "DROP",
    status: true,
  },
  {
    id: 5,
    priority: 500,
    name: "log_ssh",
    source: "ANY",
    dest: "ANY",
    service: "TCP/22",
    action: "LOG",
    status: false,
  },
];

const actionStyles = {
  ALLOW: "text-[#10b981]",
  DROP: "text-[#f43f5e]",
  REJECT: "text-[#f43f5e]",
  LOG: "text-[#eab308]",
};

export default function PolicyEngine() {
  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          {/* FLOW LINE */}
          <div className="flex items-center justify-center relative mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              <h3 className="text-center absolute right-0 bottom-2 w-full">
                Plicy Engine
              </h3>
              <LineArrow />
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          {/* ZONE FLOW */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#161616] border border-[#262626] p-6 mb-6"
          >
            <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
              Zone Flow Diagram
            </div>

            <div className="flex items-center justify-center gap-4">
              {["MGMT", "LAN", "DMZ", "WAN"].map((zone, i) => (
                <div key={zone} className="flex items-center">
                  <div className="bg-[#202020] border border-[#262626] px-6 py-4 text-center">
                    <div>{zone}</div>
                    <div className="text-xs text-[#8a8a8a] mt-1">Zone</div>
                  </div>

                  {i < 3 && <div className="mx-2 text-[#06b6d4]">───►</div>}
                </div>
              ))}
            </div>
          </motion.div>

          {/* HEADER */}
          <div className="flex justify-between items-center mb-4">
            <div className="text-sm">RULE LIST</div>

            <button className="px-4 py-2 bg-[#06b6d4] text-black text-sm font-medium hover:bg-[#0891b2] transition">
              + NEW RULE
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
                  <th className="text-left p-4">PRIORITY</th>
                  <th className="text-left p-4">RULE NAME</th>
                  <th className="text-left p-4">SOURCE</th>
                  <th className="text-left p-4">DEST</th>
                  <th className="text-left p-4">SERVICE</th>
                  <th className="text-left p-4">ACTION</th>
                  <th className="text-left p-4">STATUS</th>
                </tr>
              </thead>

              <tbody>
                {rules.map((rule, i) => (
                  <motion.tr
                    key={rule.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.05 }}
                    className="border-b border-[#262626] hover:bg-[#202020]"
                  >
                    <td className="p-4 text-[#06b6d4]">{rule.priority}</td>
                    <td className="p-4">{rule.name}</td>
                    <td className="p-4 text-[#8a8a8a]">{rule.source}</td>
                    <td className="p-4 text-[#8a8a8a]">{rule.dest}</td>
                    <td className="p-4 text-[#8a8a8a]">{rule.service}</td>
                    <td className={`p-4 ${actionStyles[rule.action]}`}>
                      {rule.action}
                    </td>
                    <td className="p-4">
                      <span
                        className={`flex items-center gap-2 text-xs ${
                          rule.status ? "text-[#10b981]" : "text-[#4a4a4a]"
                        }`}
                      >
                        <span
                          className={`w-2 h-2 rounded-full ${
                            rule.status ? "bg-[#10b981]" : "bg-[#4a4a4a]"
                          }`}
                        />
                        {rule.status ? "Active" : "Inactive"}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </motion.div>

          {/* FOOTER */}
          <div className="mt-10 text-center text-xs text-[#4a4a4a]">
            Policy engine module
            <span className="text-[#06b6d4] mx-3">|</span>
            Rule processing pipeline
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}
