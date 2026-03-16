import { useState } from 'react';
import { motion } from 'framer-motion';

interface Connection {
  proto: string;
  src: string;
  sport: number;
  dst: string;
  dport: number;
  state: 'ESTABLISHED' | 'NEW' | 'RELATED' | 'INVALID';
}

const connections: Connection[] = [
  { proto: 'TCP', src: '10.0.0.5', sport: 52341, dst: '8.8.8.8', dport: 443, state: 'ESTABLISHED' },
  { proto: 'TCP', src: '10.0.0.8', sport: 48201, dst: '1.1.1.1', dport: 80, state: 'ESTABLISHED' },
  { proto: 'UDP', src: '10.0.0.1', sport: 53, dst: 'ANY', dport: 53, state: 'NEW' },
  { proto: 'TCP', src: '192.168.1.100', sport: 22, dst: '10.0.0.5', dport: 22, state: 'INVALID' },
  { proto: 'ICMP', src: '10.0.0.5', sport: 0, dst: '8.8.8.8', dport: 0, state: 'RELATED' },
];

const stateColors = {
  ESTABLISHED: 'text-[#10b981] bg-[#10b981]/10',
  NEW: 'text-[#06b6d4] bg-[#06b6d4]/10',
  RELATED: 'text-[#eab308] bg-[#eab308]/10',
  INVALID: 'text-[#f43f5e] bg-[#f43f5e]/10',
};

const navItems = ['DASHBOARD', 'TRAFFIC', 'RULES', 'CONNECTIONS', 'ALERTS', 'DNS', 'SETTINGS'];

export default function ConnectionTracking() {
  const [activeNav, setActiveNav] = useState('CONNECTIONS');

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col">
      {/* Navigation */}
      <nav className="bg-[#161616] border-b border-[#262626] px-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1">
            {navItems.map((item, i) => (
              <div key={item} className="flex items-center">
                <button
                  onClick={() => setActiveNav(item)}
                  className={`px-4 py-4 text-sm transition-colors ${
                    activeNav === item
                      ? 'text-[#06b6d4] border-b-2 border-[#06b6d4]'
                      : 'text-[#8a8a8a] hover:text-[#f5f5f5]'
                  }`}
                >
                  {item}
                </button>
                {i < navItems.length - 1 && (
                  <span className="text-[#262626] mx-1">│</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 p-6 overflow-auto">
        <h1 className="text-xl text-[#f5f5f5] mb-6">CONNECTION TRACKING: Active Network Flows</h1>

        {/* Connection Timeline */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-[#161616] border border-[#262626] p-6 mb-6"
        >
          <h3 className="text-sm text-[#f5f5f5] mb-4">CONNECTION TIMELINE</h3>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs text-[#8a8a8a]">14:30</span>
            <div className="flex-1 h-px bg-[#262626] mx-4" />
            <span className="text-xs text-[#8a8a8a]">14:32</span>
          </div>
          <div className="flex items-center justify-center gap-8">
            <div className="text-center">
              <div className="w-24 h-24 bg-[#06b6d4]/20 border border-[#06b6d4] rounded-full flex items-center justify-center">
                <div>
                  <div className="text-2xl text-[#f5f5f5]">289</div>
                  <div className="text-xs text-[#06b6d4]">NEW</div>
                </div>
              </div>
            </div>
            <div className="flex items-center">
              <span className="text-[#06b6d4]">──────────────►</span>
            </div>
            <div className="text-center">
              <div className="w-24 h-24 bg-[#10b981]/20 border border-[#10b981] rounded-full flex items-center justify-center">
                <div>
                  <div className="text-2xl text-[#f5f5f5]">4,102</div>
                  <div className="text-xs text-[#10b981]">ESTAB</div>
                </div>
              </div>
            </div>
            <div className="flex items-center">
              <span className="text-[#06b6d4]">──────────────►</span>
            </div>
            <div className="text-center">
              <div className="w-24 h-24 bg-[#8a8a8a]/20 border border-[#8a8a8a] rounded-full flex items-center justify-center">
                <div>
                  <div className="text-2xl text-[#f5f5f5]">127</div>
                  <div className="text-xs text-[#8a8a8a]">CLOSED</div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Filters */}
        <div className="flex gap-4 mb-4">
          <select className="bg-[#161616] border border-[#262626] px-4 py-2 text-[#f5f5f5] text-sm">
            <option>All States</option>
            <option>ESTABLISHED</option>
            <option>NEW</option>
            <option>RELATED</option>
            <option>INVALID</option>
          </select>
          <select className="bg-[#161616] border border-[#262626] px-4 py-2 text-[#f5f5f5] text-sm">
            <option>All Protocols</option>
            <option>TCP</option>
            <option>UDP</option>
            <option>ICMP</option>
          </select>
          <select className="bg-[#161616] border border-[#262626] px-4 py-2 text-[#f5f5f5] text-sm">
            <option>Last 5 minutes</option>
          </select>
          <div className="flex-1" />
          <button className="px-4 py-2 border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5] text-sm">REFRESH</button>
          <button className="px-4 py-2 border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5] text-sm">EXPORT</button>
        </div>

        {/* Flow Table */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-[#161616] border border-[#262626]"
        >
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#262626] text-xs text-[#8a8a8a]">
                <th className="text-left p-4">PROTOCOL</th>
                <th className="text-left p-4">SOURCE</th>
                <th className="text-left p-4">SRC PORT</th>
                <th className="text-left p-4">DESTINATION</th>
                <th className="text-left p-4">DST PORT</th>
                <th className="text-left p-4">STATE</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((conn, i) => (
                <motion.tr
                  key={i}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.02 }}
                  className="border-b border-[#262626] hover:bg-[#202020] cursor-pointer"
                >
                  <td className="p-4">
                    <span className="flex items-center gap-2">
                      <span className="text-[#06b6d4]">──►</span>
                      <span className="text-[#f5f5f5]">{conn.proto}</span>
                    </span>
                  </td>
                  <td className="p-4 text-[#f5f5f5]">{conn.src}</td>
                  <td className="p-4 text-[#8a8a8a]">{conn.sport}</td>
                  <td className="p-4 text-[#f5f5f5]">{conn.dst}</td>
                  <td className="p-4 text-[#8a8a8a]">{conn.dport} ◄──</td>
                  <td className="p-4">
                    <span className={`px-3 py-1 text-xs ${stateColors[conn.state]}`}>
                      {conn.state}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        {/* Stats */}
        <div className="mt-4 text-sm text-[#8a8a8a]">
          Total: <span className="text-[#f5f5f5]">4,521</span> │ ESTABLISHED: <span className="text-[#10b981]">4,102</span> │ NEW: <span className="text-[#06b6d4]">289</span> │ INVALID: <span className="text-[#f43f5e]">12</span>
        </div>
      </main>
    </div>
  );
}