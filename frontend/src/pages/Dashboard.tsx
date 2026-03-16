import { useState } from 'react';
import { motion } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer } from 'recharts';

const trafficData = Array.from({ length: 60 }, (_, i) => ({
  time: i,
  ingress: Math.floor(Math.random() * 1000000 + 500000),
  egress: Math.floor(Math.random() * 500000 + 200000),
}));

const navItems = ['DASHBOARD', 'TRAFFIC', 'RULES', 'CONNECTIONS', 'ALERTS', 'DNS', 'SETTINGS'];

const liveFeed = [
  { time: '14:32:01', src: '10.0.0.5', dst: '8.8.8.8:443', proto: 'TLS', dir: '→' },
  { time: '14:32:01', src: '10.0.0.8', dst: '1.1.1.1:80', proto: 'HTTP', dir: '→' },
  { time: '14:32:00', src: '10.0.0.1', dst: 'ext:53', proto: 'DNS', dir: '→' },
  { time: '14:32:00', src: 'ext', dst: '10.0.0.5:22', proto: 'SSH', dir: '←' },
  { time: '14:31:59', src: '10.0.0.3', dst: 'ext:22', proto: 'SSH', dir: '→' },
];

const alerts = [
  { level: 'CRITICAL', msg: 'Port scan detected', src: '192.168.1.1' },
  { level: 'HIGH', msg: 'DNS tunneling', src: 'internal' },
  { level: 'HIGH', msg: 'ML anomaly (94%)', src: '10.0.0.5' },
  { level: 'MEDIUM', msg: 'Unusual pattern', src: 'LAN' },
];

export default function Dashboard() {
  const [activeNav, setActiveNav] = useState('DASHBOARD');

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
          <div className="flex items-center gap-4 text-sm text-[#8a8a8a]">
            <span>admin@MGMT</span>
            <span className="text-[#06b6d4]">│</span>
            <button className="hover:text-[#f5f5f5]">⚙</button>
            <button className="hover:text-[#f5f5f5] relative">
              🔔
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-[#f43f5e] rounded-full" />
            </button>
            <button className="hover:text-[#f5f5f5]">⏻</button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 p-6 overflow-auto">
        {/* Flow Indicator */}
        <div className="text-center mb-6 text-xs text-[#4a4a4a]">
          <span className="text-[#06b6d4]">◄</span> INGRESS ──────────────────────────────────────── EGRESS <span className="text-[#06b6d4]">►</span>
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <div className="flex items-center gap-2 text-xs text-[#8a8a8a] mb-2">
              <span className="text-[#06b6d4]">▼</span> PACKETS/SECOND
            </div>
            <div className="text-3xl font-light text-[#f5f5f5]">1,247,832</div>
            <div className="text-sm text-[#10b981] mt-1">▲ 12.3%</div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <div className="flex items-center gap-2 text-xs text-[#8a8a8a] mb-2">
              <span className="text-[#06b6d4]">▼</span> THROUGHPUT
            </div>
            <div className="text-3xl font-light text-[#f5f5f5]">892 MB/s</div>
            <div className="text-sm text-[#10b981] mt-1">▲ 5.2%</div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <div className="flex items-center gap-2 text-xs text-[#8a8a8a] mb-2">
              <span className="text-[#06b6d4]">▼</span> CONNECTIONS
            </div>
            <div className="text-3xl font-light text-[#f5f5f5]">4,521</div>
            <div className="text-sm text-[#f43f5e] mt-1">▼ 2.1%</div>
          </motion.div>
        </div>

        {/* Traffic Chart */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-[#161616] border border-[#262626] p-6 mb-6"
        >
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm text-[#f5f5f5]">TRAFFIC FLOW - 60 MINUTES</h3>
            <div className="flex gap-4 text-xs">
              <span className="flex items-center gap-2">
                <span className="w-4 h-0.5 bg-[#06b6d4]" /> INGRESS (incoming)
              </span>
              <span className="flex items-center gap-2 text-[#8a8a8a]">
                <span className="w-4 h-0.5 bg-[#8a8a8a] border-dashed" /> EGRESS (outgoing)
              </span>
            </div>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <XAxis dataKey="time" stroke="#4a4a4a" fontSize={10} />
                <YAxis stroke="#4a4a4a" fontSize={10} />
                <Area type="monotone" dataKey="ingress" stroke="#06b6d4" fill="#06b6d420" strokeWidth={2} />
                <Area type="monotone" dataKey="egress" stroke="#8a8a8a" fill="transparent" strokeDasharray="5 5" strokeWidth={1} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Two Columns */}
        <div className="grid grid-cols-2 gap-6">
          {/* Live Traffic */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-[#161616] border border-[#262626] p-4"
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="text-[#06b6d4]">◄</span>
              <h3 className="text-sm text-[#f5f5f5]">TRAFFIC FLOW</h3>
              <span className="flex-1" />
              <span className="text-[#06b6d4]">►</span>
            </div>
            <div className="space-y-2 text-xs">
              {liveFeed.map((item, i) => (
                <div key={i} className="flex items-center gap-2 text-[#f5f5f5]">
                  <span className="text-[#4a4a4a]">{item.time}</span>
                  <span className="text-[#06b6d4]">{item.dir}</span>
                  <span>{item.src}</span>
                  <span className="text-[#8a8a8a]">────</span>
                  <span>{item.dst}</span>
                  <span className="text-[#06b6d4] ml-auto">{item.proto}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 text-[#4a4a4a] text-xs">▓▓▓ LIVE STREAM ◄──────────────────────────►</div>
          </motion.div>

          {/* Alerts */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-[#161616] border border-[#262626] p-4"
          >
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-sm text-[#f5f5f5]">ALERTS</h3>
              <span className="flex-1" />
              <span className="text-[#06b6d4]">──────────────────────────►</span>
            </div>
            <div className="space-y-3">
              {alerts.map((alert, i) => (
                <div key={i} className="border-l-2 border-[#f43f5e] pl-3">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium ${
                      alert.level === 'CRITICAL' ? 'text-[#f43f5e]' : 'text-[#f97316]'
                    }`}>
                      ⚠ {alert.level}
                    </span>
                    <span className="text-[#f5f5f5] text-sm">{alert.msg}</span>
                  </div>
                  <div className="text-xs text-[#8a8a8a] mt-1">from {alert.src}</div>
                </div>
              ))}
            </div>
            <button className="w-full mt-4 text-center text-xs text-[#8a8a8a] hover:text-[#06b6d4] transition-colors">
              VIEW ALL ────────────────►
            </button>
          </motion.div>
        </div>
      </main>
    </div>
  );
}