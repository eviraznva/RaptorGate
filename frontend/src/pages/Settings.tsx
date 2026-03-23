import { useState } from 'react';
import { motion } from 'framer-motion';

interface NetworkInterface {
  name: string;
  type: string;
  ip: string;
  mac: string;
  status: boolean;
}

const interfaces: NetworkInterface[] = [
  { name: 'enp0s8', type: 'MGMT', ip: '192.168.1.1/24', mac: 'AA:BB:CC:DD:EE:FF', status: true },
  { name: 'enp0s9', type: 'LAN', ip: '10.0.0.1/24', mac: 'AA:BB:CC:DD:EE:00', status: true },
  { name: 'enp0s10', type: 'DMZ', ip: '172.16.0.1/24', mac: 'AA:BB:CC:DD:EE:01', status: false },
  { name: 'enp0s11', type: 'WAN', ip: 'dhcp', mac: 'AA:BB:CC:DD:EE:02', status: true },
];

const navItems = ['DASHBOARD', 'TRAFFIC', 'RULES', 'CONNECTIONS', 'ALERTS', 'DNS', 'SETTINGS'];

export default function Settings() {
  const [activeNav, setActiveNav] = useState('SETTINGS');
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.72);
  const [confidenceReq, setConfidenceReq] = useState(0.85);

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
        <h1 className="text-xl text-[#f5f5f5] mb-6">SYSTEM SETTINGS</h1>

        {/* Network Interfaces */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-[#161616] border border-[#262626] p-6 mb-6"
        >
          <h3 className="text-sm text-[#f5f5f5] mb-4">NETWORK INTERFACES</h3>
          
          {/* Flow visualization */}
          <div className="flex items-center justify-center gap-2 mb-6">
            {interfaces.map((iface, i) => (
              <div key={iface.name} className="flex items-center">
                <div className={`border px-6 py-4 text-center ${iface.status ? 'border-[#10b981] bg-[#10b981]/10' : 'border-[#262626] bg-[#202020]'}`}>
                  <div className="text-[#f5f5f5]">{iface.name}</div>
                  <div className="text-xs text-[#8a8a8a] mt-1">({iface.type})</div>
                  <div className={`text-xs mt-1 ${iface.status ? 'text-[#10b981]' : 'text-[#4a4a4a]'}`}>
                    ● {iface.status ? 'UP' : 'DOWN'}
                  </div>
                </div>
                {i < interfaces.length - 1 && (
                  <span className="text-[#06b6d4] mx-2">────►</span>
                )}
              </div>
            ))}
          </div>

          {/* Interface details */}
          <div className="grid grid-cols-2 gap-4">
            {interfaces.map((iface) => (
              <motion.div
                key={iface.name}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="bg-[#202020] border border-[#262626] p-4"
              >
                <div className="flex justify-between items-center mb-2">
                  <span className="text-[#f5f5f5]">{iface.name} ({iface.type})</span>
                  <span className={`text-xs ${iface.status ? 'text-[#10b981]' : 'text-[#4a4a4a]'}`}>
                    ● {iface.status ? 'UP' : 'DOWN'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-[#8a8a8a]">IP: </span>
                    <span className="text-[#f5f5f5]">{iface.ip}</span>
                  </div>
                  <div>
                    <span className="text-[#8a8a8a]">MAC: </span>
                    <span className="text-[#f5f5f5]">{iface.mac}</span>
                  </div>
                </div>
                <div className="flex gap-2 mt-3">
                  <button className="px-3 py-1 text-xs border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5]">EDIT</button>
                  <button className="px-3 py-1 text-xs border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5]">DIAGNOSTICS</button>
                </div>
              </motion.div>
            ))}
          </div>

          <button className="w-full mt-4 py-2 border border-dashed border-[#262626] text-[#8a8a8a] hover:text-[#06b6d4] hover:border-[#06b6d4] transition-colors">
            + ADD INTERFACE
          </button>
        </motion.div>

        {/* Two columns */}
        <div className="grid grid-cols-2 gap-6">
          {/* ML Config */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <h3 className="text-sm text-[#f5f5f5] mb-4">ML MODEL CONFIGURATION</h3>
            
            <div className="space-y-6">
              <div>
                <div className="flex justify-between mb-2">
                  <label className="text-sm text-[#8a8a8a]">Anomaly Threshold</label>
                  <span className="text-sm text-[#06b6d4]">{anomalyThreshold.toFixed(2)}</span>
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
                  <label className="text-sm text-[#8a8a8a]">Confidence Required</label>
                  <span className="text-sm text-[#06b6d4]">{confidenceReq.toFixed(2)}</span>
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

              <div className="grid grid-cols-2 gap-4 pt-4 border-t border-[#262626] text-sm">
                <div>
                  <span className="text-[#8a8a8a]">Model Version</span>
                  <div className="text-[#f5f5f5] mt-1">v3.2.1</div>
                </div>
                <div>
                  <span className="text-[#8a8a8a]">Training</span>
                  <div className="text-[#f5f5f5] mt-1">2024-01-10</div>
                </div>
              </div>

              <div className="flex gap-2">
                <button className="flex-1 py-2 bg-[#06b6d4] text-[#0c0c0c] font-medium hover:bg-[#0891b2] transition-colors">
                  RETRAIN MODEL
                </button>
                <button className="flex-1 py-2 border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5] transition-colors">
                  EXPORT CONFIG
                </button>
              </div>
            </div>
          </motion.div>

          {/* System Maintenance */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[#161616] border border-[#262626] p-6"
          >
            <h3 className="text-sm text-[#f5f5f5] mb-4">SYSTEM MAINTENANCE</h3>
            
            <div className="space-y-4">
              <div className="flex justify-between py-3 border-b border-[#262626]">
                <span className="text-[#8a8a8a]">Version</span>
                <span className="text-[#f5f5f5]">v2.4.1</span>
              </div>
              <div className="flex justify-between py-3 border-b border-[#262626]">
                <span className="text-[#8a8a8a]">Uptime</span>
                <span className="text-[#f5f5f5]">14d 7h 32m</span>
              </div>
              <div className="flex justify-between py-3 border-b border-[#262626]">
                <span className="text-[#8a8a8a]">CPU</span>
                <span className="text-[#f5f5f5]">78%</span>
              </div>
              <div className="flex justify-between py-3 border-b border-[#262626]">
                <span className="text-[#8a8a8a]">Memory</span>
                <span className="text-[#f5f5f5]">65%</span>
              </div>
              <div className="flex justify-between py-3 border-b border-[#262626]">
                <span className="text-[#8a8a8a]">Disk</span>
                <span className="text-[#f5f5f5]">42% used</span>
              </div>

              <div className="flex gap-2 pt-4">
                <button className="flex-1 py-2 border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5] transition-colors">
                  BACKUP
                </button>
                <button className="flex-1 py-2 border border-[#262626] text-[#8a8a8a] hover:text-[#f5f5f5] transition-colors">
                  RESTORE
                </button>
                <button className="flex-1 py-2 bg-[#06b6d4] text-[#0c0c0c] font-medium hover:bg-[#0891b2] transition-colors">
                  UPDATE
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
}