import { useState } from 'react';
import { motion } from 'framer-motion';

interface Rule {
  id: number;
  priority: number;
  name: string;
  source: string;
  dest: string;
  service: string;
  action: 'ALLOW' | 'DROP' | 'REJECT' | 'LOG';
  status: boolean;
}

const rules: Rule[] = [
  { id: 1, priority: 100, name: 'mgmt_ssh', source: 'MGMT', dest: 'LOCAL', service: 'TCP/22', action: 'ALLOW', status: true },
  { id: 2, priority: 200, name: 'lan_wan', source: 'LAN', dest: 'WAN', service: 'ANY', action: 'ALLOW', status: true },
  { id: 3, priority: 300, name: 'dmz_http', source: 'WAN', dest: 'DMZ', service: 'TCP/80', action: 'ALLOW', status: true },
  { id: 4, priority: 400, name: 'block_all', source: 'ANY', dest: 'ANY', service: 'ANY', action: 'DROP', status: true },
  { id: 5, priority: 500, name: 'log_ssh', source: 'ANY', dest: 'ANY', service: 'TCP/22', action: 'LOG', status: false },
];

const actionStyles = {
  ALLOW: 'text-[#10b981]',
  DROP: 'text-[#f43f5e]',
  REJECT: 'text-[#f43f5e]',
  LOG: 'text-[#eab308]',
};

const navItems = ['DASHBOARD', 'TRAFFIC', 'RULES', 'CONNECTIONS', 'ALERTS', 'DNS', 'SETTINGS'];

export default function PolicyEngine() {
  const [activeNav, setActiveNav] = useState('RULES');

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
        {/* Zone Flow Diagram */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-[#161616] border border-[#262626] p-6 mb-6"
        >
          <h3 className="text-sm text-[#f5f5f5] mb-4">ZONE FLOW DIAGRAM</h3>
          <div className="flex items-center justify-center gap-4">
            {['MGMT', 'LAN', 'DMZ', 'WAN'].map((zone, i) => (
              <div key={zone} className="flex items-center">
                <div className="bg-[#202020] border border-[#262626] px-6 py-4 text-center">
                  <div className="text-[#f5f5f5]">{zone}</div>
                  <div className="text-xs text-[#8a8a8a] mt-1">Zone</div>
                </div>
                {i < 3 && (
                  <div className="flex flex-col items-center mx-2">
                    <span className="text-[#06b6d4]">────</span>
                    <span className="text-[10px] text-[#4a4a4a]">►</span>
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="flex justify-center gap-8 mt-4 text-xs text-[#8a8a8a]">
            <div className="text-center">
              <div className="text-[#06b6d4]">Rule #100</div>
              <div>mgmt_ssh</div>
              <div className="text-[#10b981]">ALLOW</div>
            </div>
            <div className="text-center">
              <div className="text-[#06b6d4]">Rule #200</div>
              <div>lan_wan</div>
              <div className="text-[#10b981]">ALLOW</div>
            </div>
            <div className="text-center">
              <div className="text-[#06b6d4]">Rule #300</div>
              <div>dmz_http</div>
              <div className="text-[#10b981]">ALLOW</div>
            </div>
          </div>
        </motion.div>

        {/* Rule List */}
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-sm text-[#f5f5f5]">RULE LIST</h3>
          <button className="px-4 py-2 bg-[#06b6d4] text-[#0c0c0c] text-sm font-medium hover:bg-[#0891b2] transition-colors">
            + NEW RULE
          </button>
        </div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-[#161616] border border-[#262626]"
        >
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#262626] text-xs text-[#8a8a8a]">
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
                  className="border-b border-[#262626] hover:bg-[#202020] cursor-pointer"
                >
                  <td className="p-4 text-[#06b6d4]">{rule.priority}</td>
                  <td className="p-4 text-[#f5f5f5]">{rule.name}</td>
                  <td className="p-4 text-[#8a8a8a]">{rule.source}</td>
                  <td className="p-4 text-[#8a8a8a]">{rule.dest}</td>
                  <td className="p-4 text-[#8a8a8a]">{rule.service}</td>
                  <td className={`p-4 ${actionStyles[rule.action]}`}>{rule.action}</td>
                  <td className="p-4">
                    <span className={`flex items-center gap-2 text-xs ${rule.status ? 'text-[#10b981]' : 'text-[#4a4a4a]'}`}>
                      <span className={`w-2 h-2 rounded-full ${rule.status ? 'bg-[#10b981]' : 'bg-[#4a4a4a]'}`} />
                      {rule.status ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      </main>
    </div>
  );
}