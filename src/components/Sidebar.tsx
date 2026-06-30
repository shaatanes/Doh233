/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  Activity, Shield, Users, Settings, Sliders, FileText, Globe, Cpu, Server, Play, Terminal
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
}

export default function Sidebar({ activeTab, setActiveTab, onLogout }: SidebarProps) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'users', label: 'Users Management', icon: Users },
    { id: 'dns', label: 'DNS Upstreams', icon: Server },
    { id: 'tester', label: 'DoH Query Tester', icon: Play },
    { id: 'logs', label: 'Audit & Query Logs', icon: FileText },
    { id: 'settings', label: 'Gateway Settings', icon: Sliders },
    { id: 'system', label: 'Worker Dev & Deploy', icon: Cpu },
  ];

  return (
    <aside className="w-56 bg-[#0d0d0d] border-r border-[#262626] flex flex-col h-screen sticky top-0 shrink-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#262626] flex items-center space-x-3 bg-[#111111]">
        <div className="w-6 h-6 bg-[#f38020] rounded-sm flex items-center justify-center text-black font-mono font-bold text-xs select-none">
          CF
        </div>
        <div>
          <h1 className="font-sans font-bold text-[#e5e7eb] text-xs uppercase tracking-tight leading-none">
            CF DoH Engine
          </h1>
          <span className="text-[9px] text-green-500 font-mono mt-1 block tracking-wider font-semibold">
            ● ENGINE LIVE
          </span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <span className="px-2 text-[9px] font-bold text-[#4b5563] uppercase tracking-widest block mb-2 mt-1">
          Management
        </span>
        {menuItems.map((item) => {
          const IconComponent = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`sidebar-btn-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center space-x-2.5 px-3 py-2 border-l-2 transition-all duration-100 font-mono text-[11px] font-medium text-left ${
                isActive
                  ? 'bg-[#f380201a] border-[#f38020] text-[#f38020]'
                  : 'border-transparent text-[#9ca3af] hover:bg-[#1a1a1a] hover:text-[#e5e7eb]'
              }`}
            >
              <IconComponent className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer / Admin Profile */}
      <div className="p-3 border-t border-[#262626] bg-[#0d0d0d]">
        {/* Memory status widget */}
        <div className="px-2 pb-3 mb-2 text-[10px] text-[#4b5563] font-mono">
          <div className="flex justify-between items-center">
            <span>Memory Usage:</span>
            <span className="text-[#9ca3af]">42MB / 128MB</span>
          </div>
          <div className="w-full h-1 bg-[#1a1a1a] mt-1.5 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 w-[32%] rounded-full"></div>
          </div>
        </div>

        <div className="flex items-center space-x-2 p-2 rounded bg-[#111111] border border-[#262626]">
          <div className="w-6 h-6 rounded bg-[#262626] border border-[#333] flex items-center justify-center font-bold text-slate-300 text-[10px] font-mono">
            AD
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-semibold text-slate-200 truncate">admin_root</p>
            <p className="text-[9px] text-[#4b5563] truncate">Cloudflare Root</p>
          </div>
        </div>
        <button
          onClick={onLogout}
          id="logout-btn"
          className="w-full mt-2 text-center py-1 rounded text-[10px] font-mono font-medium text-red-400 bg-red-950/20 hover:bg-red-950/40 border border-red-900/40 hover:border-red-800/50 transition-colors duration-150"
        >
          Exit Session
        </button>
      </div>
    </aside>
  );
}
