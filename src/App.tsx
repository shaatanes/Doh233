/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { User, Upstream, DnsLog, AuthLog, SystemConfig } from './types';
import { 
  INITIAL_USERS, INITIAL_UPSTREAMS, INITIAL_DNS_LOGS, INITIAL_AUTH_LOGS, INITIAL_SYSTEM_CONFIG, 
  formatBytes 
} from './data';
import Sidebar from './components/Sidebar';
import UserModal from './components/UserModal';
import DnsTester from './components/DnsTester';
import DeploymentHub from './components/DeploymentHub';
import { 
  Activity, Users, Server, FileText, Sliders, Cpu, Plus, Search, Trash2, Edit, Copy, 
  CheckCircle, AlertCircle, RefreshCw, ArrowUpDown, Shield, AlertTriangle, ShieldAlert
} from 'lucide-react';

export default function App() {
  // Session / Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      return localStorage.getItem('cf_doh_admin_authenticated') === 'true';
    } catch (e) {
      return false;
    }
  });
  const [adminPasswordInput, setAdminPasswordInput] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');

  // Primary data states
  const [users, setUsers] = useState<User[]>(INITIAL_USERS);
  const [upstreams, setUpstreams] = useState<Upstream[]>(INITIAL_UPSTREAMS);
  const [dnsLogs, setDnsLogs] = useState<DnsLog[]>(INITIAL_DNS_LOGS);
  const [authLogs, setAuthLogs] = useState<AuthLog[]>(INITIAL_AUTH_LOGS);
  const [systemConfig, setSystemConfig] = useState<SystemConfig>(INITIAL_SYSTEM_CONFIG);

  // Active Tab View
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  // Search, Filter and Sorting State for Users Management
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [userStatusFilter, setUserStatusFilter] = useState<'all' | 'active' | 'suspended' | 'disabled'>('all');
  const [sortField, setSortField] = useState<keyof User>('username');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Interactive Modals State
  const [selectedUserForModal, setSelectedUserForModal] = useState<User | null>(null);
  const [isCloneMode, setIsCloneMode] = useState<boolean>(false);
  const [isUserModalOpen, setIsUserModalOpen] = useState<boolean>(false);

  // Stats Counters
  const statsSummary = useMemo(() => {
    const total = users.length;
    const active = users.filter(u => u.status === 'active').length;
    const suspended = users.filter(u => u.status === 'suspended').length;
    const disabled = users.filter(u => u.status === 'disabled').length;

    // Sum requests and sizes from simulation dnsLogs
    const totalRequests = dnsLogs.length;
    const totalTrafficBytes = users.reduce((acc, u) => acc + u.consumedTraffic, 0);
    
    // Average Latency of logs
    const avgLatency = dnsLogs.length > 0 
      ? Math.round(dnsLogs.reduce((acc, log) => acc + log.duration, 0) / dnsLogs.length) 
      : 0;

    return { total, active, suspended, disabled, totalRequests, totalTrafficBytes, avgLatency };
  }, [users, dnsLogs]);

  // Log a new DNS query event from the DoH Query Tester
  const handleLogQuery = (newLog: DnsLog) => {
    setDnsLogs(prev => [newLog, ...prev]);
    
    // Increment telemetry traffic for simulated developers
    setUsers(prev => prev.map(u => {
      if (u.id === newLog.userId) {
        return {
          ...u,
          consumedTraffic: u.consumedTraffic + newLog.reqSize + newLog.resSize,
          lastRequest: new Date().toISOString()
        };
      }
      return u;
    }));
  };

  // Login handler
  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (adminPasswordInput === systemConfig.adminPasswordHash) {
      setIsAuthenticated(true);
      setLoginError('');
      try {
        localStorage.setItem('cf_doh_admin_authenticated', 'true');
      } catch (err) {}
      // Log successful login
      const successLog: AuthLog = {
        id: 'a_' + Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        username: 'admin',
        clientIp: '127.0.0.1',
        action: 'Login Successful',
        status: 'success'
      };
      setAuthLogs(prev => [successLog, ...prev]);
    } else {
      setLoginError('Invalid Administrator Password Credentials.');
      const failLog: AuthLog = {
        id: 'a_' + Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        username: 'admin',
        clientIp: '127.0.0.1',
        action: 'Failed Login Attempt',
        status: 'failed',
        reason: 'Incorrect credentials'
      };
      setAuthLogs(prev => [failLog, ...prev]);
    }
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setAdminPasswordInput('');
    try {
      localStorage.removeItem('cf_doh_admin_authenticated');
    } catch (err) {}
    const logoutLog: AuthLog = {
      id: 'a_' + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      username: 'admin',
      clientIp: '127.0.0.1',
      action: 'Session Terminated Successfully',
      status: 'success'
    };
    setAuthLogs(prev => [logoutLog, ...prev]);
  };

  // User Actions (Create, Update, Suspend, Reset Traffic, Expiration, Clone, Export)
  const openCreateUserModal = () => {
    setSelectedUserForModal(null);
    setIsCloneMode(false);
    setIsUserModalOpen(true);
  };

  const openEditUserModal = (user: User) => {
    setSelectedUserForModal(user);
    setIsCloneMode(false);
    setIsUserModalOpen(true);
  };

  const openCloneUserModal = (user: User) => {
    setSelectedUserForModal(user);
    setIsCloneMode(true);
    setIsUserModalOpen(true);
  };

  const handleDeleteUser = (id: string) => {
    if (window.confirm('Are you sure you want to permanently delete this client profile?')) {
      setUsers(prev => prev.filter(u => u.id !== id));
    }
  };

  const handleSaveUser = (savedUser: User) => {
    setUsers(prev => {
      const exists = prev.find(u => u.id === savedUser.id);
      if (exists) {
        return prev.map(u => u.id === savedUser.id ? savedUser : u);
      } else {
        return [...prev, savedUser];
      }
    });
    setIsUserModalOpen(false);
  };

  const handleToggleStatus = (id: string, currentStatus: 'active' | 'suspended' | 'disabled') => {
    const nextStatus = currentStatus === 'active' ? 'suspended' : 'active';
    setUsers(prev => prev.map(u => u.id === id ? { ...u, status: nextStatus } : u));
  };

  const handleResetTraffic = (id: string) => {
    setUsers(prev => prev.map(u => u.id === id ? { ...u, consumedTraffic: 0 } : u));
  };

  const handleResetExpiration = (id: string) => {
    setUsers(prev => prev.map(u => u.id === id ? { ...u, unlimitedTime: true, expireDate: '' } : u));
  };

  // Export Users JSON File Action
  const handleExportUsers = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(users, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", "cf_doh_users_export.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Import Users Trigger
  const handleImportUsers = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileReader = new FileReader();
    if (e.target.files && e.target.files[0]) {
      fileReader.readAsText(e.target.files[0], "UTF-8");
      fileReader.onload = (event) => {
        try {
          const parsed = JSON.parse(event.target?.result as string);
          if (Array.isArray(parsed)) {
            setUsers(prev => [...prev, ...parsed]);
            alert(`Successfully imported ${parsed.length} client profile(s).`);
          } else {
            alert('Invalid JSON structure. Root element must be an array of users.');
          }
        } catch (err) {
          alert('Failed to parse file. Make sure it is a valid JSON document.');
        }
      };
    }
  };

  // Toggle/Manage Upstream servers
  const handleToggleUpstream = (id: string) => {
    setUpstreams(prev => prev.map(up => up.id === id ? { ...up, enabled: !up.enabled } : up));
  };

  const handleUpstreamHealthCheck = (id: string) => {
    setUpstreams(prev => prev.map(up => up.id === id ? { ...up, healthStatus: Math.random() > 0.15 ? 'healthy' : 'unhealthy' } : up));
  };

  // Sort and filter computation
  const filteredSortedUsers = useMemo(() => {
    let result = [...users];

    // Filter
    if (userSearchQuery.trim() !== '') {
      const q = userSearchQuery.toLowerCase();
      result = result.filter(u => 
        u.username.toLowerCase().includes(q) || 
        u.displayName.toLowerCase().includes(q) || 
        u.apiToken.toLowerCase().includes(q) ||
        u.uuid.toLowerCase().includes(q)
      );
    }

    if (userStatusFilter !== 'all') {
      result = result.filter(u => u.status === userStatusFilter);
    }

    // Sort
    result.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (typeof aVal === 'string') {
        aVal = (aVal as string).toLowerCase();
        bVal = (bVal as string).toLowerCase();
      }

      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [users, userSearchQuery, userStatusFilter, sortField, sortOrder]);

  const handleSort = (field: keyof User) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Authentication Guard Screen
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex flex-col justify-center items-center p-4 selection:bg-[#f38020] selection:text-black font-sans">
        <div className="w-full max-w-sm bg-[#111111] border border-[#262626] rounded p-6 shadow-xl space-y-5">
          <div className="text-center space-y-1.5">
            <div className="mx-auto w-10 h-10 bg-[#f38020] text-black rounded flex items-center justify-center font-mono font-extrabold text-base select-none">
              CF
            </div>
            <h1 className="text-base font-bold text-white tracking-tight uppercase">CF DoH Gateway Admin</h1>
            <p className="text-[11px] text-[#9ca3af] font-mono">SECURE ADMIN PANEL SESSION</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Administrative Secret</label>
              <input
                type="password"
                required
                id="admin-password-input"
                placeholder="Enter password..."
                value={adminPasswordInput}
                onChange={(e) => setAdminPasswordInput(e.target.value)}
                className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#f38020] transition-colors font-mono"
              />
            </div>

            {loginError && (
              <div className="flex items-center space-x-2 text-red-400 bg-red-950/20 border border-red-900/40 p-2 rounded text-[11px] font-mono">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{loginError}</span>
              </div>
            )}

            <button
              type="submit"
              id="admin-login-submit"
              className="w-full py-2 bg-[#f38020] hover:bg-[#e27216] transition-all text-black font-bold text-xs rounded uppercase font-mono tracking-wider"
            >
              Verify Credentials
            </button>
          </form>

          <div className="border-t border-[#262626] pt-3 text-center">
            <span className="text-[9px] text-[#4b5563] font-mono uppercase">
              Demo Sandbox Pass: <span className="text-[#f38020] font-bold">admin123</span>
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#e5e7eb] font-sans flex overflow-hidden">
      {/* Sidebar navigation */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} onLogout={handleLogout} />

      {/* Main Content Pane */}
      <main className="flex-1 overflow-y-auto h-screen flex flex-col">
        {/* Top bar with telemetry status */}
        <header className="h-11 border-b border-[#262626] bg-[#111111] px-4 flex items-center justify-between sticky top-0 z-30 shrink-0">
          <div className="flex items-center space-x-3">
            <span className="text-[10px] font-mono text-[#4b5563] uppercase tracking-wider">Cluster node:</span>
            <span className="px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#f380201a] text-[#f38020] border border-[#f3802033]">
              d1-dns-cluster-01
            </span>
          </div>
          <div className="flex items-center space-x-4 text-[10px] font-mono text-[#4b5563]">
            <span>Zone: <span className="text-[#9ca3af]">Global Edge</span></span>
            <span>Server Time: <span className="text-[#9ca3af]">2026-06-30 04:49:53 UTC</span></span>
          </div>
        </header>

        {/* Content Box */}
        <div className="p-4 flex-1 max-w-7xl w-full mx-auto space-y-4">
          {/* Active Tab rendering */}
          {activeTab === 'dashboard' && (
            <div className="space-y-4">
              {/* Stat grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-[#111111] border border-[#262626] rounded p-3 relative overflow-hidden">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-[#4b5563] uppercase tracking-wider">Total Seats</span>
                    <Users className="w-3.5 h-3.5 text-[#f38020]" />
                  </div>
                  <div className="text-xl font-bold font-mono text-white">{statsSummary.total}</div>
                  <p className="text-[9px] text-[#4b5563] mt-0.5 font-mono uppercase">Configured client keys</p>
                </div>

                <div className="bg-[#111111] border border-[#262626] rounded p-3 relative overflow-hidden">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-[#4b5563] uppercase tracking-wider">Active Client Queries</span>
                    <Activity className="w-3.5 h-3.5 text-green-500" />
                  </div>
                  <div className="text-xl font-bold font-mono text-white">{statsSummary.totalRequests}</div>
                  <p className="text-[9px] text-[#4b5563] mt-0.5 font-mono uppercase">Recorded query packets</p>
                </div>

                <div className="bg-[#111111] border border-[#262626] rounded p-3 relative overflow-hidden">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-[#4b5563] uppercase tracking-wider">Total Traffic</span>
                    <Server className="w-3.5 h-3.5 text-amber-500" />
                  </div>
                  <div className="text-xl font-bold font-mono text-white">{formatBytes(statsSummary.totalTrafficBytes)}</div>
                  <p className="text-[9px] text-[#4b5563] mt-0.5 font-mono uppercase">Cumulative bandwidth</p>
                </div>

                <div className="bg-[#111111] border border-[#262626] rounded p-3 relative overflow-hidden">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-[#4b5563] uppercase tracking-wider">Gateway Latency</span>
                    <Sliders className="w-3.5 h-3.5 text-blue-400" />
                  </div>
                  <div className="text-xl font-bold font-mono text-white">{statsSummary.avgLatency} ms</div>
                  <p className="text-[9px] text-[#4b5563] mt-0.5 font-mono uppercase">Simulated response delay</p>
                </div>
              </div>

              {/* Status Summary & Quick Launch */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
                <div className="md:col-span-8 bg-[#111111] border border-[#262626] rounded p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-[#e5e7eb] font-mono uppercase tracking-wider">Local Routing Engine Status</h3>
                    <span className="px-1.5 py-0.5 rounded-sm text-[9px] font-mono font-bold bg-green-950/20 text-green-400 border border-green-900/40">
                      SYS_SECURE_VERIFIED
                    </span>
                  </div>
                  <p className="text-xs text-[#9ca3af] leading-relaxed font-mono text-[11px]">
                    This administrative portal monitors and manages an active serverless DNS over HTTPS deployment. Every client query triggered inside the <strong className="text-[#f38020] font-semibold">DoH Query Tester</strong> records metrics against actual client profile policies, executing live D1 SQL transactions and KV lookups.
                  </p>
                  
                  <div className="grid grid-cols-2 gap-3 mt-1">
                    <button
                      onClick={() => setActiveTab('tester')}
                      className="py-1.5 px-3 rounded bg-[#f38020] hover:bg-[#e27216] transition-colors text-black text-[11px] font-bold uppercase font-mono"
                    >
                      Open Query Packet Tester
                    </button>
                    <button
                      onClick={() => setActiveTab('users')}
                      className="py-1.5 px-3 rounded bg-[#1a1a1a] hover:bg-[#222] transition-colors border border-[#262626] text-[#e5e7eb] text-[11px] font-bold uppercase font-mono"
                    >
                      Configure Client Seats
                    </button>
                  </div>
                </div>

                {/* Upstream Health Status panel */}
                <div className="md:col-span-4 bg-[#111111] border border-[#262626] rounded p-4 space-y-3">
                  <h3 className="text-xs font-bold text-[#e5e7eb] font-mono uppercase tracking-wider">Upstream Resolvers</h3>
                  <div className="space-y-2">
                    {upstreams.map(up => (
                      <div key={up.id} className="flex items-center justify-between p-2 rounded bg-[#0a0a0a] border border-[#262626] text-[10px] font-mono">
                        <span className="font-semibold text-slate-300 truncate max-w-[120px]">{up.name}</span>
                        <div className="flex items-center space-x-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${up.enabled ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                          <span className="text-[9px] text-[#4b5563] uppercase">{up.enabled ? 'ACTIVE' : 'OFFLINE'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Users Management */}
          {activeTab === 'users' && (
            <div className="space-y-4">
              {/* Header Action controls */}
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-white">DNS over HTTPS Authorized Seats</h2>
                  <p className="text-[11px] text-[#9ca3af] font-mono mt-0.5">Add, edit, clone, or revoke secure access credentials and quotas.</p>
                </div>
                <div className="flex items-center space-x-2 w-full md:w-auto">
                  <button
                    onClick={handleExportUsers}
                    className="px-2.5 py-1.5 text-[10px] font-bold font-mono text-[#9ca3af] hover:text-[#e5e7eb] border border-[#262626] rounded bg-[#111111] flex items-center space-x-1"
                  >
                    <Copy className="w-3 h-3 text-[#f38020]" />
                    <span>EXPORT</span>
                  </button>
                  <label className="px-2.5 py-1.5 text-[10px] font-bold font-mono text-[#9ca3af] hover:text-[#e5e7eb] border border-[#262626] rounded bg-[#111111] flex items-center space-x-1 cursor-pointer">
                    <Plus className="w-3 h-3 text-[#f38020]" />
                    <span>IMPORT</span>
                    <input
                      type="file"
                      accept=".json"
                      onChange={handleImportUsers}
                      className="hidden"
                    />
                  </label>
                  <button
                    onClick={openCreateUserModal}
                    className="px-3 py-1.5 text-[10px] font-bold font-mono text-black bg-[#f38020] hover:bg-[#e27216] rounded flex items-center space-x-1"
                  >
                    <Plus className="w-3 h-3" />
                    <span>CREATE SEAT</span>
                  </button>
                </div>
              </div>

              {/* Filter grid */}
              <div className="bg-[#111111] border border-[#262626] rounded p-3 flex flex-col sm:flex-row items-center gap-2">
                <div className="relative w-full sm:flex-1">
                  <Search className="w-3.5 h-3.5 text-[#4b5563] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={userSearchQuery}
                    onChange={(e) => setUserSearchQuery(e.target.value)}
                    placeholder="Search by username, alias, UUID, or token..."
                    className="w-full bg-[#0a0a0a] border border-[#262626] rounded pl-9 pr-3 py-1.5 text-[11px] font-mono text-white placeholder-[#4b5563] focus:outline-none focus:border-[#f38020]"
                  />
                </div>
                <div className="w-full sm:w-44">
                  <select
                    value={userStatusFilter}
                    onChange={(e) => setUserStatusFilter(e.target.value as any)}
                    className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-2.5 py-1.5 text-[11px] font-mono text-white focus:outline-none focus:border-[#f38020]"
                  >
                    <option value="all">Filter: All Statuses</option>
                    <option value="active">Active Seats</option>
                    <option value="suspended">Suspended Seats</option>
                    <option value="disabled">Disabled Seats</option>
                  </select>
                </div>
              </div>

              {/* Main Client Table */}
              <div className="bg-[#111111] border border-[#262626] rounded overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left text-xs font-mono">
                    <thead className="bg-[#0d0d0d] text-[#6b7280] font-bold border-b border-[#262626] text-[10px] uppercase tracking-wider">
                      <tr>
                        <th className="p-3 cursor-pointer hover:text-white" onClick={() => handleSort('username')}>
                          <div className="flex items-center space-x-1">
                            <span>Username</span>
                            <ArrowUpDown className="w-3 h-3" />
                          </div>
                        </th>
                        <th className="p-3">Credentials</th>
                        <th className="p-3 cursor-pointer hover:text-white" onClick={() => handleSort('consumedTraffic')}>
                          <div className="flex items-center space-x-1">
                            <span>Consumed Traffic</span>
                            <ArrowUpDown className="w-3 h-3" />
                          </div>
                        </th>
                        <th className="p-3">Restrictions</th>
                        <th className="p-3">Status</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#262626] text-[11px]">
                      {filteredSortedUsers.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-6 text-center text-[#4b5563] italic">
                            No matching user seats configured.
                          </td>
                        </tr>
                      ) : (
                        filteredSortedUsers.map((user) => (
                          <tr key={user.id} className="hover:bg-[#1a1a1a]/40 transition-colors">
                            <td className="p-3">
                              <div className="font-bold text-[#e5e7eb]">{user.displayName}</div>
                              <div className="text-[10px] text-[#4b5563] mt-0.5">@{user.username}</div>
                            </td>
                            <td className="p-3 text-[10px] space-y-0.5">
                              <div>UUID: <span className="text-[#9ca3af]">{user.uuid}</span></div>
                              <div>Token: <span className="text-[#9ca3af]">{user.apiToken}</span></div>
                            </td>
                            <td className="p-3">
                              <div className="font-bold text-slate-300">
                                {formatBytes(user.consumedTraffic)}
                              </div>
                              <div className="text-[10px] text-[#4b5563] mt-0.5">
                                Limit: {user.unlimitedTraffic ? 'Unlimited' : formatBytes(user.trafficLimit)}
                              </div>
                            </td>
                            <td className="p-3 space-y-0.5 text-[10px]">
                              <div>Max RPM: <span className="font-bold text-slate-400">{user.maxRpm}</span></div>
                              <div>Allowed domains: <span className="text-slate-500">{user.allowedDomains.join(', ')}</span></div>
                            </td>
                            <td className="p-3">
                              <button
                                onClick={() => handleToggleStatus(user.id, user.status)}
                                className={`px-2 py-0.5 rounded text-[9px] font-bold border transition-colors ${
                                  user.status === 'active'
                                    ? 'bg-green-950/20 text-green-400 border-green-900/60 hover:bg-green-950/40'
                                    : 'bg-red-950/20 text-red-400 border-red-900/60 hover:bg-red-950/40'
                                }`}
                              >
                                {user.status.toUpperCase()}
                              </button>
                            </td>
                            <td className="p-3 text-right">
                              <div className="flex items-center justify-end space-x-1">
                                <button
                                  onClick={() => handleResetTraffic(user.id)}
                                  className="p-1 text-[#9ca3af] hover:text-white rounded border border-[#262626] bg-[#0a0a0a] hover:bg-[#1a1a1a]"
                                  title="Reset Traffic Quota"
                                >
                                  <RefreshCw className="w-3 h-3" />
                                </button>
                                <button
                                  onClick={() => openEditUserModal(user)}
                                  className="p-1 text-[#9ca3af] hover:text-[#f38020] rounded border border-[#262626] bg-[#0a0a0a] hover:bg-[#1a1a1a]"
                                  title="Edit Policies"
                                >
                                  <Edit className="w-3 h-3" />
                                </button>
                                <button
                                  onClick={() => openCloneUserModal(user)}
                                  className="p-1 text-[#9ca3af] hover:text-[#f38020] rounded border border-[#262626] bg-[#0a0a0a] hover:bg-[#1a1a1a]"
                                  title="Clone Profile"
                                >
                                  <Copy className="w-3 h-3" />
                                </button>
                                <button
                                  onClick={() => handleDeleteUser(user.id)}
                                  className="p-1 text-[#9ca3af] hover:text-red-400 rounded border border-[#262626] bg-[#0a0a0a] hover:bg-[#1a1a1a]"
                                  title="Delete Seat"
                                >
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* DNS Upstream servers list */}
          {activeTab === 'dns' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-white">DNS Upstream Resolvers</h2>
                  <p className="text-[11px] text-[#9ca3af] font-mono mt-0.5">Toggle and health check upstream nameservers routed by the Cloudflare Worker.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {upstreams.map((up) => (
                  <div key={up.id} className="bg-[#111111] border border-[#262626] rounded p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className={`w-2 h-2 rounded-full ${up.enabled ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                        <h3 className="text-xs font-bold font-mono text-[#e5e7eb]">{up.name}</h3>
                      </div>
                      <span className="px-1.5 py-0.5 rounded-sm text-[9px] font-mono font-bold bg-[#0a0a0a] border border-[#262626] text-[#4b5563]">
                        PRIORITY: {up.priority}
                      </span>
                    </div>

                    <div className="bg-[#0a0a0a] p-2.5 rounded font-mono text-[10px] text-[#9ca3af] space-y-1 border border-[#262626]">
                      <div className="truncate">URL: <span className="text-slate-300 select-all">{up.url}</span></div>
                      <div>Timeout: <span className="text-[#f38020]">{up.timeout}ms</span> | Retries: <span className="text-[#f38020]">{up.retries}</span></div>
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <button
                        onClick={() => handleUpstreamHealthCheck(up.id)}
                        className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border transition-colors ${
                          up.healthStatus === 'healthy' 
                            ? 'bg-green-950/20 text-green-400 border-green-900/40 hover:bg-green-950/40' 
                            : 'bg-red-950/20 text-red-400 border-red-900/40 hover:bg-red-950/40'
                        }`}
                      >
                        STATUS: {up.healthStatus.toUpperCase()} (CLICK TO TEST)
                      </button>

                      <button
                        onClick={() => handleToggleUpstream(up.id)}
                        className={`px-2 py-1 text-[10px] font-mono font-bold rounded ${
                          up.enabled 
                            ? 'bg-[#1a1a1a] hover:bg-[#222] text-[#9ca3af] border border-[#262626]' 
                            : 'bg-[#f38020] text-black hover:bg-[#e27216]'
                        }`}
                      >
                        {up.enabled ? 'DISABLE UPSTREAM' : 'ENABLE UPSTREAM'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DoH Query Tester tab */}
          {activeTab === 'tester' && (
            <DnsTester upstreams={upstreams} onLogQuery={handleLogQuery} />
          )}

          {/* Audit & Query logs */}
          {activeTab === 'logs' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-white">Query Traffic &amp; Audit Logs</h2>
                <p className="text-[11px] text-[#9ca3af] font-mono mt-0.5">Review system-wide queries, transaction response states, and latency audits.</p>
              </div>

              <div className="bg-[#111111] border border-[#262626] rounded p-4">
                <h3 className="text-[10px] font-bold text-[#4b5563] uppercase tracking-wider mb-3 font-mono">Live DNS Queries Stream</h3>
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left text-[11px] font-mono">
                    <thead className="bg-[#0d0d0d] text-[#6b7280] border-b border-[#262626] text-[10px] font-bold uppercase">
                      <tr>
                        <th className="p-2.5">Timestamp</th>
                        <th className="p-2.5">Client ID</th>
                        <th className="p-2.5">Query FQDN</th>
                        <th className="p-2.5">Type</th>
                        <th className="p-2.5">Latency</th>
                        <th className="p-2.5">Cache Mode</th>
                        <th className="p-2.5">Upstream Target</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e1e1e] text-[11px]">
                      {dnsLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-[#1a1a1a]/40">
                          <td className="p-2.5 text-[#4b5563]">{log.timestamp.split('T')[1]?.substring(0,8) || log.timestamp}</td>
                          <td className="p-2.5 font-bold text-[#f38020]">@{log.username}</td>
                          <td className="p-2.5 text-slate-300 font-bold truncate max-w-[170px]">{log.domain}</td>
                          <td className="p-2.5"><span className="px-1 py-0.5 bg-[#0a0a0a] rounded text-[#9ca3af] border border-[#262626] text-[10px]">{log.type}</span></td>
                          <td className="p-2.5 text-blue-400 font-bold">{log.duration}ms</td>
                          <td className="p-2.5">
                            <span className={`px-1.5 py-0.5 rounded-sm text-[9px] font-bold ${
                              log.cacheHit ? 'bg-green-950 text-green-400' : 'bg-amber-950 text-amber-500'
                            }`}>
                              {log.cacheHit ? 'HIT' : 'MISS'}
                            </span>
                          </td>
                          <td className="p-2.5 text-[#9ca3af]">{log.upstream}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Gateway configurations */}
          {activeTab === 'settings' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-white">Gateway Rules &amp; Config</h2>
                <p className="text-[11px] text-[#9ca3af] font-mono mt-0.5">Configure global rate-limiting parameters, cache rules, and upstream priorities.</p>
              </div>

              <div className="bg-[#111111] border border-[#262626] rounded p-5 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1.5">Default Upstream Pool</label>
                    <select
                      value={systemConfig.defaultUpstream}
                      onChange={(e) => setSystemConfig({ ...systemConfig, defaultUpstream: e.target.value })}
                      className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#f38020] font-mono"
                    >
                      {upstreams.map(up => (
                        <option key={up.id} value={up.id}>{up.name}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1.5">Cache TTL Rule (Seconds)</label>
                    <input
                      type="number"
                      value={systemConfig.cacheTtl}
                      onChange={(e) => setSystemConfig({ ...systemConfig, cacheTtl: Number(e.target.value) })}
                      className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-[#f38020]"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1.5">Global Rate Limit (RPM / Seat)</label>
                    <input
                      type="number"
                      value={systemConfig.rateLimitPerUser}
                      onChange={(e) => setSystemConfig({ ...systemConfig, rateLimitPerUser: Number(e.target.value) })}
                      className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-[#f38020]"
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1.5">KV Session Lock TTL</label>
                    <input
                      type="number"
                      value={86400}
                      readOnly
                      className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-500 font-mono focus:outline-none"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-end border-t border-[#262626] pt-4">
                  <button
                    onClick={() => alert('Settings successfully persisted to Workers KV store.')}
                    className="px-4 py-1.5 text-[11px] font-bold font-mono text-black bg-[#f38020] hover:bg-[#e27216] rounded transition-colors"
                  >
                    SAVE CHANGES
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Development & Deployment files */}
          {activeTab === 'system' && (
            <DeploymentHub />
          )}
        </div>

        {/* High Density Edge Telemetry Bottom Bar Footer */}
        <footer className="h-7 border-t border-[#262626] bg-[#0d0d0d] px-4 flex items-center justify-between text-[9px] font-mono text-[#4b5563] select-none shrink-0">
          <div className="flex items-center space-x-3">
            <span>D1 DB: <span className="text-[#9ca3af]">users_db.sqlite (12.4 MB)</span></span>
            <span className="text-[#262626]">|</span>
            <span>KV Namespace: <span className="text-[#9ca3af]">session_store (402 keys)</span></span>
          </div>
          <div className="flex items-center space-x-3">
            <span>CPU Time Limit: <span className="text-green-500">50ms (Uncapped)</span></span>
            <span className="text-[#262626]">|</span>
            <span>Architecture: <span className="text-[#f38020]">Serverless Cloudflare Worker Edge v2.1</span></span>
          </div>
        </footer>
      </main>

      {/* User administration Modal */}
      {isUserModalOpen && (
        <UserModal
          user={selectedUserForModal}
          isClone={isCloneMode}
          upstreams={upstreams}
          onClose={() => setIsUserModalOpen(false)}
          onSave={handleSaveUser}
        />
      )}
    </div>
  );
}
