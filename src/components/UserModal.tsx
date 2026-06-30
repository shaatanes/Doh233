/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { User, Upstream } from '../types';
import { Shield, Plus, Trash2, Calendar, HelpCircle } from 'lucide-react';

interface UserModalProps {
  user: User | null; // Null means create mode
  isClone: boolean;
  upstreams: Upstream[];
  onClose: () => void;
  onSave: (savedUser: User) => void;
}

export default function UserModal({ user, isClone, upstreams, onClose, onSave }: UserModalProps) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [trafficLimitGB, setTrafficLimitGB] = useState(10);
  const [unlimitedTraffic, setUnlimitedTraffic] = useState(false);
  const [unlimitedTime, setUnlimitedTime] = useState(true);
  const [expireDate, setExpireDate] = useState('');
  const [status, setStatus] = useState<'active' | 'suspended' | 'disabled'>('active');
  const [allowedUpstreams, setAllowedUpstreams] = useState<string[]>([]);
  const [allowedDomainsStr, setAllowedDomainsStr] = useState('*');
  const [maxRpm, setMaxRpm] = useState(120);
  const [maxConcurrent, setMaxConcurrent] = useState(5);
  const [notes, setNotes] = useState('');

  useEffect(() => {
    if (user) {
      setUsername(isClone ? `${user.username}_copy` : user.username);
      setDisplayName(isClone ? `${user.displayName} (Copy)` : user.displayName);
      setDescription(user.description);
      setTrafficLimitGB(user.trafficLimit > 0 ? Math.round(user.trafficLimit / (1024 * 1024 * 1024)) : 10);
      setUnlimitedTraffic(user.unlimitedTraffic);
      setUnlimitedTime(user.unlimitedTime);
      setExpireDate(user.expireDate ? user.expireDate.split('T')[0] : '');
      setStatus(isClone ? 'active' : user.status);
      setAllowedUpstreams(user.allowedUpstreams || []);
      setAllowedDomainsStr(user.allowedDomains.join(', '));
      setMaxRpm(user.maxRpm);
      setMaxConcurrent(user.maxConcurrent);
      setNotes(user.notes);
    } else {
      // Defaults for new user
      setUsername('');
      setDisplayName('');
      setDescription('');
      setTrafficLimitGB(10);
      setUnlimitedTraffic(false);
      setUnlimitedTime(true);
      setExpireDate('');
      setStatus('active');
      setAllowedUpstreams(upstreams.map(u => u.id)); // Allow all by default
      setAllowedDomainsStr('*');
      setMaxRpm(120);
      setMaxConcurrent(5);
      setNotes('');
    }
  }, [user, isClone, upstreams]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !displayName.trim()) return;

    const domains = allowedDomainsStr
      .split(',')
      .map(d => d.trim())
      .filter(d => d.length > 0);

    const updatedUser: User = {
      id: user && !isClone ? user.id : 'u_' + Math.random().toString(36).substr(2, 9),
      uuid: user && !isClone ? user.uuid : crypto.randomUUID(),
      apiToken: user && !isClone ? user.apiToken : 'ct_' + Math.random().toString(36).substr(2, 19),
      username: username.trim(),
      displayName: displayName.trim(),
      description: description.trim(),
      createdDate: user && !isClone ? user.createdDate : new Date().toISOString(),
      expireDate: unlimitedTime ? '' : new Date(expireDate).toISOString(),
      trafficLimit: unlimitedTraffic ? 0 : trafficLimitGB * 1024 * 1024 * 1024,
      consumedTraffic: user && !isClone ? user.consumedTraffic : 0,
      unlimitedTraffic,
      unlimitedTime,
      status,
      allowedUpstreams,
      allowedDomains: domains.length > 0 ? domains : ['*'],
      maxRpm: Number(maxRpm),
      maxConcurrent: Number(maxConcurrent),
      lastLogin: user && !isClone ? user.lastLogin : '',
      lastRequest: user && !isClone ? user.lastRequest : '',
      country: user && !isClone ? user.country : 'Simulator IP',
      notes: notes.trim()
    };

    onSave(updatedUser);
  };

  const toggleUpstreamSelection = (id: string) => {
    if (allowedUpstreams.includes(id)) {
      setAllowedUpstreams(allowedUpstreams.filter(uid => uid !== id));
    } else {
      setAllowedUpstreams([...allowedUpstreams, id]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#111111] border border-[#262626] rounded max-w-2xl w-full text-slate-100 shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="p-4 border-b border-[#262626] flex items-center justify-between bg-[#0d0d0d]">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 bg-[#f380201a] text-[#f38020] border border-[#f3802033] rounded flex items-center justify-center">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                {user ? (isClone ? 'Clone Client Policy' : 'Edit Client Policy') : 'Register Client Profile'}
              </h2>
              <p className="text-[10px] text-[#4b5563] font-mono mt-0.5">Configure query quotas, upstream mappings, and whitelist rules.</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-[#4b5563] hover:text-white font-mono text-xs"
          >
            ✕
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Section 1: Basic Identity */}
          <div>
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-2">Identity Details</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Unique Username</label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))}
                  placeholder="e.g. smart_switch_dns"
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Display Name / Alias</label>
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Guest IoT Hub"
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
                />
              </div>
            </div>
            <div className="mt-2">
              <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Deployment Description</label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What machine or network location uses this profile?"
                className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
              />
            </div>
          </div>

          <hr className="border-[#262626]" />

          {/* Section 2: Quota & Timing */}
          <div>
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-2">Quotas &amp; Lifetime</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Traffic Limit */}
              <div className="bg-[#0a0a0a] p-3 rounded border border-[#262626]">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-[10px] font-bold font-mono text-[#e5e7eb] uppercase">Traffic quota</label>
                  <label className="flex items-center space-x-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={unlimitedTraffic}
                      onChange={(e) => setUnlimitedTraffic(e.target.checked)}
                      className="rounded bg-[#1a1a1a] border-[#262626] text-[#f38020] focus:ring-0 w-3 h-3"
                    />
                    <span className="text-[9px] text-[#4b5563] font-mono uppercase">Unlimited</span>
                  </label>
                </div>
                {!unlimitedTraffic && (
                  <div>
                    <input
                      type="number"
                      min="1"
                      max="10000"
                      value={trafficLimitGB}
                      onChange={(e) => setTrafficLimitGB(Number(e.target.value))}
                      className="w-full bg-[#111111] border border-[#262626] rounded px-2.5 py-1 text-xs text-white font-mono text-center focus:border-[#f38020] focus:outline-none"
                    />
                    <span className="text-[9px] text-[#4b5563] text-center block mt-1 uppercase font-mono">quota gigabytes per month</span>
                  </div>
                )}
                {unlimitedTraffic && (
                  <div className="py-1.5 text-center text-[10px] text-[#f38020] font-mono uppercase font-bold tracking-wider">
                    No Quota Limit
                  </div>
                )}
              </div>

              {/* Time Limits */}
              <div className="bg-[#0a0a0a] p-3 rounded border border-[#262626]">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-[10px] font-bold font-mono text-[#e5e7eb] uppercase">Expiration lifespan</label>
                  <label className="flex items-center space-x-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={unlimitedTime}
                      onChange={(e) => setUnlimitedTime(e.target.checked)}
                      className="rounded bg-[#1a1a1a] border-[#262626] text-[#f38020] focus:ring-0 w-3 h-3"
                    />
                    <span className="text-[9px] text-[#4b5563] font-mono uppercase">Never expire</span>
                  </label>
                </div>
                {!unlimitedTime && (
                  <div>
                    <input
                      type="date"
                      required
                      value={expireDate}
                      onChange={(e) => setExpireDate(e.target.value)}
                      className="w-full bg-[#111111] border border-[#262626] rounded px-2.5 py-1 text-xs text-white text-center font-mono focus:outline-none focus:border-[#f38020]"
                    />
                    <span className="text-[9px] text-[#4b5563] text-center block mt-1 uppercase font-mono">block access starting on date</span>
                  </div>
                )}
                {unlimitedTime && (
                  <div className="py-1.5 text-center text-[10px] text-[#f38020] font-mono uppercase font-bold tracking-wider">
                    Permanent lifespan
                  </div>
                )}
              </div>
            </div>
          </div>

          <hr className="border-[#262626]" />

          {/* Section 3: Upstreams & Query Restrictions */}
          <div>
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-2">Worker DNS Rules</h3>
            
            <div className="space-y-3">
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#e5e7eb] uppercase tracking-wider mb-1.5">
                  Allowed target upstreams (Edge Pool mapping)
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {upstreams.map((up) => (
                    <button
                      type="button"
                      key={up.id}
                      onClick={() => toggleUpstreamSelection(up.id)}
                      className={`flex items-center space-x-2 p-2 rounded border text-left text-[11px] font-mono transition-colors ${
                        allowedUpstreams.includes(up.id)
                          ? 'bg-[#f380201a] border-[#f38020] text-[#f38020]'
                          : 'bg-[#0a0a0a] border-[#262626] text-[#4b5563] hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={allowedUpstreams.includes(up.id)}
                        readOnly
                        className="rounded border-[#262626] text-[#f38020] focus:ring-0 w-3 h-3"
                      />
                      <span className="truncate">{up.name}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">
                  Query domain whitelist pattern (comma separated)
                </label>
                <input
                  type="text"
                  required
                  value={allowedDomainsStr}
                  onChange={(e) => setAllowedDomainsStr(e.target.value)}
                  placeholder="* (for all domains) or *.example.com, google.com"
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-[#f38020]"
                />
                <span className="text-[9px] text-[#4b5563] mt-1 block font-mono uppercase">Supports wildcard globs (e.g. *.internal, *google.com)</span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Max Requests/Min</label>
                  <input
                    type="number"
                    min="10"
                    max="10000"
                    value={maxRpm}
                    onChange={(e) => setMaxRpm(Number(e.target.value))}
                    className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-[#f38020]"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Concurrent Limit</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={maxConcurrent}
                    onChange={(e) => setMaxConcurrent(Number(e.target.value))}
                    className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-[#f38020]"
                  />
                </div>
              </div>
            </div>
          </div>

          <hr className="border-[#262626]" />

          {/* Section 4: Operational Status & Admin notes */}
          <div>
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-2">Policy Status &amp; Metadata</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Client Authorization Status</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value as any)}
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
                >
                  <option value="active">Active &amp; Whitelisted</option>
                  <option value="suspended">Suspended (Temporary Freeze)</option>
                  <option value="disabled">Disabled (Revoked Access)</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Administrative Notes</label>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Add details or tags..."
                  rows={2}
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] resize-none font-mono"
                />
              </div>
            </div>
          </div>

        </form>

        {/* Footer actions */}
        <div className="p-3 border-t border-[#262626] bg-[#0d0d0d] flex items-center justify-end space-x-2 shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-[10px] font-bold font-mono text-[#9ca3af] hover:text-white border border-[#262626] rounded bg-[#1a1a1a] hover:bg-[#222] transition-colors"
          >
            CANCEL
          </button>
          <button
            onClick={handleSubmit}
            id="user-modal-save-btn"
            className="px-4 py-1.5 text-[10px] font-bold font-mono text-black bg-[#f38020] rounded hover:bg-[#e27216] transition-colors"
          >
            {user ? (isClone ? 'CREATE CLONE' : 'SAVE POLICIES') : 'REGISTER CLIENT'}
          </button>
        </div>
      </div>
    </div>
  );
}
