/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Upstream, DnsLog } from '../types';
import { performLiveDnsQuery, generateMockDnsPacketHex } from '../data';
import { Play, Activity, Clock, Terminal, Globe, HelpCircle, Layers, CheckCircle } from 'lucide-react';

interface DnsTesterProps {
  upstreams: Upstream[];
  onLogQuery: (log: DnsLog) => void;
}

export default function DnsTester({ upstreams, onLogQuery }: DnsTesterProps) {
  const [domain, setDomain] = useState('example.com');
  const [recordType, setRecordType] = useState('A');
  const [selectedUpstream, setSelectedUpstream] = useState('cf-main');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [packetHex, setPacketHex] = useState<any>(null);

  const handleTestQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setIsLoading(true);
    setResult(null);

    const upstream = upstreams.find(u => u.id === selectedUpstream) || upstreams[0];
    
    // Perform Live JSON query (Safe, CORS-enabled DNS-over-HTTPS JSON lookup)
    const dnsResult = await performLiveDnsQuery(domain.trim(), recordType, upstream.url);
    
    // Generate hex representation of query packet
    const pack = generateMockDnsPacketHex(domain.trim(), recordType);

    setResult(dnsResult);
    setPacketHex(pack);
    setIsLoading(false);

    // Record the DNS log event to local state
    const newLog: DnsLog = {
      id: 'log_' + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      userId: 'u3', // Simulated Developer Sandbox
      username: 'dev_sandbox',
      clientIp: '127.0.0.1',
      country: 'United Kingdom',
      domain: domain.trim(),
      type: recordType,
      reqSize: pack.hex.length / 2,
      resSize: dnsResult.answers.length > 0 ? dnsResult.answers.reduce((acc: number, item: any) => acc + (item.data ? item.data.length : 12), 40) : 0,
      duration: dnsResult.latency,
      status: dnsResult.status === 0 ? 200 : 500,
      upstream: upstream.name,
      cacheHit: Math.random() > 0.7 // Random cache hit chance for telemetry realism
    };

    onLogQuery(newLog);
  };

  return (
    <div className="space-y-4">
      {/* Introduction */}
      <div className="bg-[#111111] border border-[#262626] rounded p-4">
        <h2 className="text-xs font-bold font-mono uppercase tracking-wider flex items-center space-x-2 text-white">
          <Globe className="text-[#f38020] w-4 h-4 animate-pulse" />
          <span>RFC 8484 DNS over HTTPS API Query Tester</span>
        </h2>
        <p className="text-[11px] text-[#9ca3af] font-mono mt-1">
          Submit live DNS over HTTPS queries using secure JSON APIs. This component tests routing policies,
          decodes transaction bytes, and captures execution logs against configured seats.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Form controls */}
        <div className="lg:col-span-5">
          <form onSubmit={handleTestQuery} className="bg-[#111111] border border-[#262626] rounded p-4 space-y-3">
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider">Configure DNS Request</h3>
            
            <div>
              <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Target Host / Domain</label>
              <input
                type="text"
                required
                value={domain}
                onChange={(e) => setDomain(e.target.value.toLowerCase().trim())}
                placeholder="e.g. google.com"
                className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-[#f38020]"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Record Type (RR)</label>
                <select
                  value={recordType}
                  onChange={(e) => setRecordType(e.target.value)}
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
                >
                  <option value="A">A (IPv4)</option>
                  <option value="AAAA">AAAA (IPv6)</option>
                  <option value="MX">MX (Mail Server)</option>
                  <option value="TXT">TXT (Text)</option>
                  <option value="CNAME">CNAME (Alias)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-1">Upstream Pool</label>
                <select
                  value={selectedUpstream}
                  onChange={(e) => setSelectedUpstream(e.target.value)}
                  className="w-full bg-[#0a0a0a] border border-[#262626] rounded px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#f38020] font-mono"
                >
                  {upstreams.map(up => (
                    <option key={up.id} value={up.id}>{up.name}</option>
                  ))}
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-[#f38020] hover:bg-[#e27216] transition-all text-black font-bold text-xs rounded py-2 flex items-center justify-center space-x-1.5 font-mono uppercase tracking-wider"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isLoading ? 'resolving dns...' : 'Submit packet query'}</span>
            </button>
          </form>
        </div>

        {/* Right Query Output Details */}
        <div className="lg:col-span-7 space-y-3">
          {!result && !isLoading && (
            <div className="bg-[#111111] border border-[#262626] rounded p-6 flex flex-col items-center justify-center text-center text-[#4b5563] h-full">
              <Terminal className="w-8 h-8 text-[#262626] mb-2 animate-pulse" />
              <p className="text-[10px] font-bold font-mono uppercase tracking-widest text-[#9ca3af]">CONSOLE DECODER STANDBY</p>
              <p className="text-[9px] text-[#4b5563] font-mono mt-1 uppercase">Submit a domain request query to parse DNS network packets.</p>
            </div>
          )}

          {isLoading && (
            <div className="bg-[#111111] border border-[#262626] rounded p-6 flex flex-col items-center justify-center text-center text-[#f38020] h-full">
              <Activity className="w-8 h-8 animate-spin mb-2" />
              <p className="text-[10px] font-bold font-mono uppercase tracking-widest">FETCHING LIVE DNS RESOLUTION</p>
              <p className="text-[9px] text-[#4b5563] font-mono mt-1 uppercase">Parsing raw payload responses from Cloudflare global endpoints.</p>
            </div>
          )}

          {result && !isLoading && (
            <div className="space-y-3">
              {/* Telemetry Header summary cards */}
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-[#111111] border border-[#262626] rounded p-2.5 text-center">
                  <span className="text-[9px] text-[#4b5563] font-bold uppercase tracking-wider block font-mono">LATENCY</span>
                  <span className="text-xs font-mono font-bold text-white">{result.latency} ms</span>
                </div>
                <div className="bg-[#111111] border border-[#262626] rounded p-2.5 text-center">
                  <span className="text-[9px] text-[#4b5563] font-bold uppercase tracking-wider block font-mono">DNS CODE</span>
                  <span className="text-xs font-mono font-bold text-white">
                    {result.status === 0 ? '0 (NOERROR)' : `${result.status} (ERR)`}
                  </span>
                </div>
                <div className="bg-[#111111] border border-[#262626] rounded p-2.5 text-center">
                  <span className="text-[9px] text-[#4b5563] font-bold uppercase tracking-wider block font-mono">RECORDS</span>
                  <span className="text-xs font-mono font-bold text-white">{result.answers.length}</span>
                </div>
              </div>

              {/* Answers Panel */}
              <div className="bg-[#111111] border border-[#262626] rounded p-3">
                <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase mb-2 flex items-center justify-between">
                  <span>Resource Record (RR) Details</span>
                  <span className="text-[9px] text-green-500 font-bold uppercase">STATUS_OK</span>
                </h3>
                {result.answers.length === 0 ? (
                  <p className="text-[10px] text-[#4b5563] italic font-mono text-center py-2 uppercase">No resource record values returned.</p>
                ) : (
                  <div className="space-y-1.5 max-h-[140px] overflow-y-auto">
                    {result.answers.map((ans: any, idx: number) => (
                      <div key={idx} className="flex items-center justify-between bg-[#0a0a0a] p-2 rounded border border-[#262626] font-mono text-[10px]">
                        <span className="text-slate-300 font-bold truncate max-w-[140px]">{ans.name}</span>
                        <div className="flex items-center space-x-2 text-[#9ca3af]">
                          <span className="px-1 py-0.5 bg-[#111111] text-[#f38020] rounded text-[9px] border border-[#262626]">
                            TTL: {ans.TTL}s
                          </span>
                          <span className="text-green-500 truncate max-w-[180px] font-bold">{ans.data}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Wire Hexadecimal Payload Visualizer */}
              {packetHex && (
                <div className="bg-[#111111] border border-[#262626] rounded p-3 font-mono">
                  <h3 className="text-[10px] font-bold text-[#4b5563] uppercase mb-2 flex items-center space-x-1">
                    <Terminal className="w-3.5 h-3.5 text-[#f38020]" />
                    <span>Hex Payload Header Decode (RFC 8484)</span>
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2 text-[10px] text-[#9ca3af] bg-[#0a0a0a] p-2 rounded border border-[#262626]">
                    <div>TX ID: <span className="text-[#f38020] font-bold">{packetHex.parsedHeaders.transactionId}</span></div>
                    <div>Flags: <span className="text-[#f38020] font-bold">{packetHex.parsedHeaders.flags}</span></div>
                    <div>Questions: <span className="text-[#f38020] font-bold">{packetHex.parsedHeaders.questions}</span></div>
                    <div>Answers: <span className="text-[#f38020] font-bold">{packetHex.parsedHeaders.answers}</span></div>
                  </div>
                  <div className="bg-[#0a0a0a] p-2 rounded border border-[#262626] text-[9px] text-[#9ca3af] leading-relaxed overflow-x-auto select-all max-h-[100px] whitespace-pre-wrap">
                    {packetHex.hex.match(/.{1,32}/g)?.map((chunk: string, i: number) => {
                      const offset = (i * 16).toString(16).padStart(4, '0').toUpperCase();
                      const bytes = chunk.match(/.{1,2}/g)?.join(' ') || chunk;
                      return (
                        <div key={i} className="flex space-x-4">
                          <span className="text-[#4b5563] select-none">{offset}:</span>
                          <span className="text-slate-300 font-bold">{bytes}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
