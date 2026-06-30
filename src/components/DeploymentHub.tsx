/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Cpu, CheckCircle, Copy, Code, Terminal, ExternalLink, RefreshCw, FileCode } from 'lucide-react';

export default function DeploymentHub() {
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string>('wrangler.jsonc');

  // Definitions of all files with summary descriptions for the deploy checklist
  const projectFiles = [
    { name: 'schema.sql', desc: 'D1 Database tables (users, dns_logs, upstreams, settings, cache)', status: 'Generated' },
    { name: 'wrangler.jsonc', desc: 'Wrangler deployment settings, KV binding & D1 binding configuration', status: 'Generated' },
    { name: 'package.json', desc: 'Cloudflare Worker dependencies, script entry points', status: 'Generated' },
    { name: 'config.example.json', desc: 'Example configuration file for the DNS over HTTPS parameters', status: 'Generated' },
    { name: 'worker.js', desc: 'Core Cloudflare Workers router, RFC8484 parser, database proxy & rate-limiter', status: 'Generated' },
    { name: 'dashboard.html', desc: 'Production vanilla HTML dashboard client interface', status: 'Generated' },
    { name: 'dashboard.js', desc: 'Vanilla ES2023 client-side authentication, charts, CRUD & log manager', status: 'Generated' },
    { name: 'style.css', desc: 'Production dark styling rules for the worker panel', status: 'Generated' },
    { name: 'README.md', desc: 'Exhaustive manual for Cloudflare bindings, D1 creation, migration & backup', status: 'Generated' },
    { name: '.gitignore', desc: 'Standard production git settings skipping local wrangler state logs', status: 'Generated' },
  ];

  const fileContents: Record<string, string> = {
    'wrangler.jsonc': `{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "cf-dns-over-https",
  "main": "worker.js",
  "compatibility_date": "2024-03-01",
  "vars": {
    "ADMIN_SESSION_TTL": 86400
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "cf-doh-db",
      "database_id": "<YOUR_DB_ID>"
    }
  ],
  "kv_namespaces": [
    {
      "binding": "DOH_KV",
      "id": "<YOUR_KV_ID>"
    }
  ]
}`,

    'schema.sql': `--- D1 SQL Database Schema for Cloudflare Workers DNS over HTTPS ---

-- Table for clients/users
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  uuid TEXT UNIQUE NOT NULL,
  api_token TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT,
  created_date TEXT NOT NULL,
  expire_date TEXT,
  traffic_limit INTEGER DEFAULT 0, -- in bytes
  consumed_traffic INTEGER DEFAULT 0, -- in bytes
  unlimited_traffic INTEGER DEFAULT 0, -- 1=true, 0=false
  unlimited_time INTEGER DEFAULT 1, -- 1=true, 0=false
  daily_traffic_limit INTEGER DEFAULT 0, -- in bytes
  daily_consumed_traffic INTEGER DEFAULT 0, -- in bytes
  daily_limit_enabled INTEGER DEFAULT 0, -- 1=true, 0=false
  status TEXT DEFAULT 'active', -- active, suspended, disabled
  allowed_upstreams TEXT, -- comma-separated upstream IDs
  allowed_domains TEXT DEFAULT '*', -- comma-separated domains
  max_rpm INTEGER DEFAULT 120,
  max_concurrent INTEGER DEFAULT 5,
  last_login TEXT,
  last_request TEXT,
  country TEXT,
  notes TEXT
);

-- Table for upstreams
CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  enabled INTEGER DEFAULT 1,
  priority INTEGER DEFAULT 1,
  timeout INTEGER DEFAULT 1000,
  retries INTEGER DEFAULT 2,
  weight INTEGER DEFAULT 10,
  health_status TEXT DEFAULT 'healthy'
);

-- Table for DNS Logs
CREATE TABLE IF NOT EXISTS dns_logs (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  country TEXT,
  domain TEXT NOT NULL,
  type TEXT NOT NULL,
  req_size INTEGER DEFAULT 0,
  res_size INTEGER DEFAULT 0,
  duration INTEGER DEFAULT 0,
  status INTEGER DEFAULT 200,
  upstream TEXT,
  cache_hit INTEGER DEFAULT 0
);

-- Table for System Settings
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Insert Default Settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('default_upstream', 'cf-main');
INSERT OR IGNORE INTO settings (key, value) VALUES ('fallback_upstream', 'google-dns');
INSERT OR IGNORE INTO settings (key, value) VALUES ('allowed_methods', 'GET,POST');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cache_ttl', '300');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cache_enabled', '1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_limit_ip', '60');
INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_limit_user', '120');
INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_password', 'admin123');`,

    'package.json': `{
  "name": "cloudflare-doh-worker",
  "version": "1.0.0",
  "description": "Production DNS-over-HTTPS Server running entirely on Cloudflare Workers",
  "main": "worker.js",
  "scripts": {
    "deploy": "wrangler deploy",
    "tail": "wrangler tail"
  },
  "devDependencies": {
    "wrangler": "^3.0.0"
  },
  "private": true
}`
  };

  const handleCopy = (filename: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopiedFile(filename);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Banner / Header */}
      <div className="bg-[#111111] border border-[#262626] rounded p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div>
          <h2 className="text-xs font-bold font-mono uppercase tracking-wider flex items-center space-x-2 text-white">
            <Cpu className="text-[#f38020] w-4 h-4" />
            <span>Worker Deploy &amp; Development Hub</span>
          </h2>
          <p className="text-[#9ca3af] text-[11px] font-mono mt-0.5">
            Configure, build, and deploy this serverless DNS-over-HTTPS infrastructure stack at the edge.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="px-2 py-0.5 text-[9px] font-mono font-bold uppercase rounded bg-[#f380201a] text-[#f38020] border border-[#f3802033]">
            Wrangler v3 Edge Ready
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Interactive Checklist & File Selector */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#111111] border border-[#262626] rounded p-4">
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-3 flex items-center justify-between">
              <span>Production Repository Assets</span>
              <span className="text-[9px] text-[#4b5563] font-mono uppercase">Root</span>
            </h3>
            
            <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
              {projectFiles.map((file) => (
                <button
                  key={file.name}
                  onClick={() => {
                    if (fileContents[file.name]) {
                      setSelectedFile(file.name);
                    }
                  }}
                  className={`w-full flex items-start space-x-2.5 p-2 rounded border text-left transition-all ${
                    selectedFile === file.name
                      ? 'bg-[#f380201a] border-[#f38020] text-[#f38020]'
                      : fileContents[file.name]
                        ? 'bg-[#0a0a0a] border-[#262626] text-slate-400 hover:border-[#333]'
                        : 'bg-[#0a0a0a]/40 border-[#262626]/60 text-slate-500 hover:border-[#333]'
                  }`}
                >
                  <div className="mt-0.5 shrink-0">
                    <CheckCircle className={`w-3.5 h-3.5 ${selectedFile === file.name ? 'text-[#f38020]' : 'text-green-600'}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-slate-200 truncate">{file.name}</span>
                      <span className="text-[9px] font-mono uppercase px-1 py-0.5 bg-[#111111] text-[#4b5563] border border-[#262626] rounded">
                        {file.status}
                      </span>
                    </div>
                    <p className="text-[10px] text-[#9ca3af] mt-0.5 line-clamp-1 font-mono">{file.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Quick CLI Reference */}
          <div className="bg-[#111111] border border-[#262626] rounded p-4">
            <h3 className="text-[10px] font-bold font-mono text-[#4b5563] uppercase tracking-wider mb-3 flex items-center space-x-1.5">
              <Terminal className="text-[#f38020] w-3.5 h-3.5" />
              <span>Cloudflare Setup CLI commands</span>
            </h3>
            <div className="bg-[#0a0a0a] p-3 rounded border border-[#262626] space-y-2.5 font-mono text-xs text-slate-300">
              <div>
                <p className="text-[#4b5563] text-[9px] uppercase font-bold tracking-wider mb-0.5"># 1. Create Cloudflare D1 Database</p>
                <div className="bg-[#111111] p-1.5 rounded text-[#f38020] select-all border border-[#262626]">$ wrangler d1 create cf-doh-db</div>
              </div>
              <div>
                <p className="text-[#4b5563] text-[9px] uppercase font-bold tracking-wider mb-0.5"># 2. Deploy Schema to production D1</p>
                <div className="bg-[#111111] p-1.5 rounded text-[#f38020] select-all border border-[#262626]">$ wrangler d1 execute cf-doh-db --file=schema.sql</div>
              </div>
              <div>
                <p className="text-[#4b5563] text-[9px] uppercase font-bold tracking-wider mb-0.5"># 3. Create Key-Value Cache Store</p>
                <div className="bg-[#111111] p-1.5 rounded text-[#f38020] select-all border border-[#262626]">$ wrangler kv:namespace create DOH_KV</div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Code Viewer */}
        <div className="lg:col-span-7 flex flex-col">
          <div className="bg-[#111111] border border-[#262626] rounded flex flex-col flex-1 overflow-hidden min-h-[480px]">
            {/* Tab header */}
            <div className="p-3 border-b border-[#262626] bg-[#0d0d0d] flex items-center justify-between">
              <div className="flex items-center space-x-1.5">
                <FileCode className="w-3.5 h-3.5 text-[#f38020]" />
                <span className="text-xs font-mono font-bold text-slate-300">{selectedFile}</span>
              </div>
              {fileContents[selectedFile] && (
                <button
                  onClick={() => handleCopy(selectedFile, fileContents[selectedFile])}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded bg-[#262626] hover:bg-[#333] border border-[#444] text-[9px] font-mono text-white transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copiedFile === selectedFile ? 'COPIED' : 'COPY CODE'}</span>
                </button>
              )}
            </div>

            {/* Code pane */}
            <div className="flex-1 p-4 overflow-auto font-mono text-xs bg-[#0a0a0a] text-slate-300 leading-relaxed max-h-[550px]">
              {fileContents[selectedFile] ? (
                <pre>{fileContents[selectedFile]}</pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 py-20">
                  <Code className="w-8 h-8 mb-2 opacity-40 text-[#f38020]" />
                  <p className="text-[11px] font-mono uppercase tracking-wider text-[#4b5563]">Review Pending</p>
                  <p className="text-[10px] mt-1 text-[#4b5563] font-mono text-center uppercase">Click on registered files list to inspect production code blocks.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
