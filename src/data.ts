/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { User, Upstream, DnsLog, AuthLog, SystemConfig } from './types';

// Generate some initial seed users
export const INITIAL_USERS: User[] = [
  {
    id: 'u1',
    uuid: '81655e46-a9af-4551-9630-863219cca7c7',
    apiToken: 'ct_a8f902b3149c017df8a',
    username: 'alice_dns',
    displayName: 'Alice Peterson',
    description: 'Corporate workstation endpoint configuration',
    createdDate: '2026-01-15T08:30:00Z',
    expireDate: '2027-01-15T00:00:00Z',
    trafficLimit: 10 * 1024 * 1024 * 1024, // 10 GB
    consumedTraffic: 4.8 * 1024 * 1024 * 1024, // 4.8 GB
    unlimitedTraffic: false,
    unlimitedTime: false,
    status: 'active',
    allowedUpstreams: ['cf-main', 'quad9-secure'],
    allowedDomains: ['*.corp.internal', '*google.com', '*github.com', '*cloudflare.com', '*wikipedia.org'],
    maxRpm: 120,
    maxConcurrent: 5,
    lastLogin: '2026-06-30T04:15:00-07:00',
    lastRequest: '2026-06-30T04:48:32-07:00',
    country: 'United States',
    notes: 'Premium commercial seat.'
  },
  {
    id: 'u2',
    uuid: 'e2db6a14-419b-4bf1-bf17-06dfef67cb82',
    apiToken: 'ct_90de991ab81dcd02e3b',
    username: 'bob_homelab',
    displayName: 'Bob Jenkins',
    description: 'Home automation & IoT cluster dns gateway',
    createdDate: '2026-02-10T11:45:00Z',
    expireDate: '2026-12-31T23:59:59Z',
    trafficLimit: 100 * 1024 * 1024 * 1024, // 100 GB
    consumedTraffic: 98.2 * 1024 * 1024 * 1024, // 98.2 GB (Near limit!)
    unlimitedTraffic: false,
    unlimitedTime: false,
    status: 'active',
    allowedUpstreams: ['cf-main', 'google-dns'],
    allowedDomains: ['*'],
    maxRpm: 300,
    maxConcurrent: 10,
    lastLogin: '2026-06-29T23:01:10-07:00',
    lastRequest: '2026-06-30T04:49:10-07:00',
    country: 'Germany',
    notes: 'Approaching monthly allotment. Monitoring closely.'
  },
  {
    id: 'u3',
    uuid: 'fa9900ee-8812-4aa8-a73e-3cb3d9bb22cb',
    apiToken: 'ct_31cbff01e83a90cdd3e',
    username: 'dev_sandbox',
    displayName: 'Developer Sandbox',
    description: 'Staging, testing and manual CLI testing account',
    createdDate: '2026-05-01T14:00:00Z',
    expireDate: '',
    trafficLimit: 0,
    consumedTraffic: 215 * 1024 * 1024, // 215 MB
    unlimitedTraffic: true,
    unlimitedTime: true,
    status: 'active',
    allowedUpstreams: ['cf-main', 'quad9-secure', 'adguard-dns'],
    allowedDomains: ['*'],
    maxRpm: 1000,
    maxConcurrent: 50,
    lastLogin: '2026-06-30T01:30:11-07:00',
    lastRequest: '2026-06-30T04:47:05-07:00',
    country: 'United Kingdom',
    notes: 'Internal developer team token.'
  },
  {
    id: 'u4',
    uuid: 'bc8aef11-738b-4a5c-89ad-9d22ff11a7b8',
    apiToken: 'ct_f62e84bc910def30219',
    username: 'suspended_guest',
    displayName: 'Temporary Guest Client',
    description: 'Suspended sandbox client (abuse check)',
    createdDate: '2026-03-01T09:00:00Z',
    expireDate: '2026-06-01T00:00:00Z',
    trafficLimit: 500 * 1024 * 1024, // 500 MB
    consumedTraffic: 498 * 1024 * 1024,
    unlimitedTraffic: false,
    unlimitedTime: false,
    status: 'suspended',
    allowedUpstreams: ['google-dns'],
    allowedDomains: ['*'],
    maxRpm: 30,
    maxConcurrent: 2,
    lastLogin: '2026-05-28T18:22:15-07:00',
    lastRequest: '2026-05-31T23:59:11-07:00',
    country: 'Brazil',
    notes: 'Suspended due to traffic quota expiration and inactive status.'
  }
];

// Initial upstreams
export const INITIAL_UPSTREAMS: Upstream[] = [
  {
    id: 'cf-main',
    name: 'Cloudflare DNS',
    url: 'https://cloudflare-dns.com/dns-query',
    enabled: true,
    priority: 1,
    timeout: 800,
    retries: 2,
    weight: 50,
    healthStatus: 'healthy'
  },
  {
    id: 'google-dns',
    name: 'Google DNS',
    url: 'https://dns.google/dns-query',
    enabled: true,
    priority: 1,
    timeout: 1000,
    retries: 2,
    weight: 30,
    healthStatus: 'healthy'
  },
  {
    id: 'quad9-secure',
    name: 'Quad9 DNS (Secure)',
    url: 'https://dns.quad9.net/dns-query',
    enabled: true,
    priority: 2,
    timeout: 1200,
    retries: 3,
    weight: 20,
    healthStatus: 'healthy'
  },
  {
    id: 'adguard-dns',
    name: 'AdGuard Default',
    url: 'https://dns.adguard-dns.com/dns-query',
    enabled: false,
    priority: 3,
    timeout: 1500,
    retries: 1,
    weight: 10,
    healthStatus: 'unknown'
  }
];

// Seed DNS query log entries
export const INITIAL_DNS_LOGS: DnsLog[] = [
  { id: 'l1', timestamp: '2026-06-30T04:48:32-07:00', userId: 'u1', username: 'alice_dns', clientIp: '192.168.10.45', country: 'United States', domain: 'api.github.com', type: 'A', reqSize: 76, resSize: 142, duration: 18, status: 200, upstream: 'Cloudflare DNS', cacheHit: false },
  { id: 'l2', timestamp: '2026-06-30T04:48:15-07:00', userId: 'u1', username: 'alice_dns', clientIp: '192.168.10.45', country: 'United States', domain: 'www.google.com', type: 'AAAA', reqSize: 72, resSize: 96, duration: 5, status: 200, upstream: 'Cloudflare DNS', cacheHit: true },
  { id: 'l3', timestamp: '2026-06-30T04:47:05-07:00', userId: 'u3', username: 'dev_sandbox', clientIp: '82.165.2.112', country: 'United Kingdom', domain: 'github.com', type: 'A', reqSize: 70, resSize: 110, duration: 24, status: 200, upstream: 'Quad9 DNS (Secure)', cacheHit: false },
  { id: 'l4', timestamp: '2026-06-30T04:45:10-07:00', userId: 'u2', username: 'bob_homelab', clientIp: '203.0.113.88', country: 'Germany', domain: 'smartthing-api.iot.internal', type: 'TXT', reqSize: 94, resSize: 120, duration: 14, status: 200, upstream: 'Cloudflare DNS', cacheHit: false },
  { id: 'l5', timestamp: '2026-06-30T04:44:00-07:00', userId: 'u2', username: 'bob_homelab', clientIp: '203.0.113.88', country: 'Germany', domain: 'pool.ntp.org', type: 'A', reqSize: 68, resSize: 156, duration: 35, status: 200, upstream: 'Google DNS', cacheHit: false },
  { id: 'l6', timestamp: '2026-06-30T04:41:22-07:00', userId: 'u1', username: 'alice_dns', clientIp: '192.168.10.45', country: 'United States', domain: 'en.wikipedia.org', type: 'A', reqSize: 74, resSize: 128, duration: 22, status: 200, upstream: 'Cloudflare DNS', cacheHit: false },
  { id: 'l7', timestamp: '2026-06-30T04:39:05-07:00', userId: 'u3', username: 'dev_sandbox', clientIp: '82.165.2.112', country: 'United Kingdom', domain: 'google.com', type: 'MX', reqSize: 68, resSize: 180, duration: 19, status: 200, upstream: 'Google DNS', cacheHit: false },
  { id: 'l8', timestamp: '2026-06-30T04:35:12-07:00', userId: 'u2', username: 'bob_homelab', clientIp: '203.0.113.88', country: 'Germany', domain: 'ads.doubleclick.net', type: 'A', reqSize: 78, resSize: 0, duration: 4, status: 403, upstream: 'Blocked - Domains', cacheHit: false }
];

// Seed Admin authentication logs
export const INITIAL_AUTH_LOGS: AuthLog[] = [
  { id: 'a1', timestamp: '2026-06-30T04:15:00-07:00', username: 'admin', clientIp: '127.0.0.1', action: 'Login Successful', status: 'success' },
  { id: 'a2', timestamp: '2026-06-30T01:30:11-07:00', username: 'admin', clientIp: '82.165.2.112', action: 'Failed Login Attempt', status: 'failed', reason: 'Invalid administrative password hash' },
  { id: 'a3', timestamp: '2026-06-29T18:45:00-07:00', username: 'admin', clientIp: '192.168.1.100', action: 'Session Timeout Logout', status: 'success' }
];

// System configuration defaults
export const INITIAL_SYSTEM_CONFIG: SystemConfig = {
  defaultUpstream: 'cf-main',
  fallbackUpstream: 'google-dns',
  allowedMethods: ['GET', 'POST'],
  cacheTtl: 300,
  cacheEnabled: true,
  maxCacheSize: 5000,
  rateLimitPerIp: 60,
  rateLimitPerUser: 120,
  loggingEnabled: true,
  adminPasswordHash: 'admin123' // default password
};

/**
 * Format bytes into human-readable units (MB, GB, TB)
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Perform a real DNS over HTTPS JSON query to a public service in the browser
 */
export async function performLiveDnsQuery(name: string, type: string, upstreamUrl: string): Promise<{
  answers: Array<{ name: string; type: number; TTL: number; data: string }>;
  latency: number;
  status: number;
  rawJson: any;
}> {
  const startTime = performance.now();
  
  // Choose correct upstream target endpoint or fallback
  let targetUrl = 'https://cloudflare-dns.com/dns-query';
  if (upstreamUrl.includes('dns.google')) {
    targetUrl = 'https://dns.google/resolve';
  } else if (upstreamUrl.includes('dns.quad9.net')) {
    targetUrl = 'https://dns.quad9.net/dns-query'; // Quad9 supports JSON at standard query endpoint
  }
  
  // Standard query parameters for DoH JSON
  const url = `${targetUrl}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/dns-json'
      }
    });
    
    const latency = Math.round(performance.now() - startTime);
    const data = await res.json();
    
    // Map standard DNS answer codes
    const answers = (data.Answer || []).map((ans: any) => ({
      name: ans.name,
      type: ans.type,
      TTL: ans.TTL,
      data: ans.data
    }));
    
    return {
      answers,
      latency,
      status: data.Status,
      rawJson: data
    };
  } catch (err) {
    const latency = Math.round(performance.now() - startTime);
    return {
      answers: [],
      latency,
      status: 2, // Server Failure (ServFail)
      rawJson: { error: (err as Error).message, details: 'The fetch request failed. This might be due to a strict network policy or offline server.' }
    };
  }
}

/**
 * Simulate raw DNS Packet generation and parsing (binary format representation)
 * For UI display of the DNS Packet headers
 */
export function generateMockDnsPacketHex(domain: string, type: string): {
  hex: string;
  parsedHeaders: {
    transactionId: string;
    flags: string;
    questions: number;
    answers: number;
    authority: number;
    additional: number;
  };
} {
  // Simple fake transaction ID
  const txId = Math.floor(Math.random() * 65535).toString(16).padStart(4, '0').toUpperCase();
  const flags = '8180'; // Standard query response, recursion desired, recursion available
  const questionsCount = 1;
  const answersCount = 2;
  
  // Format domain into label sequence
  // e.g. "google.com" -> "\x06google\x03com\x00"
  const domainParts = domain.split('.');
  let domainHex = '';
  domainParts.forEach(part => {
    const len = part.length.toString(16).padStart(2, '0');
    const charsHex = Array.from(part).map(c => c.charCodeAt(0).toString(16)).join('');
    domainHex += len + charsHex;
  });
  domainHex += '00'; // Terminating null byte
  
  // Type hex (A is 1, AAAA is 28, MX is 15, TXT is 16)
  let typeHex = '0001';
  if (type === 'AAAA') typeHex = '001c';
  else if (type === 'MX') typeHex = '000f';
  else if (type === 'TXT') typeHex = '0010';
  
  const classHex = '0001'; // IN (Internet)
  
  const hex = `${txId}${flags}000${questionsCount}000${answersCount}00000000${domainHex}${typeHex}${classHex}`;
  
  return {
    hex: hex.toUpperCase(),
    parsedHeaders: {
      transactionId: `0x${txId}`,
      flags: `0x${flags}`,
      questions: questionsCount,
      answers: answersCount,
      authority: 0,
      additional: 0
    }
  };
}
