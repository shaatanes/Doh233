/**
 * Cloudflare Worker implementing DNS over HTTPS (DoH) - RFC 8484
 * Production-ready backend with Multi-User mapping, Database (D1) integration,
 * Glob domain whitelist validation, Rate limiting, and correct upstream routing.
 */

// Helper to convert base64url to Uint8Array
function base64urlToBytes(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Helper to build a DNS query packet from name and type
function buildDnsQuery(name, typeStr) {
  let typeNum = 1; // Default to A
  const upperType = typeStr.toUpperCase();
  if (upperType === 'A') typeNum = 1;
  else if (upperType === 'NS') typeNum = 2;
  else if (upperType === 'CNAME') typeNum = 5;
  else if (upperType === 'SOA') typeNum = 6;
  else if (upperType === 'PTR') typeNum = 12;
  else if (upperType === 'MX') typeNum = 15;
  else if (upperType === 'TXT') typeNum = 16;
  else if (upperType === 'AAAA') typeNum = 28;
  else if (upperType === 'SRV') typeNum = 33;
  else if (upperType === 'ANY') typeNum = 255;
  else if (!isNaN(Number(typeStr))) typeNum = Number(typeStr);

  const header = new Uint8Array(12);
  const txId = Math.floor(Math.random() * 65536);
  header[0] = (txId >> 8) & 0xff;
  header[1] = txId & 0xff;
  header[2] = 0x01; // Flags: RD = 1
  header[3] = 0x00;
  header[4] = 0x00; // QDCOUNT = 1
  header[5] = 0x01;

  const parts = name.split('.');
  const nameBytes = [];
  const encoder = new TextEncoder();
  for (const part of parts) {
    if (!part) continue;
    nameBytes.push(part.length);
    const encodedPart = encoder.encode(part);
    for (const b of encodedPart) {
      nameBytes.push(b);
    }
  }
  nameBytes.push(0); // Null terminator

  const footer = new Uint8Array(4);
  footer[0] = (typeNum >> 8) & 0xff;
  footer[1] = typeNum & 0xff;
  footer[2] = 0x00; // QCLASS = IN (1)
  footer[3] = 0x01;

  const packet = new Uint8Array(header.length + nameBytes.length + footer.length);
  packet.set(header, 0);
  packet.set(new Uint8Array(nameBytes), header.length);
  packet.set(footer, header.length + nameBytes.length);

  return packet;
}

// Helper to parse domain name from DNS packet
function parseDomainFromDnsPacket(packet) {
  if (!packet || packet.length < 12) return "";
  let offset = 12;
  const parts = [];
  const decoder = new TextDecoder("ascii");
  let iterations = 0;
  while (offset < packet.length && iterations < 128) {
    iterations++;
    const len = packet[offset];
    if (len === 0) {
      break;
    }
    // Check for compression pointer (starts with 11xxxxxx, i.e. >= 192)
    if ((len & 0xc0) === 0xc0) {
      break;
    }
    if (offset + 1 + len > packet.length) {
      break; // out of bounds
    }
    const partBytes = packet.subarray(offset + 1, offset + 1 + len);
    parts.push(decoder.decode(partBytes));
    offset += 1 + len;
  }
  return parts.join('.');
}

// Helper to parse query type from DNS packet
function parseQTypeFromDnsPacket(packet) {
  if (!packet || packet.length < 12) return "A";
  let offset = 12;
  let iterations = 0;
  while (offset < packet.length && iterations < 128) {
    iterations++;
    const len = packet[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    // Check for compression pointer (starts with 11xxxxxx, i.e. >= 192)
    if ((len & 0xc0) === 0xc0) {
      offset += 2;
      break;
    }
    offset += 1 + len;
  }
  if (offset + 2 <= packet.length) {
    const typeNum = (packet[offset] << 8) | packet[offset + 1];
    const types = {
      1: 'A',
      2: 'NS',
      5: 'CNAME',
      6: 'SOA',
      12: 'PTR',
      15: 'MX',
      16: 'TXT',
      28: 'AAAA',
      33: 'SRV',
      255: 'ANY'
    };
    return types[typeNum] || `TYPE${typeNum}`;
  }
  return "A";
}

// Helper to convert array buffer to hex string
function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper to check domain glob matching
function isDomainAllowed(domain, allowedPatterns) {
  if (!allowedPatterns || allowedPatterns.length === 0) return true;
  if (allowedPatterns.includes('*')) return true;
  
  const lowerDomain = domain.toLowerCase();
  for (const pattern of allowedPatterns) {
    const lowerPattern = pattern.toLowerCase();
    const escaped = lowerPattern.replace(/[-\/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\\\*/g, '.*');
    const regex = new RegExp('^' + escaped + '$');
    if (regex.test(lowerDomain)) {
      return true;
    }
  }
  return false;
}

// Helper to construct a standard DNS response with response code (RCODE)
function buildDnsErrorResponse(queryPacket, rcode) {
  const response = new Uint8Array(12);
  const view = new DataView(response.buffer);
  let txId = Math.floor(Math.random() * 65536);
  let rd = 1;
  
  if (queryPacket && queryPacket.length >= 12) {
    const qView = new DataView(queryPacket.buffer, queryPacket.byteOffset, queryPacket.byteLength);
    txId = qView.getUint16(0);
    const queryFlags = qView.getUint16(2);
    rd = (queryFlags >> 8) & 1;
  }
  
  view.setUint16(0, txId);
  
  // Flags: Response, Opcode (0), AA (0), TC (0), RD, RA (1), Z (0), RCODE
  const flags = 0x8100 | (rd << 8) | (rcode & 0x0f);
  view.setUint16(2, flags);
  
  if (queryPacket && queryPacket.length >= 12) {
    view.setUint16(4, 1); // QDCOUNT = 1
    let offset = 12;
    while (offset < queryPacket.length) {
      const len = queryPacket[offset];
      if (len === 0) {
        offset += 1;
        break;
      }
      offset += 1 + len;
    }
    offset += 4; // Skip QTYPE and QCLASS
    if (offset <= queryPacket.length) {
      const questionSection = queryPacket.subarray(12, offset);
      const combined = new Uint8Array(response.length + questionSection.length);
      combined.set(response, 0);
      combined.set(questionSection, response.length);
      return combined;
    }
  }
  return response;
}

// Helper to parse authorization token
function getAuthToken(request, url) {
  // Check Query params
  if (url.searchParams.get('token')) return url.searchParams.get('token');
  if (url.searchParams.get('apiToken')) return url.searchParams.get('apiToken');
  if (url.searchParams.get('apiKey')) return url.searchParams.get('apiKey');
  if (url.searchParams.get('api_key')) return url.searchParams.get('api_key');
  if (url.searchParams.get('uuid')) return url.searchParams.get('uuid');
  
  // Check path parameter /dns-query/:token
  const pathParts = url.pathname.split('/');
  if (pathParts.length > 2 && pathParts[1] === 'dns-query' && pathParts[2]) {
    return pathParts[2];
  }
  
  // Check headers
  const authHeader = request.headers.get('authorization');
  if (authHeader) {
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return authHeader;
  }
  if (request.headers.get('x-api-key')) return request.headers.get('x-api-key');
  if (request.headers.get('x-auth-token')) return request.headers.get('x-auth-token');
  if (request.headers.get('x-uuid')) return request.headers.get('x-uuid');
  
  return null;
}

// In-memory rate limiting map (token -> Array of timestamps)
const rateLimitStores = new Map();
function checkRateLimit(token, maxRpm) {
  const now = Date.now();
  let timestamps = rateLimitStores.get(token) || [];
  timestamps = timestamps.filter(t => now - t < 60000);
  if (timestamps.length >= maxRpm) {
    return false;
  }
  timestamps.push(now);
  rateLimitStores.set(token, timestamps);
  return true;
}

// Static fallback profiles
const STATIC_USERS = [
  {
    id: 'u1',
    uuid: '81655e46-a9af-4551-9630-863219cca7c7',
    apiToken: 'ct_a8f902b3149c017df8a',
    username: 'alice_dns',
    displayName: 'Alice Peterson',
    trafficLimit: 10 * 1024 * 1024 * 1024,
    consumedTraffic: 4.8 * 1024 * 1024 * 1024,
    unlimitedTraffic: false,
    status: 'active',
    allowedUpstreams: ['cf-main', 'quad9-secure'],
    allowedDomains: ['*'],
    maxRpm: 120
  },
  {
    id: 'u2',
    uuid: 'e2db6a14-419b-4bf1-bf17-06dfef67cb82',
    apiToken: 'ct_90de991ab81dcd02e3b',
    username: 'bob_homelab',
    displayName: 'Bob Jenkins',
    trafficLimit: 100 * 1024 * 1024 * 1024,
    consumedTraffic: 98.2 * 1024 * 1024 * 1024,
    unlimitedTraffic: false,
    status: 'active',
    allowedUpstreams: ['cf-main', 'google-dns'],
    allowedDomains: ['*'],
    maxRpm: 300
  },
  {
    id: 'u3',
    uuid: 'fa9900ee-8812-4aa8-a73e-3cb3d9bb22cb',
    apiToken: 'ct_31cbff01e83a90cdd3e',
    username: 'dev_sandbox',
    displayName: 'Developer Sandbox',
    trafficLimit: 0,
    consumedTraffic: 215 * 1024 * 1024,
    unlimitedTraffic: true,
    status: 'active',
    allowedUpstreams: ['cf-main', 'quad9-secure', 'adguard-dns'],
    allowedDomains: ['*'],
    maxRpm: 1000
  },
  {
    id: 'u4',
    uuid: 'bc8aef11-738b-4a5c-89ad-9d22ff11a7b8',
    apiToken: 'ct_f62e84bc910def30219',
    username: 'suspended_guest',
    displayName: 'Temporary Guest Client',
    trafficLimit: 500 * 1024 * 1024,
    consumedTraffic: 498 * 1024 * 1024,
    unlimitedTraffic: false,
    status: 'suspended',
    allowedUpstreams: ['google-dns'],
    allowedDomains: ['*'],
    maxRpm: 30
  }
];

const STATIC_UPSTREAMS = {
  'cf-main': 'https://1.1.1.1/dns-query',
  'google-dns': 'https://dns.google/dns-query',
  'quad9-secure': 'https://dns.quad9.net/dns-query',
  'adguard-dns': 'https://dns.adguard-dns.com/dns-query'
};

// Helper functions for KV fallback when env.DB is not bound
async function getKVUsers(env) {
  if (!env.DOH_KV) return STATIC_USERS;
  try {
    const raw = await env.DOH_KV.get('users_list');
    if (raw) return JSON.parse(raw);
    // Initialize with STATIC_USERS if not present
    await env.DOH_KV.put('users_list', JSON.stringify(STATIC_USERS));
    return STATIC_USERS;
  } catch (e) {
    console.error("KV get users failed:", e);
    return STATIC_USERS;
  }
}

async function saveKVUsers(env, users) {
  if (!env.DOH_KV) return;
  try {
    await env.DOH_KV.put('users_list', JSON.stringify(users));
  } catch (e) {
    console.error("KV save users failed:", e);
  }
}

async function getKVLogs(env) {
  if (!env.DOH_KV) return [];
  try {
    const raw = await env.DOH_KV.get('dns_logs_list');
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    console.error("KV get logs failed:", e);
    return [];
  }
}

async function saveKVLogs(env, logs) {
  if (!env.DOH_KV) return;
  try {
    const trimmed = logs.slice(0, 100);
    await env.DOH_KV.put('dns_logs_list', JSON.stringify(trimmed));
  } catch (e) {
    console.error("KV save logs failed:", e);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // API route check FIRST
    if (url.pathname.startsWith('/api/')) {
      // Handle OPTIONS for API CORS
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
            'Access-Control-Max-Age': '86400',
          }
        });
      }

      const corsHeaders = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
      };

      try {
        // 1. GET /api/users
        if (url.pathname === '/api/users' && request.method === 'GET') {
          if (env.DB) {
            const { results } = await env.DB.prepare("SELECT * FROM users").all();
            const mapped = results.map(dbUser => ({
              id: dbUser.id,
              uuid: dbUser.uuid,
              apiToken: dbUser.api_token,
              username: dbUser.username,
              displayName: dbUser.display_name,
              description: dbUser.description,
              createdDate: dbUser.created_date,
              expireDate: dbUser.expire_date,
              trafficLimit: dbUser.traffic_limit,
              consumedTraffic: dbUser.consumed_traffic,
              unlimitedTraffic: dbUser.unlimited_traffic === 1,
              unlimitedTime: dbUser.unlimited_time === 1,
              status: dbUser.status,
              allowedUpstreams: dbUser.allowed_upstreams ? dbUser.allowed_upstreams.split(',') : [],
              allowedDomains: dbUser.allowed_domains ? dbUser.allowed_domains.split(',') : [],
              maxRpm: dbUser.max_rpm,
              maxConcurrent: dbUser.max_concurrent,
              lastLogin: dbUser.last_login,
              lastRequest: dbUser.last_request,
              country: dbUser.country,
              notes: dbUser.notes
            }));
            return new Response(JSON.stringify(mapped), { headers: corsHeaders });
          } else {
            const users = await getKVUsers(env);
            return new Response(JSON.stringify(users), { headers: corsHeaders });
          }
        }

        // 2. POST /api/users (Create or Update)
        if (url.pathname === '/api/users' && request.method === 'POST') {
          const body = await request.json();
          if (env.DB) {
            const existing = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(body.id).first();
            
            const allowedUpstreams = Array.isArray(body.allowedUpstreams) ? body.allowedUpstreams.join(',') : '';
            const allowedDomains = Array.isArray(body.allowedDomains) ? body.allowedDomains.join(',') : '*';

            if (existing) {
              await env.DB.prepare(`
                UPDATE users SET 
                  uuid = ?, api_token = ?, username = ?, display_name = ?, description = ?, 
                  expire_date = ?, traffic_limit = ?, consumed_traffic = ?, unlimited_traffic = ?, unlimited_time = ?, 
                  status = ?, allowed_upstreams = ?, allowed_domains = ?, max_rpm = ?, max_concurrent = ?, 
                  notes = ?
                WHERE id = ?
              `).bind(
                body.uuid, body.apiToken, body.username, body.displayName, body.description,
                body.expireDate || null, body.trafficLimit || 0, body.consumedTraffic || 0, body.unlimitedTraffic ? 1 : 0, body.unlimitedTime ? 1 : 0,
                body.status || 'active', allowedUpstreams, allowedDomains, body.maxRpm || 120, body.maxConcurrent || 5,
                body.notes || null, body.id
              ).run();
            } else {
              await env.DB.prepare(`
                INSERT INTO users (
                  id, uuid, api_token, username, display_name, description, created_date,
                  expire_date, traffic_limit, consumed_traffic, unlimited_traffic, unlimited_time,
                  status, allowed_upstreams, allowed_domains, max_rpm, max_concurrent, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).bind(
                body.id, body.uuid, body.apiToken, body.username, body.displayName, body.description, body.createdDate || new Date().toISOString(),
                body.expireDate || null, body.trafficLimit || 0, body.consumedTraffic || 0, body.unlimitedTraffic ? 1 : 0, body.unlimitedTime ? 1 : 0,
                body.status || 'active', allowedUpstreams, allowedDomains, body.maxRpm || 120, body.maxConcurrent || 5, body.notes || null
              ).run();
            }
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
          } else {
            const currentUsers = await getKVUsers(env);
            const idx = currentUsers.findIndex(u => u.id === body.id);
            if (idx >= 0) {
              currentUsers[idx] = body;
            } else {
              currentUsers.push(body);
            }
            await saveKVUsers(env, currentUsers);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
          }
        }

        // 3. DELETE /api/users
        if (url.pathname === '/api/users' && request.method === 'DELETE') {
          const id = url.searchParams.get('id');
          if (!id) {
            return new Response(JSON.stringify({ success: false, error: 'Missing user id' }), { status: 400, headers: corsHeaders });
          }
          if (env.DB) {
            await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
          } else {
            const currentUsers = await getKVUsers(env);
            const updated = currentUsers.filter(u => u.id !== id);
            await saveKVUsers(env, updated);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
          }
        }

        // 4. GET /api/logs
        if (url.pathname === '/api/logs' && request.method === 'GET') {
          if (env.DB) {
            const { results } = await env.DB.prepare("SELECT * FROM dns_logs ORDER BY timestamp DESC LIMIT 200").all();
            const mapped = results.map(log => ({
              id: log.id,
              timestamp: log.timestamp,
              userId: log.user_id,
              username: log.username,
              clientIp: log.client_ip,
              country: log.country,
              domain: log.domain,
              type: log.type,
              reqSize: log.req_size,
              resSize: log.res_size,
              duration: log.duration,
              status: log.status,
              upstream: log.upstream,
              cacheHit: log.cache_hit === 1
            }));
            return new Response(JSON.stringify(mapped), { headers: corsHeaders });
          } else {
            const logs = await getKVLogs(env);
            return new Response(JSON.stringify(logs), { headers: corsHeaders });
          }
        }

        // 5. GET /api/system
        if (url.pathname === '/api/system' && request.method === 'GET') {
          let adminPasswordHash = 'admin123';
          let defaultUpstream = 'cf-main';
          let cacheTtl = 300;
          let rateLimitPerUser = 120;

          if (env.DB) {
            const results = await env.DB.prepare("SELECT key, value FROM settings").all();
            for (const row of results.results) {
              if (row.key === 'admin_password') adminPasswordHash = row.value;
              if (row.key === 'default_upstream') defaultUpstream = row.value;
              if (row.key === 'cache_ttl') cacheTtl = parseInt(row.value) || 300;
              if (row.key === 'rate_limit_user') rateLimitPerUser = parseInt(row.value) || 120;
            }
          } else if (env.DOH_KV) {
            const raw = await env.DOH_KV.get('system_settings');
            if (raw) {
              const parsed = JSON.parse(raw);
              adminPasswordHash = parsed.adminPasswordHash || adminPasswordHash;
              defaultUpstream = parsed.defaultUpstream || defaultUpstream;
              cacheTtl = parsed.cacheTtl || cacheTtl;
              rateLimitPerUser = parsed.rateLimitPerUser || rateLimitPerUser;
            }
          }
          return new Response(JSON.stringify({ adminPasswordHash, defaultUpstream, cacheTtl, rateLimitPerUser }), { headers: corsHeaders });
        }

        // 6. POST /api/system
        if (url.pathname === '/api/system' && request.method === 'POST') {
          const body = await request.json();
          if (env.DB) {
            if (body.adminPasswordHash) {
              await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)").bind(body.adminPasswordHash).run();
            }
            if (body.defaultUpstream) {
              await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('default_upstream', ?)").bind(body.defaultUpstream).run();
            }
            if (body.cacheTtl !== undefined) {
              await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cache_ttl', ?)").bind(String(body.cacheTtl)).run();
            }
            if (body.rateLimitPerUser !== undefined) {
              await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('rate_limit_user', ?)").bind(String(body.rateLimitPerUser)).run();
            }
          } else if (env.DOH_KV) {
            let current = { adminPasswordHash: 'admin123', defaultUpstream: 'cf-main', cacheTtl: 300, rateLimitPerUser: 120 };
            const raw = await env.DOH_KV.get('system_settings');
            if (raw) current = JSON.parse(raw);
            const updated = {
              adminPasswordHash: body.adminPasswordHash || current.adminPasswordHash,
              defaultUpstream: body.defaultUpstream || current.defaultUpstream,
              cacheTtl: body.cacheTtl !== undefined ? body.cacheTtl : current.cacheTtl,
              rateLimitPerUser: body.rateLimitPerUser !== undefined ? body.rateLimitPerUser : current.rateLimitPerUser
            };
            await env.DOH_KV.put('system_settings', JSON.stringify(updated));
          }
          return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        return new Response(JSON.stringify({ error: 'Endpoint not found' }), { status: 404, headers: corsHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // Route check: /dns-query
    if (!url.pathname.startsWith('/dns-query')) {
      if (env.ASSETS) {
        try {
          let response = await env.ASSETS.fetch(request);
          // SPA Fallback: If not found and accepts HTML, serve index.html
          if (response.status === 404 && request.headers.get("accept")?.includes("text/html")) {
            const fallbackRequest = new Request(new URL("/index.html", request.url), request);
            response = await env.ASSETS.fetch(fallbackRequest);
          }
          return response;
        } catch (assetsErr) {
          return new Response(`Assets error: ${assetsErr.message}`, { status: 500 });
        }
      }
      return new Response('Not Found', { status: 404 });
    }

    // CORS preflight options
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    try {
      // 0. Load System Settings dynamically
      let systemSettings = {
        adminPasswordHash: 'admin123',
        defaultUpstream: 'cf-main',
        cacheTtl: 300,
        rateLimitPerUser: 120
      };

      if (env.DB) {
        try {
          const results = await env.DB.prepare("SELECT key, value FROM settings").all();
          for (const row of results.results) {
            if (row.key === 'admin_password') systemSettings.adminPasswordHash = row.value;
            if (row.key === 'default_upstream') systemSettings.defaultUpstream = row.value;
            if (row.key === 'cache_ttl') systemSettings.cacheTtl = parseInt(row.value) || 300;
            if (row.key === 'rate_limit_user') systemSettings.rateLimitPerUser = parseInt(row.value) || 120;
          }
        } catch (err) {}
      } else if (env.DOH_KV) {
        try {
          const raw = await env.DOH_KV.get('system_settings');
          if (raw) {
            const parsed = JSON.parse(raw);
            systemSettings.adminPasswordHash = parsed.adminPasswordHash || systemSettings.adminPasswordHash;
            systemSettings.defaultUpstream = parsed.defaultUpstream || systemSettings.defaultUpstream;
            systemSettings.cacheTtl = parsed.cacheTtl || systemSettings.cacheTtl;
            systemSettings.rateLimitPerUser = parsed.rateLimitPerUser || systemSettings.rateLimitPerUser;
          }
        } catch (err) {}
      }

      // 1. Identify User Token and Profile (Supports DB query, KV fallback, and static fallback)
      const token = getAuthToken(request, url);
      let user = null;

      if (token) {
        if (env.DB) {
          try {
            const dbUser = await env.DB.prepare(
              "SELECT * FROM users WHERE api_token = ? OR uuid = ? OR id = ? OR username = ?"
            ).bind(token, token, token, token).first();
            
            if (dbUser) {
              user = {
                id: dbUser.id,
                uuid: dbUser.uuid,
                apiToken: dbUser.api_token,
                username: dbUser.username,
                displayName: dbUser.display_name,
                description: dbUser.description,
                createdDate: dbUser.created_date,
                expireDate: dbUser.expire_date,
                trafficLimit: dbUser.traffic_limit,
                consumedTraffic: dbUser.consumed_traffic,
                unlimitedTraffic: dbUser.unlimited_traffic === 1,
                unlimitedTime: dbUser.unlimited_time === 1,
                status: dbUser.status,
                allowedUpstreams: dbUser.allowed_upstreams ? dbUser.allowed_upstreams.split(',') : [],
                allowedDomains: dbUser.allowed_domains ? dbUser.allowed_domains.split(',') : [],
                maxRpm: dbUser.max_rpm,
                maxConcurrent: dbUser.max_concurrent,
                lastLogin: dbUser.last_login,
                lastRequest: dbUser.last_request,
                country: dbUser.country,
                notes: dbUser.notes
              };
            }
          } catch (dbErr) {
            console.error("DB User lookup failed:", dbErr);
          }
        } else if (env.DOH_KV) {
          try {
            const kvUsers = await getKVUsers(env);
            user = kvUsers.find(u => 
              u.apiToken === token || 
              u.uuid === token || 
              u.id === token || 
              u.username === token
            );
          } catch (err) {}
        }
        
        if (!user) {
          user = STATIC_USERS.find(u => 
            u.apiToken === token || 
            u.uuid === token || 
            u.id === token || 
            u.username === token
          );
        }
      }

      // 2. Parse DNS binary packet from request
      let dnsPacket = null;
      let domainName = "";
      let qType = "A";

      if (request.method === 'GET') {
        const name = url.searchParams.get('name');
        const type = url.searchParams.get('type');
        const dns = url.searchParams.get('dns');

        if (dns) {
          try {
            dnsPacket = base64urlToBytes(dns);
            domainName = parseDomainFromDnsPacket(dnsPacket);
            qType = parseQTypeFromDnsPacket(dnsPacket);
          } catch (e) {
            // Decoding failed
          }
        }
        
        if (!dnsPacket && name) {
          try {
            dnsPacket = buildDnsQuery(name, type || 'A');
            domainName = name;
            qType = (type || 'A').toUpperCase();
          } catch (e) {
            // building query failed
          }
        }
      } else if (request.method === 'POST') {
        const arrayBuffer = await request.arrayBuffer();
        if (arrayBuffer && arrayBuffer.byteLength > 0) {
          dnsPacket = new Uint8Array(arrayBuffer);
          domainName = parseDomainFromDnsPacket(dnsPacket);
          qType = parseQTypeFromDnsPacket(dnsPacket);
        }
      }

      // If we cannot construct or parse a DNS packet under any input, return valid standard FORMERR DNS response
      if (!dnsPacket) {
        const errResponse = buildDnsErrorResponse(null, 1); // FORMERR
        return new Response(errResponse, {
          status: 200,
          headers: {
            'Content-Type': 'application/dns-message',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // 3. User Policy Enforcement (Limits, Allowed Domains, Suspensions, Expiration)
      if (user) {
        // A. Account Status check
        if (user.status === 'suspended' || user.status === 'disabled') {
          const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
          return new Response(errResponse, {
            status: 200,
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }

        // B. Traffic Quota check
        if (!user.unlimitedTraffic) {
          if (user.consumedTraffic >= user.trafficLimit) {
            const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
            return new Response(errResponse, {
              status: 200,
              headers: {
                'Content-Type': 'application/dns-message',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
        }

        // C. Expiration check
        if (!user.unlimitedTime && user.expireDate) {
          const expiry = new Date(user.expireDate);
          if (expiry.getTime() < Date.now()) {
            const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
            return new Response(errResponse, {
              status: 200,
              headers: {
                'Content-Type': 'application/dns-message',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
        }

        // D. Allowed Domains glob whitelist check
        if (domainName && !isDomainAllowed(domainName, user.allowedDomains)) {
          const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
          return new Response(errResponse, {
            status: 200,
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }

        // E. Rate limits
        const userMaxRpm = user.maxRpm || systemSettings.rateLimitPerUser || 120;
        if (!checkRateLimit(token, userMaxRpm)) {
          const errResponse = buildDnsErrorResponse(dnsPacket, 2); // SERVFAIL
          return new Response(errResponse, {
            status: 200,
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // 4. Upstream DNS Resolver Selection or KV Cache check
      let cacheHit = false;
      let responseBody = null;
      let duration = 0;
      const cacheKey = `doh:${domainName}:${qType}`;
      const startTime = Date.now();

      if (env.DOH_KV && domainName) {
        try {
          const cachedHex = await env.DOH_KV.get(cacheKey);
          if (cachedHex) {
            // Convert hex back to ArrayBuffer
            const bytes = new Uint8Array(cachedHex.length / 2);
            for (let i = 0; i < cachedHex.length; i += 2) {
              bytes[i / 2] = parseInt(cachedHex.substring(i, i + 2), 16);
            }
            responseBody = bytes.buffer;
            cacheHit = true;
            duration = Date.now() - startTime;
          }
        } catch (kvErr) {
          console.error("KV Cache read error:", kvErr);
        }
      }

      let upstreamId = url.searchParams.get('upstream') || request.headers.get('x-upstream-id');

      const isValidUrl = (u) => {
        if (!u || typeof u !== 'string') return false;
        try {
          const parsed = new URL(u);
          return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (e) {
          return false;
        }
      };

      const getUpstreamUrl = (idOrUrl) => {
        if (isValidUrl(idOrUrl)) return idOrUrl;
        if (STATIC_UPSTREAMS[idOrUrl]) return STATIC_UPSTREAMS[idOrUrl];
        return null;
      };

      // Set default upstream url based on system settings
      const defaultUpstreamUrl = getUpstreamUrl(systemSettings.defaultUpstream) || STATIC_UPSTREAMS['cf-main'];
      let selectedUpstreamUrl = defaultUpstreamUrl;

      if (user) {
        if (upstreamId && typeof upstreamId === 'string') {
          // If the user specifies an upstream, check if they are allowed to use it
          if (user.allowedUpstreams && user.allowedUpstreams.includes(upstreamId)) {
            const mapped = getUpstreamUrl(upstreamId);
            if (mapped) selectedUpstreamUrl = mapped;
          }
        }
        
        // If selectedUpstreamUrl is still the system default fallback, use their first allowed upstream
        if (selectedUpstreamUrl === defaultUpstreamUrl) {
          if (user.allowedUpstreams && user.allowedUpstreams.length > 0) {
            const primaryUpstream = user.allowedUpstreams[0];
            const mapped = getUpstreamUrl(primaryUpstream);
            if (mapped) selectedUpstreamUrl = mapped;
          }
        }
      } else {
        // Public/default requests
        if (upstreamId && typeof upstreamId === 'string') {
          const mapped = getUpstreamUrl(upstreamId);
          if (mapped) selectedUpstreamUrl = mapped;
        }
      }

      // Final safety guarantee
      if (!isValidUrl(selectedUpstreamUrl)) {
        selectedUpstreamUrl = STATIC_UPSTREAMS['cf-main'];
      }

      if (!cacheHit) {
        // 5. Forward binary request to target upstream with Automatic Failover to prevent failure in Intra
        const upstreamsToTry = [selectedUpstreamUrl];
        if (selectedUpstreamUrl !== STATIC_UPSTREAMS['google-dns']) {
          upstreamsToTry.push(STATIC_UPSTREAMS['google-dns']);
        }
        if (selectedUpstreamUrl !== STATIC_UPSTREAMS['cf-main']) {
          upstreamsToTry.push(STATIC_UPSTREAMS['cf-main']);
        }
        if (selectedUpstreamUrl !== STATIC_UPSTREAMS['quad9-secure']) {
          upstreamsToTry.push(STATIC_UPSTREAMS['quad9-secure']);
        }

        let upstreamResponse = null;
        let success = false;
        for (const upstreamUrl of upstreamsToTry) {
          try {
            const res = await fetch(upstreamUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message'
              },
              body: dnsPacket
            });
            if (res.ok) {
              upstreamResponse = res;
              success = true;
              selectedUpstreamUrl = upstreamUrl;
              break;
            }
          } catch (err) {
            console.error(`Upstream failover trying next. Error fetching ${upstreamUrl}:`, err);
          }
        }

        if (!success || !upstreamResponse) {
          const errResponse = buildDnsErrorResponse(dnsPacket, 2); // SERVFAIL
          return new Response(errResponse, {
            status: 200,
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }

        responseBody = await upstreamResponse.arrayBuffer();
        duration = Date.now() - startTime;

        // Save to KV cache if enabled
        if (env.DOH_KV && domainName && responseBody) {
          try {
            const hexString = arrayBufferToHex(responseBody);
            const ttl = Math.max(60, systemSettings.cacheTtl || 300); // KV expirationTtl must be at least 60 seconds
            await env.DOH_KV.put(cacheKey, hexString, { expirationTtl: ttl });
          } catch (kvErr) {
            console.error("KV Cache write error:", kvErr);
          }
        }
      }

      // 6. Track consumed bandwidth stats & log to D1 or KV accurately
      if (user) {
        const totalBytes = dnsPacket.length + responseBody.byteLength;
        user.consumedTraffic = (user.consumedTraffic || 0) + totalBytes; // Update in-memory
        
        const logId = 'log_' + Math.random().toString(36).substring(2, 15);
        const clientIp = request.headers.get('cf-connecting-ip') || '127.0.0.1';
        const country = request.headers.get('cf-ipcountry') || 'US';
        const timestamp = new Date().toISOString();

        if (env.DB) {
          try {
            await env.DB.prepare(
              "UPDATE users SET consumed_traffic = consumed_traffic + ?, last_request = ? WHERE id = ?"
            ).bind(totalBytes, timestamp, user.id).run();

            await env.DB.prepare(
              "INSERT INTO dns_logs (id, timestamp, user_id, username, client_ip, country, domain, type, req_size, res_size, duration, status, upstream, cache_hit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              logId,
              timestamp,
              user.id,
              user.username,
              clientIp,
              country,
              domainName || 'unknown',
              qType,
              dnsPacket.length,
              responseBody.byteLength,
              duration,
              200,
              selectedUpstreamUrl,
              cacheHit ? 1 : 0
            ).run();
          } catch (dbErr) {
            console.error("Failed to perform DB tracking/logging:", dbErr);
          }
        } else if (env.DOH_KV) {
          try {
            // Persistent traffic stats in KV
            const kvUsers = await getKVUsers(env);
            const idx = kvUsers.findIndex(u => u.id === user.id);
            if (idx >= 0) {
              kvUsers[idx].consumedTraffic = (kvUsers[idx].consumedTraffic || 0) + totalBytes;
              kvUsers[idx].lastRequest = timestamp;
              await saveKVUsers(env, kvUsers);
            }

            // Real-time DNS Logging in KV
            const newLog = {
              id: logId,
              timestamp,
              userId: user.id,
              username: user.username,
              clientIp,
              country,
              domain: domainName || 'unknown',
              type: qType,
              reqSize: dnsPacket.length,
              resSize: responseBody.byteLength,
              duration,
              status: 200,
              upstream: selectedUpstreamUrl,
              cacheHit
            };
            const currentLogs = await getKVLogs(env);
            currentLogs.unshift(newLog);
            await saveKVLogs(env, currentLogs);
          } catch (kvErr) {
            console.error("Failed to perform KV tracking/logging:", kvErr);
          }
        }
      }

      // 7. Send binary DNS answer packet
      return new Response(responseBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/dns-message',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (error) {
      console.error('DoH forwarding error:', error);
      const errResponse = buildDnsErrorResponse(null, 2); // SERVFAIL
      return new Response(errResponse, {
        status: 200,
        headers: {
          'Content-Type': 'application/dns-message',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  }
};
