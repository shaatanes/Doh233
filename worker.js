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
    allowedDomains: ['*.corp.internal', '*google.com', '*github.com', '*cloudflare.com', '*wikipedia.org'],
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
  'cf-main': 'https://cloudflare-dns.com/dns-query',
  'google-dns': 'https://dns.google/dns-query',
  'quad9-secure': 'https://dns.quad9.net/dns-query',
  'adguard-dns': 'https://dns.adguard-dns.com/dns-query'
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

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
      // 1. Identify User Token and Profile (Supports DB query and static fallback)
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

      // 3. User Policy Enforcement (Limits, Allowed Domains, Suspensions)
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

        // C. Allowed Domains glob whitelist check
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

        // D. Rate limits
        if (!checkRateLimit(token, user.maxRpm)) {
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
      let selectedUpstreamUrl = STATIC_UPSTREAMS['cf-main']; // default fallback

      const isValidUrl = (u) => {
        if (!u || typeof u !== 'string') return false;
        try {
          const parsed = new URL(u);
          return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (e) {
          return false;
        }
      };

      if (user) {
        if (upstreamId && typeof upstreamId === 'string') {
          // If the user specifies an upstream, check if they are allowed to use it
          if (user.allowedUpstreams.includes(upstreamId)) {
            if (isValidUrl(upstreamId)) {
              selectedUpstreamUrl = upstreamId;
            } else if (STATIC_UPSTREAMS[upstreamId]) {
              selectedUpstreamUrl = STATIC_UPSTREAMS[upstreamId];
            }
          }
        }
        
        // If selectedUpstreamUrl is still the default fallback or is invalid, use their first allowed upstream
        if ((selectedUpstreamUrl === STATIC_UPSTREAMS['cf-main']) && user.allowedUpstreams && user.allowedUpstreams.length > 0) {
          const primaryUpstream = user.allowedUpstreams[0];
          if (isValidUrl(primaryUpstream)) {
            selectedUpstreamUrl = primaryUpstream;
          } else if (STATIC_UPSTREAMS[primaryUpstream]) {
            selectedUpstreamUrl = STATIC_UPSTREAMS[primaryUpstream];
          }
        }
      } else {
        // Public/default requests
        if (upstreamId && typeof upstreamId === 'string') {
          if (isValidUrl(upstreamId)) {
            selectedUpstreamUrl = upstreamId;
          } else if (STATIC_UPSTREAMS[upstreamId]) {
            selectedUpstreamUrl = STATIC_UPSTREAMS[upstreamId];
          }
        }
      }

      // Final safety guarantee
      if (!isValidUrl(selectedUpstreamUrl)) {
        selectedUpstreamUrl = STATIC_UPSTREAMS['cf-main'];
      }

      if (!cacheHit) {
        // 5. Forward binary request to target upstream
        const upstreamResponse = await fetch(selectedUpstreamUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/dns-message',
            'Accept': 'application/dns-message'
          },
          body: dnsPacket
        });

        if (!upstreamResponse.ok) {
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
            await env.DOH_KV.put(cacheKey, hexString, { expirationTtl: 300 });
          } catch (kvErr) {
            console.error("KV Cache write error:", kvErr);
          }
        }
      }

      // 6. Track consumed bandwidth stats & log to D1
      if (user) {
        const totalBytes = dnsPacket.length + responseBody.byteLength;
        user.consumedTraffic += totalBytes; // Update in-memory fallback
        if (env.DB) {
          try {
            await env.DB.prepare(
              "UPDATE users SET consumed_traffic = consumed_traffic + ?, last_request = ? WHERE id = ?"
            ).bind(totalBytes, new Date().toISOString(), user.id).run();

            // D1 Query logging
            const logId = 'log_' + Math.random().toString(36).substring(2, 15);
            const clientIp = request.headers.get('cf-connecting-ip') || '127.0.0.1';
            const country = request.headers.get('cf-ipcountry') || 'US';
            await env.DB.prepare(
              "INSERT INTO dns_logs (id, timestamp, user_id, username, client_ip, country, domain, type, req_size, res_size, duration, status, upstream, cache_hit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              logId,
              new Date().toISOString(),
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
              upstreamId || 'cf-main',
              cacheHit ? 1 : 0
            ).run();
          } catch (dbErr) {
            console.error("Failed to perform DB tracking/logging:", dbErr);
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
