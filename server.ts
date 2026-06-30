import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { INITIAL_USERS } from "./src/data";

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Support raw body parsed buffer for all content types under /dns-query path
  app.use(/^\/dns-query(\/.*)?$/, express.raw({ type: '*/*', limit: '10mb' }));

  // Static Upstream Endpoints mapping
  const UPSTREAM_URLS: Record<string, string> = {
    'cf-main': 'https://cloudflare-dns.com/dns-query',
    'google-dns': 'https://dns.google/dns-query',
    'quad9-secure': 'https://dns.quad9.net/dns-query',
    'adguard-dns': 'https://dns.adguard-dns.com/dns-query'
  };

  // In-memory traffic store initialized with existing quotas
  const userTrafficStore = new Map<string, number>();
  for (const u of INITIAL_USERS) {
    userTrafficStore.set(u.id, u.consumedTraffic);
  }

  // In-memory rate limiting map (token -> Array of timestamps)
  const rateLimitStores = new Map<string, number[]>();

  // Helper to convert base64url to Buffer
  function base64urlToBuffer(base64url: string): Buffer {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return Buffer.from(base64, 'base64');
  }

  // Helper to build a DNS query packet from name and type
  function buildDnsQuery(name: string, typeStr: string): Buffer {
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

    const header = Buffer.alloc(12);
    const txId = Math.floor(Math.random() * 65536);
    header.writeUInt16BE(txId, 0);       // Transaction ID
    header.writeUInt16BE(0x0100, 2);     // Flags: Standard query, Recursion Desired
    header.writeUInt16BE(1, 4);          // Questions count: 1
    header.writeUInt16BE(0, 6);          // Answer count: 0
    header.writeUInt16BE(0, 8);          // Authority count: 0
    header.writeUInt16BE(0, 10);         // Additional count: 0

    const parts = name.split('.');
    const nameBuffers: Buffer[] = [];
    for (const part of parts) {
      if (!part) continue;
      const lenBuf = Buffer.alloc(1);
      lenBuf[0] = part.length;
      const partBuf = Buffer.from(part, 'ascii');
      nameBuffers.push(lenBuf, partBuf);
    }
    nameBuffers.push(Buffer.from([0])); // Terminating null byte

    const questionFooter = Buffer.alloc(4);
    questionFooter.writeUInt16BE(typeNum, 0); // QTYPE
    questionFooter.writeUInt16BE(1, 2);       // QCLASS: IN (1)

    return Buffer.concat([header, ...nameBuffers, questionFooter]);
  }

  // Helper to parse domain name from DNS packet
  function parseDomainFromDnsPacket(packet: Buffer): string {
    if (!packet || packet.length < 12) return "";
    let offset = 12;
    const parts: string[] = [];
    while (offset < packet.length) {
      const len = packet[offset];
      if (len === 0) {
        break;
      }
      if (offset + 1 + len > packet.length) {
        break; // out of bounds
      }
      const part = packet.toString('ascii', offset + 1, offset + 1 + len);
      parts.push(part);
      offset += 1 + len;
    }
    return parts.join('.');
  }

  // Helper to check domain glob matching
  function isDomainAllowed(domain: string, allowedPatterns: string[]): boolean {
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
  function buildDnsErrorResponse(queryPacket: Buffer | null, rcode: number): Buffer {
    const response = Buffer.alloc(12);
    let txId = Math.floor(Math.random() * 65536);
    let rd = 1;
    if (queryPacket && queryPacket.length >= 12) {
      txId = queryPacket.readUInt16BE(0);
      const queryFlags = queryPacket.readUInt16BE(2);
      rd = (queryFlags >> 8) & 1;
    }
    response.writeUInt16BE(txId, 0); // Transaction ID
    
    // Flags: Response, Opcode (0), AA (0), TC (0), RD, RA (1), Z (0), RCODE
    const flags = 0x8100 | (rd << 8) | (rcode & 0x0f);
    response.writeUInt16BE(flags, 2);
    
    if (queryPacket && queryPacket.length >= 12) {
      response.writeUInt16BE(1, 4); // QDCOUNT = 1
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
        return Buffer.concat([response, questionSection]);
      }
    }
    return response;
  }

  // Helper to parse authorization token
  function getAuthToken(req: any): string | null {
    // Check Query params
    if (req.query.token && typeof req.query.token === 'string') return req.query.token;
    if (req.query.apiToken && typeof req.query.apiToken === 'string') return req.query.apiToken;
    if (req.query.apiKey && typeof req.query.apiKey === 'string') return req.query.apiKey;
    if (req.query.api_key && typeof req.query.api_key === 'string') return req.query.api_key;
    if (req.query.uuid && typeof req.query.uuid === 'string') return req.query.uuid;
    
    // Check path parameter /dns-query/:token
    const pathParts = req.path.split('/');
    if (pathParts.length > 2 && pathParts[1] === 'dns-query' && pathParts[2]) {
      return pathParts[2];
    }
    
    // Check headers
    const authHeader = req.headers['authorization'];
    if (authHeader && typeof authHeader === 'string') {
      if (authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
      }
      return authHeader;
    }
    if (req.headers['x-api-key'] && typeof req.headers['x-api-key'] === 'string') return req.headers['x-api-key'];
    if (req.headers['x-auth-token'] && typeof req.headers['x-auth-token'] === 'string') return req.headers['x-auth-token'];
    if (req.headers['x-uuid'] && typeof req.headers['x-uuid'] === 'string') return req.headers['x-uuid'];
    
    return null;
  }

  // Helper to track rate limits in-memory sliding window
  function checkRateLimit(token: string, maxRpm: number): boolean {
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

  app.all(/^\/dns-query(\/.*)?$/, async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization');

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    try {
      // 1. Identify User Token and Profile
      const token = getAuthToken(req);
      let user = null;
      if (token) {
        user = INITIAL_USERS.find(u => 
          u.apiToken === token || 
          u.uuid === token || 
          u.id === token || 
          u.username === token
        );
      }

      // 2. Parse DNS binary packet from request
      let dnsPacket: Buffer | null = null;
      let domainName = "";
      let qType = "A";

      if (req.method === 'GET') {
        const { name, type, dns } = req.query;

        if (dns && typeof dns === 'string') {
          try {
            dnsPacket = base64urlToBuffer(dns);
            domainName = parseDomainFromDnsPacket(dnsPacket);
          } catch (e) {
            // Decoding failed
          }
        }
        
        if (!dnsPacket && name && typeof name === 'string') {
          const typeStr = typeof type === 'string' ? type : 'A';
          dnsPacket = buildDnsQuery(name, typeStr);
          domainName = name;
          qType = typeStr.toUpperCase();
        }
      } else if (req.method === 'POST') {
        if (Buffer.isBuffer(req.body) && req.body.length > 0) {
          dnsPacket = req.body;
          domainName = parseDomainFromDnsPacket(dnsPacket);
        }
      }

      // If we cannot construct or parse a DNS packet under any input, return valid standard FORMERR DNS response
      if (!dnsPacket) {
        const errResponse = buildDnsErrorResponse(null, 1); // FORMERR
        res.setHeader('Content-Type', 'application/dns-message');
        res.send(errResponse);
        return;
      }

      // 3. User Policy Enforcement (Limits, Allowed Domains, Suspensions)
      if (user) {
        // A. Account Status check
        if (user.status === 'suspended' || user.status === 'disabled') {
          const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
          res.setHeader('Content-Type', 'application/dns-message');
          res.send(errResponse);
          return;
        }

        // B. Traffic Quota check
        if (!user.unlimitedTraffic) {
          const currentTraffic = userTrafficStore.get(user.id) || 0;
          if (currentTraffic >= user.trafficLimit) {
            const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
            res.setHeader('Content-Type', 'application/dns-message');
            res.send(errResponse);
            return;
          }
        }

        // C. Allowed Domains glob whitelist check
        if (domainName && !isDomainAllowed(domainName, user.allowedDomains)) {
          const errResponse = buildDnsErrorResponse(dnsPacket, 5); // REFUSED
          res.setHeader('Content-Type', 'application/dns-message');
          res.send(errResponse);
          return;
        }

        // D. Rate limits
        if (!checkRateLimit(token!, user.maxRpm)) {
          const errResponse = buildDnsErrorResponse(dnsPacket, 2); // SERVFAIL
          res.setHeader('Content-Type', 'application/dns-message');
          res.send(errResponse);
          return;
        }
      }

      // 4. Upstream DNS Resolver Selection
      let upstreamId = req.query.upstream || req.headers['x-upstream-id'];
      let selectedUpstreamUrl = UPSTREAM_URLS['cf-main']; // default fallback

      if (user) {
        if (upstreamId && typeof upstreamId === 'string' && user.allowedUpstreams.includes(upstreamId)) {
          selectedUpstreamUrl = UPSTREAM_URLS[upstreamId] || UPSTREAM_URLS['cf-main'];
        } else if (user.allowedUpstreams && user.allowedUpstreams.length > 0) {
          selectedUpstreamUrl = UPSTREAM_URLS[user.allowedUpstreams[0]] || UPSTREAM_URLS['cf-main'];
        }
      } else {
        if (upstreamId && typeof upstreamId === 'string' && UPSTREAM_URLS[upstreamId]) {
          selectedUpstreamUrl = UPSTREAM_URLS[upstreamId];
        }
      }

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
        res.setHeader('Content-Type', 'application/dns-message');
        res.send(errResponse);
        return;
      }

      const arrayBuffer = await upstreamResponse.arrayBuffer();
      const responseBuffer = Buffer.from(arrayBuffer);

      // 6. Track consumed bandwidth stats
      if (user) {
        const totalBytes = dnsPacket.length + responseBuffer.length;
        const currentTraffic = userTrafficStore.get(user.id) || 0;
        const newTraffic = currentTraffic + totalBytes;
        userTrafficStore.set(user.id, newTraffic);
        user.consumedTraffic = newTraffic; // Sync live stats on user profile
      }

      // 7. Send binary DNS answer packet
      res.setHeader('Content-Type', 'application/dns-message');
      res.send(responseBuffer);
    } catch (error) {
      console.error('DoH forwarding error:', error);
      // Ensure we ALWAYS return a valid DNS response on unexpected exceptions
      const errResponse = buildDnsErrorResponse(null, 2); // SERVFAIL
      res.setHeader('Content-Type', 'application/dns-message');
      res.send(errResponse);
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
