/**
 * Cloudflare Worker implementing DNS over HTTPS (DoH) - RFC 8484
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Endpoint: /dns-query
    if (url.pathname !== '/dns-query') {
      return new Response('Not Found', { status: 404 });
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Accept',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    try {
      let dnsPacket = null;

      if (request.method === 'GET') {
        const name = url.searchParams.get('name');
        const type = url.searchParams.get('type');
        const dns = url.searchParams.get('dns');

        if (dns) {
          dnsPacket = base64urlToBytes(dns);
        } else if (name) {
          dnsPacket = buildDnsQuery(name, type || 'A');
        } else {
          return new Response('Missing name/type or dns query parameters', { status: 400 });
        }
      } else if (request.method === 'POST') {
        const contentType = request.headers.get('content-type');
        if (contentType === 'application/dns-message') {
          dnsPacket = new Uint8Array(await request.arrayBuffer());
        } else {
          return new Response('Invalid Content-Type. Expected application/dns-message', { status: 415 });
        }
      } else {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: {
            'Allow': 'GET, POST',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Forward to Cloudflare DNS DoH endpoint
      const cfResponse = await fetch('https://cloudflare-dns.com/dns-query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message'
        },
        body: dnsPacket
      });

      if (!cfResponse.ok) {
        return new Response('Cloudflare DNS query failed', {
          status: cfResponse.status,
          headers: { 'Access-Control-Allow-Origin': '*' }
        });
      }

      const responseBody = await cfResponse.arrayBuffer();

      return new Response(responseBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/dns-message',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (error) {
      return new Response(`Internal DNS Resolution Error: ${error.message}`, {
        status: 500,
        headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }
  }
};
