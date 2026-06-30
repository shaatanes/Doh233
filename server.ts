import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Raw body parser for dns messages
  app.use('/dns-query', express.raw({ type: 'application/dns-message', limit: '10mb' }));

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

  app.all('/dns-query', async (req, res) => {
    try {
      let dnsPacket: Buffer | null = null;

      if (req.method === 'GET') {
        const { name, type, dns } = req.query;

        if (dns && typeof dns === 'string') {
          dnsPacket = base64urlToBuffer(dns);
        } else if (name && typeof name === 'string') {
          const typeStr = typeof type === 'string' ? type : 'A';
          dnsPacket = buildDnsQuery(name, typeStr);
        } else {
          res.status(400).send('Missing name/type or dns query parameters');
          return;
        }
      } else if (req.method === 'POST') {
        if (Buffer.isBuffer(req.body) && req.body.length > 0) {
          dnsPacket = req.body;
        } else {
          res.status(400).send('Empty or invalid DNS query body');
          return;
        }
      } else {
        res.setHeader('Allow', 'GET, POST');
        res.status(405).send('Method Not Allowed');
        return;
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
        res.status(cfResponse.status).send('Cloudflare DNS query failed');
        return;
      }

      const arrayBuffer = await cfResponse.arrayBuffer();
      const responseBuffer = Buffer.from(arrayBuffer);

      res.setHeader('Content-Type', 'application/dns-message');
      res.send(responseBuffer);
    } catch (error) {
      console.error('DoH forwarding error:', error);
      res.status(500).send('Internal DNS Resolution Error');
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
