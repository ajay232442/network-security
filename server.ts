import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({ limit: '10mb' }));

// Initialize Gemini API client with User-Agent telemetry
const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    })
  : null;

// Endpoint: Network Interfaces Status
app.get('/api/network-interfaces', (_req, res) => {
  res.json({
    interfaces: [
      {
        id: 'eth0',
        name: 'eth0 (Gigabit Ethernet)',
        ip: '192.168.1.145',
        netmask: '255.255.255.0',
        mac: '00:1A:2B:3C:4D:5E',
        status: 'UP',
        promiscuous: true,
        rxPackets: 184920,
        txPackets: 142103,
        speed: '1000 Mbps',
      },
      {
        id: 'wlan0',
        name: 'wlan0 (Wi-Fi 802.11ax)',
        ip: '10.0.0.88',
        netmask: '255.255.255.0',
        mac: '3C:52:82:11:22:33',
        status: 'UP',
        promiscuous: false,
        rxPackets: 92340,
        txPackets: 45210,
        speed: '540 Mbps',
      },
      {
        id: 'tun0',
        name: 'tun0 (Corporate WireGuard VPN)',
        ip: '10.8.0.4',
        netmask: '255.255.255.255',
        mac: '00:00:00:00:00:00',
        status: 'UP',
        promiscuous: true,
        rxPackets: 65120,
        txPackets: 41200,
        speed: '300 Mbps',
      },
      {
        id: 'lo0',
        name: 'lo0 (Loopback Interface)',
        ip: '127.0.0.1',
        netmask: '255.0.0.0',
        mac: '00:00:00:00:00:00',
        status: 'UP',
        promiscuous: false,
        rxPackets: 12040,
        txPackets: 12040,
        speed: '10 Gbps',
      },
    ],
  });
});

// Endpoint: AI Forensic Threat Analysis on Packet
app.post('/api/analyze-packet', async (req, res) => {
  try {
    const { packet } = req.body;
    if (!packet) {
      return res.status(400).json({ error: 'Missing packet payload for analysis' });
    }

    if (!ai) {
      // Fallback response if GEMINI_API_KEY is not yet populated
      return res.json({
        analysis: {
          threatAssessment: packet.threatInfo || 'Baseline Network Activity Inspection',
          confidenceScore: packet.isSuspicious ? 88 : 15,
          mitreAttack: packet.isSuspicious ? 'T1046: Network Service Discovery' : 'N/A (Standard Traffic)',
          severity: packet.severity || 'LOW',
          technicalAnalysis: `Packet #${packet.id} from ${packet.sourceIp}:${packet.sourcePort || '-'} to ${packet.destinationIp}:${packet.destinationPort || '-'} utilizing protocol ${packet.protocol}. ${
            packet.isSuspicious
              ? 'Abnormal pattern matching observed signatures in active IDS rules.'
              : 'Protocol headers and flag sequence conform to expected RFC specifications.'
          }`,
          indicatorsOfCompromise: [packet.sourceIp, `${packet.destinationIp}:${packet.destinationPort || '-'}`],
          mitigationRules: [
            {
              tool: 'iptables',
              rule: `iptables -A INPUT -s ${packet.sourceIp} -p tcp --dport ${packet.destinationPort || 80} -j DROP`,
            },
            {
              tool: 'Suricata',
              rule: `alert tcp ${packet.sourceIp} any -> any ${packet.destinationPort || 80} (msg:"Suspicious inbound probe from ${packet.sourceIp}"; sid:1000001; rev:1;)`,
            },
          ],
          immediateAction: packet.isSuspicious
            ? 'Quarantine source IP on perimeter edge router and inspect related sessions in firewall logs.'
            : 'No immediate remediation required. Continue passive monitoring.',
        },
      });
    }

    const prompt = `You are a Principal Cyber Security Incident Responder and Network Intrusion Analyst.
Analyze the following captured network packet metadata and payload:
Packet Details:
- ID: ${packet.id}
- Timestamp: ${packet.timestamp}
- Protocol: ${packet.protocol}
- Source IP: ${packet.sourceIp} (Port: ${packet.sourcePort ?? 'N/A'})
- Destination IP: ${packet.destinationIp} (Port: ${packet.destinationPort ?? 'N/A'})
- Packet Size: ${packet.length} bytes
- Flags: ${packet.flags ? JSON.stringify(packet.flags) : 'N/A'}
- Summary: ${packet.info || ''}
- Suspicious Flagged: ${packet.isSuspicious ? 'YES - ' + packet.threatInfo : 'NO'}
- Payload Preview (Hex/ASCII): ${packet.payloadPreview || 'N/A'}

Provide an authoritative security analysis formatted in JSON matching this schema:
{
  "threatAssessment": string (e.g., "Nmap SYN Stealth Scan Probe", "DNS Exfiltration Subdomain Chunk", "Legitimate HTTPS TLS Handshake"),
  "confidenceScore": number (0 to 100),
  "mitreAttack": string (e.g. "T1046: Network Service Discovery" or "T1071.004: DNS", or "None"),
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "technicalAnalysis": string (concise 2-3 paragraph technical breakdown of header flags, port target, attack vector or legitimate behavior),
  "indicatorsOfCompromise": string[] (IPs, malicious domains, attack signatures),
  "mitigationRules": [
    { "tool": string, "rule": string } (provide practical rules for iptables, Suricata, and AWS Security Group / firewall)
  ],
  "immediateAction": string (actionable advice for the SOC analyst)
}

Output ONLY valid JSON.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const text = response.text || '{}';
    let parsedAnalysis;
    try {
      parsedAnalysis = JSON.parse(text);
    } catch {
      parsedAnalysis = {
        threatAssessment: packet.threatInfo || 'Analysis complete',
        confidenceScore: 75,
        mitreAttack: 'T1046',
        severity: packet.severity || 'MEDIUM',
        technicalAnalysis: text,
        indicatorsOfCompromise: [packet.sourceIp],
        mitigationRules: [
          { tool: 'iptables', rule: `iptables -A INPUT -s ${packet.sourceIp} -j DROP` },
        ],
        immediateAction: 'Review source IP connections in perimeter log.',
      };
    }

    return res.json({ analysis: parsedAnalysis });
  } catch (err: unknown) {
    console.error('Gemini packet analysis error:', err);
    return res.status(500).json({
      error: 'Failed to analyze packet',
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// Endpoint: AI Executive SOC Summary Report
app.post('/api/generate-soc-report', async (req, res) => {
  try {
    const { stats, alerts, topTalkers } = req.body;

    if (!ai) {
      return res.json({
        report: {
          executiveSummary:
            'During the monitoring session, a total of ' +
            (stats?.totalPackets || 0) +
            ' packets were passively inspected across the interface. ' +
            (stats?.suspiciousCount || 0) +
            ' packets triggered IDS rule signatures, primarily consisting of port enumeration and abnormal DNS queries.',
          riskPosture: stats?.suspiciousCount > 10 ? 'ELEVATED' : 'NOMINAL',
          primaryThreats: [
            'Automated TCP Port Probing targeting common service ports',
            'DNS query volume spikes with high entropy subdomains',
          ],
          defensiveRecommendations: [
            'Enforce rate limiting on edge firewalls for SYN packets.',
            'Restrict outbound DNS resolution to internal secure DNS resolvers (DoH/DoT).',
            'Audit public-facing services on ports 22, 23, and 3389.',
          ],
        },
      });
    }

    const prompt = `You are a Chief Information Security Officer (CISO) and Lead Incident Responder.
Generate a concise, professional executive SOC summary report based on the following captured traffic metrics:
- Total Packets Captured: ${stats?.totalPackets || 0}
- Inbound Bandwidth: ${stats?.inboundBytes || 0} bytes
- Outbound Bandwidth: ${stats?.outboundBytes || 0} bytes
- Suspicious Packets Flagged: ${stats?.suspiciousCount || 0}
- Triggered Alerts: ${JSON.stringify(alerts?.slice(0, 5) || [])}
- Top Source IPs (Talkers): ${JSON.stringify(topTalkers || [])}

Provide the response in JSON matching:
{
  "executiveSummary": string (2-3 paragraphs high-level security overview suitable for senior management),
  "riskPosture": "LOW" | "NOMINAL" | "ELEVATED" | "CRITICAL",
  "primaryThreats": string[] (bullet points of top detected threats),
  "defensiveRecommendations": string[] (actionable defense-in-depth steps)
}
Output ONLY valid JSON.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const text = response.text || '{}';
    const parsed = JSON.parse(text);
    return res.json({ report: parsed });
  } catch (err: unknown) {
    console.error('Gemini report generation error:', err);
    return res.status(500).json({
      error: 'Failed to generate report',
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// Setup Vite middleware in dev or static files in production
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Network Traffic Analyzer] Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
