import { NetworkPacket, Protocol, TrafficDirection } from '../types/network';

function getFormattedTime(offsetMs: number = 0): { timestamp: string; timeEpoch: number } {
  const d = new Date(Date.now() - offsetMs);
  const timestamp =
    d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
  return { timestamp, timeEpoch: d.getTime() };
}

export interface PresetScenario {
  id: string;
  name: string;
  description: string;
  badge: string;
  badgeColor: string;
  generatePackets: () => NetworkPacket[];
}

export const PRESET_SCENARIOS: PresetScenario[] = [
  {
    id: 'enterprise_baseline',
    name: 'Enterprise Production Traffic (Baseline)',
    description: 'Normal corporate network traffic: HTTPS browsing, Google DNS queries, TLS handshakes, NTP clock sync, and internal SSH.',
    badge: 'BENIGN',
    badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    generatePackets: () => {
      const packets: NetworkPacket[] = [];
      let id = 1;
      const baseTime = 120000;

      const items: Array<{
        proto: Protocol;
        src: string;
        dst: string;
        sPort: number;
        dPort: number;
        len: number;
        info: string;
        dir: TrafficDirection;
        flags?: { syn?: boolean; ack?: boolean; psh?: boolean; fin?: boolean };
        dns?: { query: string; type: string };
      }> = [
        {
          proto: 'DNS',
          src: '192.168.1.105',
          dst: '8.8.8.8',
          sPort: 54120,
          dPort: 53,
          len: 74,
          info: 'Standard query A api.github.com',
          dir: 'OUTBOUND',
          dns: { query: 'api.github.com', type: 'A' },
        },
        {
          proto: 'DNS',
          src: '8.8.8.8',
          dst: '192.168.1.105',
          sPort: 53,
          dPort: 54120,
          len: 90,
          info: 'Standard query response A 140.82.121.6',
          dir: 'INBOUND',
          dns: { query: 'api.github.com', type: 'A' },
        },
        {
          proto: 'HTTPS',
          src: '192.168.1.105',
          dst: '140.82.121.6',
          sPort: 51240,
          dPort: 443,
          len: 74,
          info: '51240 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460',
          dir: 'OUTBOUND',
          flags: { syn: true },
        },
        {
          proto: 'HTTPS',
          src: '140.82.121.6',
          dst: '192.168.1.105',
          sPort: 443,
          dPort: 51240,
          len: 74,
          info: '443 → 51240 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0',
          dir: 'INBOUND',
          flags: { syn: true, ack: true },
        },
        {
          proto: 'HTTPS',
          src: '192.168.1.105',
          dst: '140.82.121.6',
          sPort: 51240,
          dPort: 443,
          len: 66,
          info: '51240 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0',
          dir: 'OUTBOUND',
          flags: { ack: true },
        },
        {
          proto: 'HTTPS',
          src: '192.168.1.105',
          dst: '140.82.121.6',
          sPort: 51240,
          dPort: 443,
          len: 517,
          info: 'Client Hello, Version: TLS 1.3, SNI: api.github.com',
          dir: 'OUTBOUND',
          flags: { psh: true, ack: true },
        },
        {
          proto: 'UDP',
          src: '192.168.1.105',
          dst: '216.239.35.0',
          sPort: 123,
          dPort: 123,
          len: 90,
          info: 'NTP Client, Version 4, NTP request mode 3',
          dir: 'OUTBOUND',
        },
        {
          proto: 'ICMP',
          src: '192.168.1.105',
          dst: '1.1.1.1',
          sPort: 0,
          dPort: 0,
          len: 84,
          info: 'Echo (ping) request  id=0x19a4, seq=1/256, ttl=64',
          dir: 'OUTBOUND',
        },
        {
          proto: 'ICMP',
          src: '1.1.1.1',
          dst: '192.168.1.105',
          sPort: 0,
          dPort: 0,
          len: 84,
          info: 'Echo (ping) reply    id=0x19a4, seq=1/256, ttl=57 (reply in 12.4ms)',
          dir: 'INBOUND',
        },
        {
          proto: 'SSH',
          src: '192.168.1.42',
          dst: '192.168.1.10',
          sPort: 49812,
          dPort: 22,
          len: 124,
          info: 'Encrypted SSH packet (SSH-2.0-OpenSSH_9.3)',
          dir: 'INTERNAL',
          flags: { psh: true, ack: true },
        },
      ];

      for (let i = 0; i < 25; i++) {
        const item = items[i % items.length];
        const offset = baseTime - i * 4500;
        const time = getFormattedTime(offset);

        packets.push({
          id: id++,
          timestamp: time.timestamp,
          timeEpoch: time.timeEpoch,
          sourceIp: item.src,
          destinationIp: item.dst,
          sourcePort: item.sPort,
          destinationPort: item.dPort,
          protocol: item.proto,
          length: item.len + Math.floor(Math.random() * 40),
          info: item.info,
          direction: item.dir,
          flags: item.flags,
          isSuspicious: false,
          dnsQuery: item.dns?.query,
          dnsType: item.dns?.type,
          rawHex: `0000   00 1a 2b 3c 4d 5e 00 50 56 c0 00 08 08 00 45 00   ..+<M^.PV.....E.\n0010   00 3c ${Math.floor(Math.random() * 99).toString(16).padStart(2, '0')} 00 40 00 40 06 b8 61 c0 a8 01 69 c0 a8   .<...@.@..a...i..\n0020   01 01 c8 01 00 50 00 00 00 00 00 00 00 00 a0 02   .....P..........`,
          payloadPreview: item.proto === 'HTTPS' ? '.....api.github.com..........' : '..ping.payload.data..',
          ttl: 64,
        });
      }

      return packets;
    },
  },
  {
    id: 'port_scan',
    name: 'Nmap SYN Stealth Port Scan Investigation',
    description: 'Adversary scanning internal host across 20+ common ports looking for vulnerable exposed services.',
    badge: 'ATTACK: RECON',
    badgeColor: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    generatePackets: () => {
      const packets: NetworkPacket[] = [];
      let id = 1;
      const attackerIp = '198.51.100.44';
      const targetIp = '192.168.1.105';
      const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200];
      const baseOffset = 45000;

      ports.forEach((targetPort, idx) => {
        const offset = baseOffset - idx * 750;
        const time = getFormattedTime(offset);
        const srcPort = 40000 + Math.floor(Math.random() * 20000);

        packets.push({
          id: id++,
          timestamp: time.timestamp,
          timeEpoch: time.timeEpoch,
          sourceIp: attackerIp,
          destinationIp: targetIp,
          sourcePort: srcPort,
          destinationPort: targetPort,
          protocol: 'TCP',
          length: 58,
          info: `${srcPort} → ${targetPort} [SYN] Seq=0 Win=1024 Len=0 (Nmap probe)`,
          direction: 'INBOUND',
          flags: { syn: true },
          isSuspicious: true,
          threatInfo: 'Horizontal / Vertical Port Scan Detected',
          severity: 'CRITICAL',
          category: 'PORT_SCAN',
          mitreId: 'T1046',
          ttl: 52,
          rawHex: `0000   00 1a 2b 3c 4d 5e f8 1e 32 4a 88 90 08 00 45 00   ..+<M^..2J....E.\n0010   00 28 d4 12 00 00 34 06 a1 f0 c6 33 64 2c c0 a8   .(....4....3d,..`,
          payloadPreview: 'nmap-syn-scan-probe',
        });

        // Add RST response for closed ports
        if (targetPort !== 80 && targetPort !== 443 && targetPort !== 22) {
          const respTime = getFormattedTime(offset - 4);
          packets.push({
            id: id++,
            timestamp: respTime.timestamp,
            timeEpoch: respTime.timeEpoch,
            sourceIp: targetIp,
            destinationIp: attackerIp,
            sourcePort: targetPort,
            destinationPort: srcPort,
            protocol: 'TCP',
            length: 54,
            info: `${targetPort} → ${srcPort} [RST, ACK] Seq=1 Ack=1 Win=0 Len=0`,
            direction: 'OUTBOUND',
            flags: { rst: true, ack: true },
            isSuspicious: false,
            ttl: 64,
          });
        }
      });

      return packets;
    },
  },
  {
    id: 'dns_exfiltration',
    name: 'DNS Tunneling & Data Exfiltration Attempt',
    description: 'Malware exfiltrating sensitive credentials and system files inside high-entropy base64 DNS queries.',
    badge: 'ATTACK: EXFILTRATION',
    badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    generatePackets: () => {
      const packets: NetworkPacket[] = [];
      let id = 1;
      const infectedHost = '192.168.1.189';
      const dnsServer = '8.8.8.8';

      const encodedChunks = [
        'dGhpc19pc19zZWNyZXRfY3JlZGVudGlhbHNfcm9vdA==',
        'cGFzc3dvcmQ9U3VwZXJTZWNyZXQyMDI2IQ==',
        'Y29uZmlnLmtleS5wZW0uZXhmaWx0cmF0ZWQ=',
        'ZXhjaGFuZ2Vfc2VydmVyX250bG1faGFzaA==',
        'c2hhMjU2X2JpdGNvaW5fd2FsbGV0X3NlZWQ=',
        'YWRtaW5fc2Vzc2lvbl90b2tlbl9qd3Q=',
      ];

      encodedChunks.forEach((chunk, idx) => {
        const offset = 30000 - idx * 2500;
        const time = getFormattedTime(offset);
        const query = `${chunk}.v1.tunnel.attacker-c2.xyz`;

        packets.push({
          id: id++,
          timestamp: time.timestamp,
          timeEpoch: time.timeEpoch,
          sourceIp: infectedHost,
          destinationIp: dnsServer,
          sourcePort: 51900 + idx,
          destinationPort: 53,
          protocol: 'DNS',
          length: 124 + chunk.length,
          info: `Standard query TXT ${query}`,
          direction: 'OUTBOUND',
          isSuspicious: true,
          threatInfo: 'Suspected DNS Tunneling / Exfiltration Query',
          severity: 'HIGH',
          category: 'DNS_TUNNEL',
          mitreId: 'T1071.004',
          dnsQuery: query,
          dnsType: 'TXT',
          payloadPreview: query,
          rawHex: `0000   00 1a 2b 3c 4d 5e 00 50 56 c0 00 08 08 00 45 00   ..+<M^.PV.....E.\n0010   00 78 c2 99 00 00 40 11 9b 12 c0 a8 01 bd 08 08   .x....@.........`,
          ttl: 64,
        });
      });

      return packets;
    },
  },
  {
    id: 'syn_flood_ddos',
    name: 'SYN Flood Distributed Denial of Service (DDoS)',
    description: 'High-volume volume attack flooding web application port 443 with half-open connections.',
    badge: 'ATTACK: DDOS',
    badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    generatePackets: () => {
      const packets: NetworkPacket[] = [];
      let id = 1;
      const targetIp = '192.168.1.105';
      const botIps = [
        '45.33.32.156',
        '185.220.101.5',
        '194.26.29.112',
        '91.240.118.172',
        '203.0.113.195',
      ];

      for (let i = 0; i < 35; i++) {
        const bot = botIps[i % botIps.length];
        const offset = 15000 - i * 200;
        const time = getFormattedTime(offset);
        const sPort = 30000 + Math.floor(Math.random() * 30000);

        packets.push({
          id: id++,
          timestamp: time.timestamp,
          timeEpoch: time.timeEpoch,
          sourceIp: bot,
          destinationIp: targetIp,
          sourcePort: sPort,
          destinationPort: 443,
          protocol: 'TCP',
          length: 60,
          info: `${sPort} → 443 [SYN] Seq=${100000 + i * 150} Win=512 Len=0 (Flooding)`,
          direction: 'INBOUND',
          flags: { syn: true },
          isSuspicious: true,
          threatInfo: 'Potential TCP SYN Flood / DoS Attack',
          severity: 'CRITICAL',
          category: 'SYN_FLOOD',
          mitreId: 'T1498.001',
          ttl: 48,
          rawHex: `0000   00 1a 2b 3c 4d 5e 52 54 00 12 34 56 08 00 45 00   ..+<M^RT..4V..E.\n0010   00 3c 00 00 40 00 30 06 c8 44 2d 21 20 9c c0 a8   .<..@.0..D-! ...`,
          payloadPreview: 'syn-flood-burst',
        });
      }

      return packets;
    },
  },
];

/**
 * Real-time packet generator simulating a live network tap.
 * Yields normal background packets mixed with occasional anomalous packets.
 */
export function generateLivePacket(id: number, injectThreat = false): NetworkPacket {
  const time = getFormattedTime(0);
  const protocols: Protocol[] = ['HTTPS', 'HTTPS', 'HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'SSH'];
  let proto: Protocol = injectThreat ? 'TCP' : protocols[Math.floor(Math.random() * protocols.length)];

  let srcIp = '192.168.1.105';
  let dstIp = '142.250.190.46';
  let sPort: number | null = 50000 + Math.floor(Math.random() * 15000);
  let dPort: number | null = 443;
  let info = '';
  let dir: TrafficDirection = 'OUTBOUND';
  let len = 60 + Math.floor(Math.random() * 1100);
  let flags = undefined;
  let dnsQuery = undefined;
  let dnsType = undefined;
  let isSuspicious = false;
  let threatInfo = undefined;
  let severity = undefined;
  let category = undefined;
  let mitreId = undefined;

  if (injectThreat) {
    // Generate an injected attack packet
    const threatTypes = ['PORT_SCAN', 'DNS_TUNNEL', 'INSECURE_TELNET', 'BRUTE_FORCE'];
    const chosen = threatTypes[Math.floor(Math.random() * threatTypes.length)];

    if (chosen === 'PORT_SCAN') {
      srcIp = '198.51.100.44';
      dstIp = '192.168.1.105';
      sPort = 44921;
      dPort = [21, 22, 23, 25, 80, 443, 3389, 8080][Math.floor(Math.random() * 8)];
      dir = 'INBOUND';
      flags = { syn: true };
      info = `${sPort} → ${dPort} [SYN] Seq=0 Win=1024 Len=0 (Probe)`;
      isSuspicious = true;
      threatInfo = 'Horizontal / Vertical Port Scan Detected';
      severity = 'HIGH' as const;
      category = 'PORT_SCAN' as const;
      mitreId = 'T1046';
    } else if (chosen === 'DNS_TUNNEL') {
      srcIp = '192.168.1.189';
      dstIp = '8.8.8.8';
      sPort = 53892;
      dPort = 53;
      proto = 'DNS';
      dir = 'OUTBOUND';
      const chunk = Math.random().toString(36).substring(2, 14) + Math.random().toString(36).substring(2, 14);
      dnsQuery = `${chunk}.stage3.tunnel.attacker.xyz`;
      dnsType = 'TXT';
      info = `Standard query TXT ${dnsQuery}`;
      isSuspicious = true;
      threatInfo = 'Suspected DNS Tunneling / Exfiltration Query';
      severity = 'HIGH' as const;
      category = 'DNS_TUNNEL' as const;
      mitreId = 'T1071.004';
    } else if (chosen === 'INSECURE_TELNET') {
      srcIp = '192.168.1.201';
      dstIp = '192.168.1.10';
      sPort = 58210;
      dPort = 23;
      proto = 'TELNET';
      dir = 'INTERNAL';
      flags = { psh: true, ack: true };
      info = 'Telnet command: login root / password: admin';
      isSuspicious = true;
      threatInfo = 'Unencrypted Telnet Session Detected';
      severity = 'MEDIUM' as const;
      category = 'CLEARTEXT_AUTH' as const;
      mitreId = 'T1552.001';
    } else {
      srcIp = '203.0.113.195';
      dstIp = '192.168.1.105';
      sPort = 52140;
      dPort = 22;
      proto = 'SSH';
      dir = 'INBOUND';
      flags = { syn: true };
      info = `${sPort} → 22 [SYN] SSH Auth Attempt`;
      isSuspicious = true;
      threatInfo = 'Repeated SSH Authentication Probes (Brute Force)';
      severity = 'HIGH' as const;
      category = 'BRUTE_FORCE' as const;
      mitreId = 'T1110.001';
    }
  } else {
    // Normal traffic
    const externalHosts = [
      { ip: '142.250.190.46', name: 'Google Cloud' },
      { ip: '151.101.1.140', name: 'Fastly CDN' },
      { ip: '104.16.132.229', name: 'Cloudflare Edge' },
      { ip: '13.107.42.14', name: 'Microsoft 365' },
      { ip: '140.82.121.3', name: 'GitHub' },
    ];
    const host = externalHosts[Math.floor(Math.random() * externalHosts.length)];

    if (proto === 'HTTPS') {
      dstIp = host.ip;
      dPort = 443;
      flags = { ack: true, psh: Math.random() > 0.5 };
      info = `${sPort} → 443 [ACK] Seq=${1000 + id} Ack=${2000 + id} Win=64240 Len=${len}`;
    } else if (proto === 'DNS') {
      dstIp = '8.8.8.8';
      dPort = 53;
      const domains = ['cloudflare.com', 'google.com', 'aws.amazon.com', 'github.com', 'wikipedia.org', 'slack.com'];
      dnsQuery = domains[Math.floor(Math.random() * domains.length)];
      dnsType = 'A';
      info = `Standard query ${dnsType} ${dnsQuery}`;
    } else if (proto === 'ICMP') {
      dstIp = '1.1.1.1';
      sPort = null;
      dPort = null;
      info = `Echo (ping) request seq=${id % 100} ttl=64`;
    } else if (proto === 'HTTP') {
      dstIp = host.ip;
      dPort = 80;
      flags = { psh: true, ack: true };
      info = `GET /api/v1/health HTTP/1.1 (Host: ${host.name.toLowerCase().replace(' ', '')}.com)`;
    } else {
      dstIp = host.ip;
      dPort = 8080;
      flags = { ack: true };
      info = `${sPort} → 8080 [ACK] Len=${len}`;
    }
  }

  return {
    id,
    timestamp: time.timestamp,
    timeEpoch: time.timeEpoch,
    sourceIp: srcIp,
    destinationIp: dstIp,
    sourcePort: sPort,
    destinationPort: dPort,
    protocol: proto,
    length: len,
    info,
    direction: dir,
    flags,
    isSuspicious,
    threatInfo,
    severity,
    category,
    mitreId,
    dnsQuery,
    dnsType,
    rawHex: `0000   00 1a 2b 3c 4d 5e 00 50 56 c0 00 08 08 00 45 00\n0010   00 ${len.toString(16).padStart(2, '0')} 4a 12 00 00 40 06 .. .. c0 a8 01 69 .. .. .. ..`,
    payloadPreview: dnsQuery || info.slice(0, 32),
    ttl: 64,
  };
}
