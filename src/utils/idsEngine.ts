import {
  AlertSeverity,
  NetworkPacket,
  SecurityAlert,
  ThreatCategory,
} from '../types/network';

interface PortScanTracker {
  ports: Set<number>;
  firstSeen: number;
  lastSeen: number;
}

interface SynFloodTracker {
  synTimestamps: number[];
}

interface BruteForceTracker {
  attempts: number[];
}

interface BeaconTracker {
  timestamps: number[];
}

// Shannon entropy calculation for DNS tunneling detection
function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export class IdsEngine {
  private portScanState: Map<string, PortScanTracker> = new Map();
  private synFloodState: Map<string, SynFloodTracker> = new Map();
  private bruteForceState: Map<string, BruteForceTracker> = new Map();
  private beaconState: Map<string, BeaconTracker> = new Map();
  private generatedAlerts: SecurityAlert[] = [];

  // Known suspicious threat feeds / C2 indicators for simulation & detection
  private static readonly KNOWN_MALICIOUS_IPS = new Set([
    '198.51.100.44',
    '203.0.113.195',
    '45.33.32.156',
    '185.220.101.5',
    '194.26.29.112',
    '91.240.118.172',
  ]);

  private static readonly SUSPICIOUS_DNS_TLDS = ['.tk', '.xyz', '.top', '.ru', '.onion', '.pw'];

  public reset(): void {
    this.portScanState.clear();
    this.synFloodState.clear();
    this.bruteForceState.clear();
    this.beaconState.clear();
    this.generatedAlerts = [];
  }

  /**
   * Evaluates packet against intrusion detection rules.
   * Modifies packet in-place with threat flags and returns any newly triggered alert.
   */
  public inspectPacket(packet: NetworkPacket): SecurityAlert | null {
    const now = packet.timeEpoch || Date.now();
    let triggeredCategory: ThreatCategory | null = null;
    let severity: AlertSeverity = 'LOW';
    let title = '';
    let description = '';
    let mitreId = '';

    // 1. Known Malicious C2 / Threat Intel match
    if (
      IdsEngine.KNOWN_MALICIOUS_IPS.has(packet.sourceIp) ||
      IdsEngine.KNOWN_MALICIOUS_IPS.has(packet.destinationIp)
    ) {
      triggeredCategory = 'BEACONING';
      severity = 'CRITICAL';
      mitreId = 'T1071.001';
      title = 'Known Threat Actor / C2 Communication Detected';
      description = `Traffic identified communicating with known malicious indicator (${
        IdsEngine.KNOWN_MALICIOUS_IPS.has(packet.destinationIp) ? packet.destinationIp : packet.sourceIp
      }) associated with Active Threat Feeds.`;
    }

    // 2. DNS Tunneling & Exfiltration Detection
    if (!triggeredCategory && packet.protocol === 'DNS' && packet.dnsQuery) {
      const query = packet.dnsQuery.toLowerCase();
      const entropy = calculateShannonEntropy(query);
      const isLongSubdomain = query.length > 28;
      const isSuspiciousTld = IdsEngine.SUSPICIOUS_DNS_TLDS.some((tld) => query.endsWith(tld));

      if ((isLongSubdomain && entropy > 3.6) || isSuspiciousTld || query.includes('tunnel') || query.includes('exfil')) {
        triggeredCategory = 'DNS_TUNNEL';
        severity = 'HIGH';
        mitreId = 'T1071.004';
        title = 'Suspected DNS Tunneling / Exfiltration Query';
        description = `High-entropy DNS query detected: "${packet.dnsQuery}" (Entropy: ${entropy.toFixed(2)}, Length: ${query.length}). Potential data covert exfiltration.`;
      }
    }

    // 3. Cleartext Credentials / Insecure Protocols
    if (!triggeredCategory) {
      if (packet.destinationPort === 23 || packet.sourcePort === 23) {
        triggeredCategory = 'CLEARTEXT_AUTH';
        severity = 'MEDIUM';
        mitreId = 'T1552.001';
        title = 'Unencrypted Telnet Session Detected';
        description = `Insecure plaintext Telnet protocol in use on port 23 between ${packet.sourceIp} and ${packet.destinationIp}. Passwords and sessions transmitted in the clear.`;
      } else if (
        (packet.destinationPort === 21 || packet.sourcePort === 21) &&
        packet.payloadPreview &&
        (packet.payloadPreview.includes('USER') || packet.payloadPreview.includes('PASS'))
      ) {
        triggeredCategory = 'CLEARTEXT_AUTH';
        severity = 'HIGH';
        mitreId = 'T1552.001';
        title = 'Cleartext FTP Authentication Transmission';
        description = `Plaintext FTP authentication commands observed in packet payload between ${packet.sourceIp} and ${packet.destinationIp}.`;
      }
    }

    // 4. Port Scan Detection (Sliding Window on source IP)
    if (!triggeredCategory && packet.protocol === 'TCP' && packet.destinationPort !== null && packet.flags?.syn && !packet.flags.ack) {
      const key = packet.sourceIp;
      let tracker = this.portScanState.get(key);
      if (!tracker) {
        tracker = { ports: new Set(), firstSeen: now, lastSeen: now };
        this.portScanState.set(key, tracker);
      }

      // Reset tracker if older than 15 seconds
      if (now - tracker.firstSeen > 15000) {
        tracker.ports.clear();
        tracker.firstSeen = now;
      }

      tracker.ports.add(packet.destinationPort);
      tracker.lastSeen = now;

      if (tracker.ports.size >= 5) {
        triggeredCategory = 'PORT_SCAN';
        severity = tracker.ports.size >= 12 ? 'CRITICAL' : 'HIGH';
        mitreId = 'T1046';
        title = 'Horizontal / Vertical Port Scan Detected';
        description = `Source IP ${packet.sourceIp} probed ${tracker.ports.size} distinct ports within a 15-second window. Indicative of automated Nmap reconnaissance.`;
      }
    }

    // 5. SYN Flood / DoS Detection
    if (!triggeredCategory && packet.flags?.syn && !packet.flags?.ack) {
      const key = `${packet.destinationIp}:${packet.destinationPort}`;
      let tracker = this.synFloodState.get(key);
      if (!tracker) {
        tracker = { synTimestamps: [] };
        this.synFloodState.set(key, tracker);
      }

      tracker.synTimestamps.push(now);
      // Keep only timestamps from last 3 seconds
      tracker.synTimestamps = tracker.synTimestamps.filter((t) => now - t <= 3000);

      if (tracker.synTimestamps.length >= 10) {
        triggeredCategory = 'SYN_FLOOD';
        severity = 'CRITICAL';
        mitreId = 'T1498.001';
        title = 'Potential TCP SYN Flood / DoS Attack';
        description = `Target ${key} received ${tracker.synTimestamps.length} SYN packets without ACK in under 3 seconds. Resource exhaustion attempt likely.`;
      }
    }

    // 6. Brute Force Detection (repeated attempts on SSH port 22 or RDP 3389)
    if (!triggeredCategory && (packet.destinationPort === 22 || packet.destinationPort === 3389)) {
      const key = `${packet.sourceIp}->${packet.destinationPort}`;
      let tracker = this.bruteForceState.get(key);
      if (!tracker) {
        tracker = { attempts: [] };
        this.bruteForceState.set(key, tracker);
      }

      tracker.attempts.push(now);
      tracker.attempts = tracker.attempts.filter((t) => now - t <= 12000);

      if (tracker.attempts.length >= 4) {
        triggeredCategory = 'BRUTE_FORCE';
        severity = 'HIGH';
        mitreId = 'T1110.001';
        const serviceName = packet.destinationPort === 22 ? 'SSH' : 'RDP';
        title = `Repeated ${serviceName} Authentication Probes (Brute Force)`;
        description = `Host ${packet.sourceIp} generated ${tracker.attempts.length} consecutive connection requests to ${serviceName} on ${packet.destinationIp} within 12 seconds.`;
      }
    }

    // 7. Unusual Port Anomaly (e.g., Trojan backdoor ports 4444, 1337, 31337, 6667)
    if (!triggeredCategory && packet.destinationPort !== null) {
      const backdoorPorts = [4444, 1337, 31337, 5555, 6667, 8888, 9999];
      if (backdoorPorts.includes(packet.destinationPort)) {
        triggeredCategory = 'UNUSUAL_PORT';
        severity = 'MEDIUM';
        mitreId = 'T1571';
        title = `Communication on Suspicious High-Risk Port (${packet.destinationPort})`;
        description = `Traffic destined to non-standard port ${packet.destinationPort} commonly associated with Metasploit shells or IRC botnets.`;
      }
    }

    if (triggeredCategory) {
      packet.isSuspicious = true;
      packet.threatInfo = title;
      packet.severity = severity;
      packet.category = triggeredCategory;
      packet.mitreId = mitreId;

      // Rate limit identical alert generation (1 per 4 seconds per category + source IP)
      const isDuplicate = this.generatedAlerts.some(
        (a) =>
          a.category === triggeredCategory &&
          a.sourceIp === packet.sourceIp &&
          now - a.timeEpoch < 4000
      );

      if (!isDuplicate) {
        const alert: SecurityAlert = {
          id: `ALT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          timestamp: packet.timestamp,
          timeEpoch: now,
          severity,
          category: triggeredCategory,
          title,
          description,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          destinationPort: packet.destinationPort ?? undefined,
          protocol: packet.protocol,
          packetId: packet.id,
          mitreId,
          acknowledged: false,
          resolved: false,
          explanation: `Automated detection triggered by passive IDS signature matching behavioral heuristic and MITRE ATT&CK technique ${mitreId}.`,
        };

        this.generatedAlerts.unshift(alert);
        // Keep max 200 alerts
        if (this.generatedAlerts.length > 200) {
          this.generatedAlerts.pop();
        }
        return alert;
      }
    }

    return null;
  }

  public getAlerts(): SecurityAlert[] {
    return this.generatedAlerts;
  }
}
