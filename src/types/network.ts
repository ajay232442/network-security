export type Protocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'DNS'
  | 'HTTP'
  | 'HTTPS'
  | 'ARP'
  | 'SSH'
  | 'FTP'
  | 'TELNET';

export type TrafficDirection = 'INBOUND' | 'OUTBOUND' | 'INTERNAL';

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
  | 'PORT_SCAN'
  | 'BRUTE_FORCE'
  | 'DNS_TUNNEL'
  | 'SYN_FLOOD'
  | 'CLEARTEXT_AUTH'
  | 'UNUSUAL_PORT'
  | 'BEACONING'
  | 'ANOMALOUS_TRAFFIC';

export interface TcpFlags {
  syn?: boolean;
  ack?: boolean;
  fin?: boolean;
  rst?: boolean;
  psh?: boolean;
  urg?: boolean;
}

export interface NetworkPacket {
  id: number;
  timestamp: string;
  timeEpoch: number;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: Protocol;
  length: number;
  info: string;
  direction: TrafficDirection;
  flags?: TcpFlags;
  isSuspicious: boolean;
  threatInfo?: string;
  severity?: AlertSeverity;
  category?: ThreatCategory;
  mitreId?: string;
  rawHex?: string;
  payloadPreview?: string;
  ttl?: number;
  ipId?: number;
  checksum?: string;
  macSrc?: string;
  macDst?: string;
  dnsQuery?: string;
  dnsType?: string;
  httpMethod?: string;
  httpUri?: string;
  httpStatusCode?: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  timeEpoch: number;
  severity: AlertSeverity;
  category: ThreatCategory;
  title: string;
  description: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort?: number;
  protocol: string;
  packetId: number;
  mitreId: string;
  acknowledged: boolean;
  resolved: boolean;
  explanation?: string;
}

export interface TrafficStats {
  totalPackets: number;
  inboundBytes: number;
  outboundBytes: number;
  internalBytes: number;
  totalBytes: number;
  currentBps: number;
  currentPps: number;
  suspiciousCount: number;
  protocolCounts: Record<string, number>;
  severityCounts: Record<AlertSeverity, number>;
}

export interface FilterCriteria {
  search: string;
  protocol: string;
  sourceIp: string;
  destinationIp: string;
  port: string;
  suspiciousOnly: boolean;
  severity: string;
  direction: string;
  timeRange: string;
}

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  ip: string;
  netmask: string;
  mac: string;
  status: string;
  promiscuous: boolean;
  rxPackets: number;
  txPackets: number;
  speed: string;
}

export interface AiPacketAnalysis {
  threatAssessment: string;
  confidenceScore: number;
  mitreAttack: string;
  severity: AlertSeverity;
  technicalAnalysis: string;
  indicatorsOfCompromise: string[];
  mitigationRules: { tool: string; rule: string }[];
  immediateAction: string;
}

export interface ExecutiveReportData {
  executiveSummary: string;
  riskPosture: 'LOW' | 'NOMINAL' | 'ELEVATED' | 'CRITICAL';
  primaryThreats: string[];
  defensiveRecommendations: string[];
  stats: TrafficStats;
  topTalkers: { ip: string; packets: number; bytes: number; role: 'source' | 'destination' }[];
  topAlerts: SecurityAlert[];
  generatedAt: string;
}

export interface GeoLocation {
  ip: string;
  country: string;
  countryCode: string;
  flag: string;
  city: string;
  latitude: number;
  longitude: number;
  asn?: string;
  org?: string;
  isPrivate: boolean;
}

export interface GeoConnection {
  id: string;
  sourceIp: string;
  destinationIp: string;
  sourceGeo: GeoLocation;
  destinationGeo: GeoLocation;
  protocol: Protocol;
  packetCount: number;
  byteCount: number;
  lastSeen: number;
  isThreat: boolean;
  severity?: AlertSeverity;
  category?: ThreatCategory;
}

