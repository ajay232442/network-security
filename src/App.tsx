import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  NetworkPacket,
  SecurityAlert,
  TrafficStats,
  FilterCriteria,
  NetworkInterfaceInfo,
} from './types/network';
import { IdsEngine } from './utils/idsEngine';
import { generateLivePacket, PRESET_SCENARIOS } from './utils/samplePcaps';
import { Header } from './components/Header';
import { StatsOverview } from './components/StatsOverview';
import { TrafficCharts } from './components/TrafficCharts';
import { GeographicMap } from './components/GeographicMap';
import { PacketTable } from './components/PacketTable';
import { PacketInspectorModal } from './components/PacketInspectorModal';
import { AlertsDrawer } from './components/AlertsDrawer';
import { PcapUploadModal } from './components/PcapUploadModal';
import { ReportModal } from './components/ReportModal';
import { Globe, Activity, LayoutGrid } from 'lucide-react';

export default function App() {
  // Capture State
  const [isCapturing, setIsCapturing] = useState<boolean>(true);
  const [captureSpeed, setCaptureSpeed] = useState<number>(1);
  const [packets, setPackets] = useState<NetworkPacket[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<NetworkPacket | null>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [visualTab, setVisualTab] = useState<'BOTH' | 'MAP' | 'CHARTS'>('BOTH');

  // Modals & Drawers
  const [isAlertsOpen, setIsAlertsOpen] = useState<boolean>(false);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);

  // Interfaces
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([
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
      name: 'tun0 (WireGuard VPN)',
      ip: '10.8.0.4',
      netmask: '255.255.255.255',
      mac: '00:00:00:00:00:00',
      status: 'UP',
      promiscuous: true,
      rxPackets: 65120,
      txPackets: 41200,
      speed: '300 Mbps',
    },
  ]);
  const [selectedInterface, setSelectedInterface] = useState<string>('eth0');

  // IDS Engine instance
  const idsEngineRef = useRef<IdsEngine>(new IdsEngine());
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);

  // Waveform History (rolling 30 seconds)
  const [throughputHistory, setThroughputHistory] = useState<
    Array<{ time: string; inboundBytes: number; outboundBytes: number; pps: number }>
  >([]);

  // Filters
  const [filters, setFilters] = useState<FilterCriteria>({
    search: '',
    protocol: 'ALL',
    sourceIp: '',
    destinationIp: '',
    port: '',
    suspiciousOnly: false,
    severity: 'ALL',
    direction: 'ALL',
    timeRange: 'ALL',
  });

  // Load interfaces from backend on startup
  useEffect(() => {
    fetch('/api/network-interfaces')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && data.interfaces?.length > 0) {
          setInterfaces(data.interfaces);
        }
      })
      .catch((err) => console.log('Using default interface config:', err));
  }, []);

  // Initialize with initial baseline scenario
  useEffect(() => {
    const baseline = PRESET_SCENARIOS[0].generatePackets();
    const evaluatedPackets = baseline.map((p) => {
      const alert = idsEngineRef.current.inspectPacket(p);
      if (alert) {
        setAlerts((prev) => [alert, ...prev]);
      }
      return p;
    });
    setPackets(evaluatedPackets);
  }, []);

  // Streaming Live Packet Capture Loop
  const packetIdCounter = useRef<number>(50);
  const recentInboundBytes = useRef<number>(0);
  const recentOutboundBytes = useRef<number>(0);
  const recentPps = useRef<number>(0);

  useEffect(() => {
    if (!isCapturing) return;

    // Interval inversely proportional to captureSpeed
    const intervalMs = Math.max(120, Math.floor(1000 / (captureSpeed * 2.5)));

    const timer = setInterval(() => {
      packetIdCounter.current += 1;
      // Occasional random threat injection during live streaming (~4% chance)
      const injectThreat = Math.random() < 0.04;
      const newPacket = generateLivePacket(packetIdCounter.current, injectThreat);

      // Inspect through IDS rules
      const alert = idsEngineRef.current.inspectPacket(newPacket);
      if (alert) {
        setAlerts((prev) => [alert, ...prev.slice(0, 199)]);
      }

      // Record byte meters
      if (newPacket.direction === 'INBOUND') {
        recentInboundBytes.current += newPacket.length;
      } else if (newPacket.direction === 'OUTBOUND') {
        recentOutboundBytes.current += newPacket.length;
      }
      recentPps.current += 1;

      setPackets((prev) => {
        const next = [...prev, newPacket];
        // Retain max 1500 packets in memory
        return next.length > 1500 ? next.slice(next.length - 1500) : next;
      });
    }, intervalMs);

    return () => clearInterval(timer);
  }, [isCapturing, captureSpeed]);

  // Periodic Throughput Waveform Sampler (every 1 second)
  useEffect(() => {
    const sampler = setInterval(() => {
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];

      setThroughputHistory((prev) => {
        const sample = {
          time: timeStr,
          inboundBytes: recentInboundBytes.current,
          outboundBytes: recentOutboundBytes.current,
          pps: recentPps.current,
        };

        // Reset rolling meters
        recentInboundBytes.current = 0;
        recentOutboundBytes.current = 0;
        recentPps.current = 0;

        const next = [...prev, sample];
        return next.length > 30 ? next.slice(next.length - 30) : next;
      });
    }, 1000);

    return () => clearInterval(sampler);
  }, []);

  // Compute Traffic Statistics
  const stats: TrafficStats = useMemo(() => {
    let inboundBytes = 0;
    let outboundBytes = 0;
    let internalBytes = 0;
    let suspiciousCount = 0;
    const protocolCounts: Record<string, number> = {};
    const severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

    packets.forEach((p) => {
      if (p.direction === 'INBOUND') inboundBytes += p.length;
      else if (p.direction === 'OUTBOUND') outboundBytes += p.length;
      else internalBytes += p.length;

      protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;

      if (p.isSuspicious) {
        suspiciousCount++;
        if (p.severity) {
          severityCounts[p.severity] = (severityCounts[p.severity] || 0) + 1;
        }
      }
    });

    const totalBytes = inboundBytes + outboundBytes + internalBytes;
    const lastSample = throughputHistory[throughputHistory.length - 1];
    const currentBps = lastSample ? lastSample.inboundBytes + lastSample.outboundBytes : 0;
    const currentPps = lastSample ? lastSample.pps : 0;

    return {
      totalPackets: packets.length,
      inboundBytes,
      outboundBytes,
      internalBytes,
      totalBytes,
      currentBps,
      currentPps,
      suspiciousCount,
      protocolCounts,
      severityCounts,
    };
  }, [packets, throughputHistory]);

  // Filtered Packets
  const filteredPackets = useMemo(() => {
    return packets.filter((p) => {
      // Search
      if (filters.search) {
        const s = filters.search.toLowerCase();
        const matchesIp = p.sourceIp.includes(s) || p.destinationIp.includes(s);
        const matchesPort =
          (p.sourcePort && String(p.sourcePort).includes(s)) ||
          (p.destinationPort && String(p.destinationPort).includes(s));
        const matchesInfo = p.info.toLowerCase().includes(s);
        const matchesProto = p.protocol.toLowerCase().includes(s);
        const matchesDns = p.dnsQuery && p.dnsQuery.toLowerCase().includes(s);
        if (!matchesIp && !matchesPort && !matchesInfo && !matchesProto && !matchesDns) {
          return false;
        }
      }

      // Protocol
      if (filters.protocol !== 'ALL' && p.protocol !== filters.protocol) {
        return false;
      }

      // Direction
      if (filters.direction !== 'ALL' && p.direction !== filters.direction) {
        return false;
      }

      // Suspicious Only
      if (filters.suspiciousOnly && !p.isSuspicious) {
        return false;
      }

      // Severity
      if (filters.severity !== 'ALL' && p.severity !== filters.severity) {
        return false;
      }

      return true;
    });
  }, [packets, filters]);

  // Handlers
  const handleToggleCapture = () => setIsCapturing((prev) => !prev);

  const handleClearCapture = () => {
    setPackets([]);
    idsEngineRef.current.reset();
    setAlerts([]);
    setSelectedPacket(null);
  };

  const handleInjectThreat = () => {
    packetIdCounter.current += 1;
    const threatPkt = generateLivePacket(packetIdCounter.current, true);
    const alert = idsEngineRef.current.inspectPacket(threatPkt);
    if (alert) {
      setAlerts((prev) => [alert, ...prev]);
    }
    setPackets((prev) => [...prev, threatPkt]);
  };

  const handleLoadPackets = (newPackets: NetworkPacket[]) => {
    idsEngineRef.current.reset();
    const evaluated = newPackets.map((p) => {
      const alert = idsEngineRef.current.inspectPacket(p);
      if (alert) {
        setAlerts((prev) => [alert, ...prev]);
      }
      return p;
    });
    setPackets(evaluated);
    packetIdCounter.current = Math.max(100, evaluated.length + 1);
  };

  const handleInspectPacketById = (id: number) => {
    const found = packets.find((p) => p.id === id);
    if (found) {
      setSelectedPacket(found);
      setIsAlertsOpen(false);
    }
  };

  const handleAcknowledgeAlert = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a))
    );
  };

  const handleResolveAlert = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, resolved: true, acknowledged: true } : a))
    );
  };

  const handleClearResolved = () => {
    setAlerts((prev) => prev.filter((a) => !a.resolved));
  };

  // CSV Exporter for Packets
  const handleExportCsv = useCallback(() => {
    if (packets.length === 0) return;
    const headers = [
      'ID',
      'Timestamp',
      'SourceIP',
      'SourcePort',
      'DestinationIP',
      'DestinationPort',
      'Protocol',
      'Length',
      'Direction',
      'IsSuspicious',
      'Severity',
      'ThreatInfo',
      'SummaryInfo',
    ];

    const rows = packets.map((p) => [
      p.id,
      `"${p.timestamp}"`,
      `"${p.sourceIp}"`,
      p.sourcePort || '',
      `"${p.destinationIp}"`,
      p.destinationPort || '',
      `"${p.protocol}"`,
      p.length,
      `"${p.direction}"`,
      p.isSuspicious ? 'YES' : 'NO',
      `"${p.severity || ''}"`,
      `"${(p.threatInfo || '').replace(/"/g, '""')}"`,
      `"${(p.info || '').replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `network_capture_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, [packets]);

  // CSV Exporter for Alerts
  const handleExportAlertsCsv = useCallback(() => {
    if (alerts.length === 0) return;
    const headers = [
      'AlertID',
      'Timestamp',
      'Severity',
      'Category',
      'Title',
      'Description',
      'SourceIP',
      'DestinationIP',
      'DestinationPort',
      'Protocol',
      'PacketID',
      'MITRE_ID',
      'Status',
    ];

    const rows = alerts.map((a) => [
      `"${a.id}"`,
      `"${a.timestamp}"`,
      `"${a.severity}"`,
      `"${a.category}"`,
      `"${a.title.replace(/"/g, '""')}"`,
      `"${a.description.replace(/"/g, '""')}"`,
      `"${a.sourceIp}"`,
      `"${a.destinationIp}"`,
      a.destinationPort || '',
      `"${a.protocol}"`,
      a.packetId,
      `"${a.mitreId}"`,
      a.resolved ? 'RESOLVED' : a.acknowledged ? 'ACKNOWLEDGED' : 'NEW',
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `soc_security_alerts_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, [alerts]);

  const topTalkers = useMemo(() => {
    const srcMap: Record<string, { packets: number; bytes: number }> = {};
    packets.forEach((p) => {
      if (!srcMap[p.sourceIp]) srcMap[p.sourceIp] = { packets: 0, bytes: 0 };
      srcMap[p.sourceIp].packets++;
      srcMap[p.sourceIp].bytes += p.length;
    });

    return Object.entries(srcMap)
      .map(([ip, data]) => ({ ip, ...data, role: 'source' as const }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5);
  }, [packets]);

  const unreadAlertCount = useMemo(() => {
    return alerts.filter((a) => !a.acknowledged && !a.resolved).length;
  }, [alerts]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-900 selection:text-white">
      {/* Header */}
      <Header
        isCapturing={isCapturing}
        onToggleCapture={handleToggleCapture}
        onClearCapture={handleClearCapture}
        captureSpeed={captureSpeed}
        onChangeSpeed={setCaptureSpeed}
        interfaces={interfaces}
        selectedInterface={selectedInterface}
        onSelectInterface={setSelectedInterface}
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenAlerts={() => setIsAlertsOpen(true)}
        onOpenReport={() => setIsReportOpen(true)}
        onExportCsv={handleExportCsv}
        onInjectThreat={handleInjectThreat}
        unreadAlertCount={unreadAlertCount}
        totalPackets={packets.length}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-3 sm:p-4 space-y-3.5">
        {/* Real-time KPI Stats Overview */}
        <StatsOverview
          stats={stats}
          selectedProtocol={filters.protocol}
          onSelectProtocol={(proto) => setFilters((f) => ({ ...f, protocol: proto }))}
          onFilterSuspiciousOnly={() =>
            setFilters((f) => ({ ...f, suspiciousOnly: !f.suspiciousOnly }))
          }
          suspiciousOnly={filters.suspiciousOnly}
        />

        {/* Telemetry View Switcher */}
        <div className="flex flex-wrap items-center justify-between bg-slate-900/60 p-1.5 rounded-lg border border-slate-800/80 text-xs gap-2">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-semibold px-2 flex items-center gap-1.5">
              <span>Telemetry View:</span>
            </span>
            <button
              onClick={() => setVisualTab('BOTH')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                visualTab === 'BOTH'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <LayoutGrid className="w-3 h-3" />
              <span>Combined SOC</span>
            </button>
            <button
              onClick={() => setVisualTab('MAP')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                visualTab === 'MAP'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Globe className="w-3 h-3" />
              <span>Global Threat Map</span>
            </button>
            <button
              onClick={() => setVisualTab('CHARTS')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                visualTab === 'CHARTS'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Activity className="w-3 h-3" />
              <span>Bandwidth Charts</span>
            </button>
          </div>

          {filters.search && (
            <div className="flex items-center gap-2 pr-2 text-xs font-mono">
              <span className="text-slate-400">Map Filter:</span>
              <span className="text-cyan-400 font-bold bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                {filters.search}
              </span>
              <button
                onClick={() => setFilters((f) => ({ ...f, search: '' }))}
                className="text-slate-400 hover:text-rose-300 underline text-[11px]"
              >
                Clear
              </button>
            </div>
          )}
        </div>

        {/* Geographic Threat & Traffic Origin Map */}
        {(visualTab === 'MAP' || visualTab === 'BOTH') && (
          <GeographicMap
            packets={packets}
            onSelectIpFilter={(ip) => setFilters((f) => ({ ...f, search: ip }))}
            selectedFilterIp={filters.search}
          />
        )}

        {/* Real-time Throughput Waveform & Protocol Charts */}
        {(visualTab === 'CHARTS' || visualTab === 'BOTH') && (
          <TrafficCharts
            history={throughputHistory}
            packets={packets}
            protocolCounts={stats.protocolCounts}
          />
        )}

        {/* Live Packet Inspection Stream Table */}
        <PacketTable
          packets={packets}
          filteredPackets={filteredPackets}
          selectedPacket={selectedPacket}
          onSelectPacket={setSelectedPacket}
          filters={filters}
          onUpdateFilters={(newFilters) => setFilters((f) => ({ ...f, ...newFilters }))}
          onResetFilters={() =>
            setFilters({
              search: '',
              protocol: 'ALL',
              sourceIp: '',
              destinationIp: '',
              port: '',
              suspiciousOnly: false,
              severity: 'ALL',
              direction: 'ALL',
              timeRange: 'ALL',
            })
          }
          autoScroll={autoScroll}
          onToggleAutoScroll={() => setAutoScroll((v) => !v)}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 px-4 text-xs text-slate-500 flex flex-col sm:flex-row justify-between items-center gap-2 max-w-7xl mx-auto w-full">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
          <span>Passive Network Traffic Analyzer • Zero intrusive modifications</span>
        </div>
        <div className="font-mono text-[11px] text-slate-600">
          Engine: Libpcap 2.4 Decoder • RFC 793/791 Parser • Gemini AI Forensic Intelligence
        </div>
      </footer>

      {/* Modals & Slide-Overs */}
      {selectedPacket && (
        <PacketInspectorModal
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}

      <AlertsDrawer
        isOpen={isAlertsOpen}
        onClose={() => setIsAlertsOpen(false)}
        alerts={alerts}
        onAcknowledgeAlert={handleAcknowledgeAlert}
        onResolveAlert={handleResolveAlert}
        onClearResolved={handleClearResolved}
        onInspectPacketById={handleInspectPacketById}
        onExportAlertsCsv={handleExportAlertsCsv}
      />

      <PcapUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onLoadPackets={handleLoadPackets}
      />

      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        stats={stats}
        alerts={alerts}
        topTalkers={topTalkers}
        onExportCsv={handleExportCsv}
      />
    </div>
  );
}
