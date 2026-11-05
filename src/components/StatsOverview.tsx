import React from 'react';
import {
  Layers,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ShieldCheck,
  AlertOctagon,
} from 'lucide-react';
import { TrafficStats } from '../types/network';

interface StatsOverviewProps {
  stats: TrafficStats;
  selectedProtocol: string;
  onSelectProtocol: (proto: string) => void;
  onFilterSuspiciousOnly: () => void;
  suspiciousOnly: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatBps(bps: number): string {
  if (bps < 1000) return `${Math.round(bps)} B/s`;
  if (bps < 1000000) return `${(bps / 1000).toFixed(1)} KB/s`;
  return `${(bps / 1000000).toFixed(2)} MB/s`;
}

export const StatsOverview: React.FC<StatsOverviewProps> = ({
  stats,
  selectedProtocol,
  onSelectProtocol,
  onFilterSuspiciousOnly,
  suspiciousOnly,
}) => {
  // Threat Level logic
  let threatLevel: 'NOMINAL' | 'LOW' | 'ELEVATED' | 'CRITICAL' = 'NOMINAL';
  let threatColor = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  let threatBarColor = 'bg-emerald-500';
  let threatPercent = 10;

  if (stats.severityCounts.CRITICAL > 0) {
    threatLevel = 'CRITICAL';
    threatColor = 'text-rose-400 border-rose-500/40 bg-rose-500/15';
    threatBarColor = 'bg-rose-500';
    threatPercent = 100;
  } else if (stats.severityCounts.HIGH > 0 || stats.suspiciousCount > 5) {
    threatLevel = 'ELEVATED';
    threatColor = 'text-amber-400 border-amber-500/40 bg-amber-500/15';
    threatBarColor = 'bg-amber-500';
    threatPercent = 70;
  } else if (stats.suspiciousCount > 0) {
    threatLevel = 'LOW';
    threatColor = 'text-blue-400 border-blue-500/40 bg-blue-500/15';
    threatBarColor = 'bg-blue-500';
    threatPercent = 35;
  }

  const commonProtocols = ['TCP', 'UDP', 'DNS', 'HTTPS', 'HTTP', 'ICMP', 'SSH', 'ARP'];

  return (
    <div className="space-y-3">
      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Total Packets */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span className="font-medium flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" /> Total Captured Packets
            </span>
            <span className="font-mono text-cyan-400 bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-800 text-[11px]">
              {stats.currentPps} pkts/s
            </span>
          </div>
          <div className="flex items-baseline justify-between mt-1">
            <div className="text-2xl font-bold font-mono text-white tracking-tight">
              {stats.totalPackets.toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 font-mono">
              Volume: {formatBytes(stats.totalBytes)}
            </div>
          </div>
        </div>

        {/* Card 2: Bandwidth & Throughput */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span className="font-medium flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-blue-400" /> Bandwidth Consumption
            </span>
            <span className="font-mono text-blue-400 bg-blue-950/80 px-1.5 py-0.5 rounded border border-blue-800 text-[11px]">
              {formatBps(stats.currentBps)}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-1 font-mono text-xs">
            <div className="flex items-center gap-1.5 bg-slate-950/60 p-1.5 rounded border border-slate-800/80">
              <ArrowDownLeft className="w-3.5 h-3.5 text-emerald-400" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Inbound</div>
                <div className="text-slate-200 font-semibold">{formatBytes(stats.inboundBytes)}</div>
              </div>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-950/60 p-1.5 rounded border border-slate-800/80">
              <ArrowUpRight className="w-3.5 h-3.5 text-cyan-400" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Outbound</div>
                <div className="text-slate-200 font-semibold">{formatBytes(stats.outboundBytes)}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Card 3: Suspicious Packets & IDS Alerts */}
        <div
          onClick={onFilterSuspiciousOnly}
          className={`bg-slate-900/90 border rounded-lg p-3.5 shadow-sm cursor-pointer transition-all ${
            suspiciousOnly
              ? 'border-rose-500 ring-1 ring-rose-500/50 bg-rose-950/20'
              : 'border-slate-800 hover:border-slate-700'
          }`}
          title="Click to toggle filter to suspicious packets only"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span className="font-medium flex items-center gap-1.5">
              <AlertOctagon className="w-4 h-4 text-rose-400" /> Anomalous / IDS Flags
            </span>
            <span className="text-[10px] text-slate-400 hover:text-white underline">
              {suspiciousOnly ? 'Showing flagged' : 'Filter by flag'}
            </span>
          </div>
          <div className="flex items-baseline justify-between mt-1">
            <div className="text-2xl font-bold font-mono text-rose-400 tracking-tight">
              {stats.suspiciousCount}
            </div>
            <div className="flex items-center gap-1.5 text-[11px] font-mono">
              {stats.severityCounts.CRITICAL > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-rose-900/60 text-rose-300 border border-rose-700">
                  {stats.severityCounts.CRITICAL} Crit
                </span>
              )}
              {stats.severityCounts.HIGH > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-amber-900/60 text-amber-300 border border-amber-700">
                  {stats.severityCounts.HIGH} High
                </span>
              )}
              {stats.severityCounts.MEDIUM > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700">
                  {stats.severityCounts.MEDIUM} Med
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Card 4: Threat Posture Gauge */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span className="font-medium flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Security Posture
            </span>
            <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${threatColor}`}>
              {threatLevel}
            </span>
          </div>
          <div className="mt-2.5">
            <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
              <div
                className={`h-full transition-all duration-500 ${threatBarColor}`}
                style={{ width: `${threatPercent}%` }}
              />
            </div>
            <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono mt-1.5">
              <span>NOMINAL</span>
              <span>ELEVATED</span>
              <span>CRITICAL</span>
            </div>
          </div>
        </div>
      </div>

      {/* Protocol Quick-Filter Bar */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-1 scrollbar-none text-xs">
        <span className="text-slate-500 text-xs font-mono mr-1 shrink-0">Protocol Distribution:</span>
        <button
          onClick={() => onSelectProtocol('ALL')}
          className={`px-2.5 py-1 rounded-md text-xs font-medium shrink-0 transition-colors ${
            selectedProtocol === 'ALL'
              ? 'bg-cyan-600 text-white shadow-sm'
              : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700/80 border border-slate-700/50'
          }`}
        >
          All ({stats.totalPackets})
        </button>
        {commonProtocols.map((proto) => {
          const count = stats.protocolCounts[proto] || 0;
          const isSelected = selectedProtocol === proto;
          return (
            <button
              key={proto}
              onClick={() => onSelectProtocol(proto)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono shrink-0 transition-colors flex items-center gap-1.5 ${
                isSelected
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700/80 border border-slate-700/50'
              }`}
            >
              <span>{proto}</span>
              <span className={`text-[10px] px-1 py-0.2 rounded ${isSelected ? 'bg-cyan-700' : 'bg-slate-900 text-slate-400'}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
