import React, { useMemo } from 'react';
import { NetworkPacket } from '../types/network';

interface TrafficChartsProps {
  history: Array<{ time: string; inboundBytes: number; outboundBytes: number; pps: number }>;
  packets: NetworkPacket[];
  protocolCounts: Record<string, number>;
}

export const TrafficCharts: React.FC<TrafficChartsProps> = ({
  history,
  packets,
  protocolCounts,
}) => {
  // Top talkers calculation from current packet sample
  const { topSources, topDestinations } = useMemo(() => {
    const srcMap: Record<string, { packets: number; bytes: number }> = {};
    const dstMap: Record<string, { packets: number; bytes: number }> = {};

    packets.forEach((pkt) => {
      if (!srcMap[pkt.sourceIp]) srcMap[pkt.sourceIp] = { packets: 0, bytes: 0 };
      srcMap[pkt.sourceIp].packets++;
      srcMap[pkt.sourceIp].bytes += pkt.length;

      if (!dstMap[pkt.destinationIp]) dstMap[pkt.destinationIp] = { packets: 0, bytes: 0 };
      dstMap[pkt.destinationIp].packets++;
      dstMap[pkt.destinationIp].bytes += pkt.length;
    });

    const topSrc = Object.entries(srcMap)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5);

    const topDst = Object.entries(dstMap)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5);

    return { topSources: topSrc, topDestinations: topDst };
  }, [packets]);

  // Compute SVG coordinates for real-time throughput chart
  const { inboundPoints, outboundPoints, ppsPoints, maxByteRate } = useMemo(() => {
    if (history.length === 0) {
      return { inboundPoints: '', outboundPoints: '', ppsPoints: '', maxByteRate: 1000 };
    }

    const maxRate = Math.max(
      1000,
      ...history.map((h) => Math.max(h.inboundBytes, h.outboundBytes))
    );

    const maxPps = Math.max(5, ...history.map((h) => h.pps));

    const width = 500;
    const height = 120;
    const step = width / Math.max(history.length - 1, 1);

    const inCoords: string[] = [];
    const outCoords: string[] = [];
    const ppsCoords: string[] = [];

    history.forEach((h, i) => {
      const x = Math.round(i * step);
      const inY = Math.round(height - (h.inboundBytes / maxRate) * (height - 15) - 5);
      const outY = Math.round(height - (h.outboundBytes / maxRate) * (height - 15) - 5);
      const ppsY = Math.round(height - (h.pps / maxPps) * (height - 15) - 5);

      inCoords.push(`${x},${inY}`);
      outCoords.push(`${x},${outY}`);
      ppsCoords.push(`${x},${ppsY}`);
    });

    return {
      inboundPoints: inCoords.join(' '),
      outboundPoints: outCoords.join(' '),
      ppsPoints: ppsCoords.join(' '),
      maxByteRate: maxRate,
    };
  }, [history]);

  // Protocol distribution percentages
  const protocolBreakdown = useMemo(() => {
    const total = Object.values(protocolCounts).reduce((acc, c) => acc + c, 0) || 1;
    const colors: Record<string, string> = {
      HTTPS: 'bg-emerald-500',
      HTTP: 'bg-cyan-500',
      DNS: 'bg-amber-500',
      TCP: 'bg-blue-500',
      UDP: 'bg-indigo-500',
      ICMP: 'bg-pink-500',
      SSH: 'bg-purple-500',
      TELNET: 'bg-rose-500',
      ARP: 'bg-slate-400',
    };

    return Object.entries(protocolCounts)
      .map(([proto, count]) => ({
        proto,
        count,
        percent: ((count / total) * 100).toFixed(1),
        color: colors[proto] || 'bg-slate-500',
      }))
      .sort((a, b) => b.count - a.count);
  }, [protocolCounts]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      {/* Chart 1: Bandwidth Throughput Waveform */}
      <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Live Bandwidth & Packet Rate Throughput
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">
              (Peak: {(maxByteRate / 1024).toFixed(1)} KB/s)
            </span>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-0.5 bg-emerald-400 inline-block rounded" /> Inbound
            </span>
            <span className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2.5 h-0.5 bg-cyan-400 inline-block rounded" /> Outbound
            </span>
            <span className="flex items-center gap-1.5 text-indigo-400">
              <span className="w-2.5 h-0.5 bg-indigo-400 inline-block border-b border-dashed border-indigo-400" /> PPS
            </span>
          </div>
        </div>

        {/* SVG Sparkline */}
        <div className="relative h-28 w-full bg-slate-950/80 rounded border border-slate-800/80 overflow-hidden px-2 pt-2">
          {history.length < 2 ? (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Gathering traffic samples...
            </div>
          ) : (
            <svg
              className="w-full h-full overflow-visible"
              viewBox="0 0 500 120"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="inboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#34d399" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#34d399" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="outboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1="30" x2="500" y2="30" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="60" x2="500" y2="60" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="90" x2="500" y2="90" stroke="#1e293b" strokeDasharray="3 3" />

              {/* Inbound Area */}
              <polygon
                points={`0,120 ${inboundPoints} 500,120`}
                fill="url(#inboundGrad)"
              />
              <polyline
                points={inboundPoints}
                fill="none"
                stroke="#34d399"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />

              {/* Outbound Area */}
              <polygon
                points={`0,120 ${outboundPoints} 500,120`}
                fill="url(#outboundGrad)"
              />
              <polyline
                points={outboundPoints}
                fill="none"
                stroke="#38bdf8"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />

              {/* PPS Line */}
              <polyline
                points={ppsPoints}
                fill="none"
                stroke="#818cf8"
                strokeWidth="1.5"
                strokeDasharray="4 3"
              />
            </svg>
          )}
        </div>

        <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono mt-1 px-1">
          <span>-30s</span>
          <span>-20s</span>
          <span>-10s</span>
          <span>LIVE NOW</span>
        </div>
      </div>

      {/* Chart 2: Protocol Share & Top Talkers */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 shadow-sm flex flex-col justify-between">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
            Protocol Breakdown
          </h3>
          <div className="space-y-1.5">
            {protocolBreakdown.slice(0, 4).map((p) => (
              <div key={p.proto} className="text-xs">
                <div className="flex justify-between items-center text-slate-400 font-mono text-[11px] mb-0.5">
                  <span className="text-slate-200">{p.proto}</span>
                  <span>{p.percent}% ({p.count})</span>
                </div>
                <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                  <div
                    className={`h-full ${p.color} transition-all duration-300`}
                    style={{ width: `${p.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Talker IP preview */}
        <div className="mt-3 pt-2.5 border-t border-slate-800/80">
          <div className="flex justify-between items-center text-[11px] text-slate-400 font-mono mb-1">
            <span className="font-semibold text-slate-300">Top Source Talker:</span>
            <span className="text-cyan-400">{topSources[0]?.ip || 'None'}</span>
          </div>
          <div className="flex justify-between items-center text-[11px] text-slate-400 font-mono">
            <span className="font-semibold text-slate-300">Top Destination:</span>
            <span className="text-emerald-400">{topDestinations[0]?.ip || 'None'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
