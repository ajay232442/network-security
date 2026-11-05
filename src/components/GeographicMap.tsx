import React, { useMemo, useState } from 'react';
import {
  Globe,
  Radio,
  ShieldAlert,
  ShieldCheck,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Filter,
  Layers,
  ArrowDownLeft,
  ArrowUpRight,
  ExternalLink,
  MapPin,
  Sparkles,
} from 'lucide-react';
import { GeoConnection, GeoLocation, NetworkPacket } from '../types/network';
import { projectGeoToSvg, resolveGeoIp, SENSOR_LOCATION } from '../utils/geoIp';

interface GeographicMapProps {
  packets: NetworkPacket[];
  onSelectIpFilter: (ip: string) => void;
  selectedFilterIp?: string;
}

// Stylized high-contrast SVG vector landmass paths for equirectangular projection (viewBox 0 0 1000 500)
const WORLD_LANDMASS_PATHS = [
  // North America
  'M 120 70 L 170 60 L 220 50 L 290 65 L 305 95 L 290 120 L 250 115 L 235 150 L 220 180 L 195 240 L 165 245 L 140 215 L 115 170 L 95 130 L 105 90 Z',
  // Central & South America
  'M 200 250 L 240 255 L 275 270 L 330 290 L 350 340 L 330 400 L 290 470 L 270 475 L 260 410 L 240 340 L 210 290 Z',
  // Europe
  'M 470 70 L 530 65 L 560 85 L 550 120 L 580 145 L 540 180 L 490 185 L 460 160 L 470 115 L 450 90 Z',
  // United Kingdom & Ireland
  'M 455 100 L 470 95 L 465 115 L 450 115 Z',
  // Africa
  'M 470 190 L 530 185 L 580 230 L 590 280 L 560 340 L 530 410 L 485 410 L 460 330 L 430 260 L 450 205 Z',
  // Eurasia (Russia / Central Asia / China)
  'M 560 70 L 680 50 L 800 60 L 890 85 L 870 140 L 830 150 L 780 200 L 740 260 L 680 250 L 630 210 L 580 170 L 570 100 Z',
  // South Asia & Southeast Asia (India / Indochina)
  'M 680 220 L 720 230 L 730 290 L 690 320 L 660 270 Z',
  'M 740 250 L 790 260 L 780 330 L 750 320 Z',
  // Japan
  'M 870 150 L 885 160 L 875 185 L 860 175 Z',
  // Australia & New Zealand
  'M 790 350 L 860 340 L 890 390 L 850 440 L 780 410 L 775 365 Z',
  'M 910 430 L 925 440 L 915 460 L 905 450 Z',
  // Greenland
  'M 320 30 L 370 25 L 390 60 L 340 75 Z',
];

export const GeographicMap: React.FC<GeographicMapProps> = ({
  packets,
  onSelectIpFilter,
  selectedFilterIp,
}) => {
  const [threatsOnly, setThreatsOnly] = useState<boolean>(false);
  const [animateParticles, setAnimateParticles] = useState<boolean>(true);
  const [hoveredNode, setHoveredNode] = useState<{
    geo: GeoLocation;
    x: number;
    y: number;
    packetCount: number;
    byteCount: number;
    isThreat: boolean;
    threatInfo?: string;
    protocol: string;
  } | null>(null);

  const [hoveredConnection, setHoveredConnection] = useState<GeoConnection | null>(null);

  const MAP_WIDTH = 1000;
  const MAP_HEIGHT = 500;

  // Sensor SVG Coordinates
  const sensorCoord = useMemo(() => {
    return projectGeoToSvg(
      SENSOR_LOCATION.latitude,
      SENSOR_LOCATION.longitude,
      MAP_WIDTH,
      MAP_HEIGHT
    );
  }, []);

  // Aggregate active international connections from captured packets
  const { connections, nodesByIp, topOriginCountries, totalInternationalPackets } = useMemo(() => {
    const connMap: Record<string, GeoConnection> = {};
    const nodeMap: Record<
      string,
      {
        geo: GeoLocation;
        packetCount: number;
        byteCount: number;
        isThreat: boolean;
        threatInfo?: string;
        protocol: string;
        lastSeen: number;
      }
    > = {};

    const countryMap: Record<
      string,
      { country: string; flag: string; count: number; bytes: number; threats: number }
    > = {};

    let intlPackets = 0;

    packets.forEach((p) => {
      // Determine external IP
      const srcGeo = resolveGeoIp(p.sourceIp);
      const dstGeo = resolveGeoIp(p.destinationIp);

      const hasExternalSrc = !srcGeo.isPrivate;
      const hasExternalDst = !dstGeo.isPrivate;

      if (!hasExternalSrc && !hasExternalDst) return;

      intlPackets++;

      const remoteGeo = hasExternalSrc ? srcGeo : dstGeo;
      const remoteIp = remoteGeo.ip;

      // Update Node map
      if (!nodeMap[remoteIp]) {
        nodeMap[remoteIp] = {
          geo: remoteGeo,
          packetCount: 0,
          byteCount: 0,
          isThreat: false,
          threatInfo: undefined,
          protocol: p.protocol,
          lastSeen: p.timeEpoch,
        };
      }
      nodeMap[remoteIp].packetCount++;
      nodeMap[remoteIp].byteCount += p.length;
      nodeMap[remoteIp].lastSeen = Math.max(nodeMap[remoteIp].lastSeen, p.timeEpoch);
      if (p.isSuspicious) {
        nodeMap[remoteIp].isThreat = true;
        nodeMap[remoteIp].threatInfo = p.threatInfo || 'Flagged Threat';
      }

      // Update Connection arc map
      const connKey = `${p.sourceIp}->${p.destinationIp}:${p.protocol}`;
      if (!connMap[connKey]) {
        connMap[connKey] = {
          id: connKey,
          sourceIp: p.sourceIp,
          destinationIp: p.destinationIp,
          sourceGeo: srcGeo,
          destinationGeo: dstGeo,
          protocol: p.protocol,
          packetCount: 0,
          byteCount: 0,
          lastSeen: p.timeEpoch,
          isThreat: false,
          severity: p.severity,
          category: p.category,
        };
      }
      connMap[connKey].packetCount++;
      connMap[connKey].byteCount += p.length;
      if (p.isSuspicious) {
        connMap[connKey].isThreat = true;
      }

      // Update Country leaderboard
      const cName = remoteGeo.country;
      if (!countryMap[cName]) {
        countryMap[cName] = {
          country: cName,
          flag: remoteGeo.flag,
          count: 0,
          bytes: 0,
          threats: 0,
        };
      }
      countryMap[cName].count++;
      countryMap[cName].bytes += p.length;
      if (p.isSuspicious) countryMap[cName].threats++;
    });

    const sortedCountries = Object.values(countryMap).sort((a, b) => b.count - a.count);

    return {
      connections: Object.values(connMap),
      nodesByIp: Object.values(nodeMap),
      topOriginCountries: sortedCountries,
      totalInternationalPackets: intlPackets,
    };
  }, [packets]);

  // Filter connections if threatsOnly is toggled
  const visibleConnections = useMemo(() => {
    return connections.filter((c) => {
      if (threatsOnly) return c.isThreat;
      return true;
    });
  }, [connections, threatsOnly]);

  // Format bytes for HUD
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg shadow-md overflow-hidden flex flex-col">
      {/* Map Control Bar */}
      <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400">
            <Globe className="w-4 h-4 animate-spin-slow" />
          </div>
          <div>
            <div className="font-bold text-white flex items-center gap-2">
              Global Threat & Traffic Origin Map
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                {nodesByIp.length} Foreign IPs Active
              </span>
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              Live geographic packet arcs connecting international origins to local sensor
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Threats only toggle */}
          <button
            onClick={() => setThreatsOnly((prev) => !prev)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
              threatsOnly
                ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Threat Arcs Only</span>
          </button>

          {/* Particle flow toggle */}
          <button
            onClick={() => setAnimateParticles((prev) => !prev)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
              animateParticles
                ? 'bg-cyan-950/60 border-cyan-800 text-cyan-300'
                : 'bg-slate-950 border-slate-800 text-slate-500'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Packet Flows</span>
          </button>

          {selectedFilterIp && (
            <button
              onClick={() => onSelectIpFilter('')}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono px-1"
            >
              Clear IP Filter ({selectedFilterIp})
            </button>
          )}
        </div>
      </div>

      {/* Main Map Canvas Area */}
      <div className="relative w-full bg-slate-950 overflow-hidden border-b border-slate-800/80">
        <svg
          viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
          className="w-full h-[360px] sm:h-[420px] select-none block"
          style={{ background: 'radial-gradient(ellipse at center, #090e17 0%, #020617 100%)' }}
        >
          <defs>
            {/* Glow Filters */}
            <filter id="threat-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="sensor-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="traffic-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Linear Gradients for Arc Lines */}
            <linearGradient id="arc-threat" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.85" />
              <stop offset="50%" stopColor="#fb7185" stopOpacity="0.95" />
              <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.75" />
            </linearGradient>

            <linearGradient id="arc-normal" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.7" />
              <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.7" />
            </linearGradient>

            <linearGradient id="arc-warning" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.75" />
              <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.85" />
            </linearGradient>

            {/* Pattern for Map Grid Matrix */}
            <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.6" strokeDasharray="2 3" />
            </pattern>
          </defs>

          {/* Subtle Grid Matrix Background */}
          <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#grid-pattern)" opacity="0.45" />

          {/* Latitude Equator & Prime Meridian Lines */}
          <line x1="0" y1="250" x2={MAP_WIDTH} y2="250" stroke="#334155" strokeWidth="1" strokeDasharray="4 6" opacity="0.5" />
          <line x1="500" y1="0" x2="500" y2={MAP_HEIGHT} stroke="#334155" strokeWidth="1" strokeDasharray="4 6" opacity="0.5" />

          {/* World Landmass Silhouettes */}
          <g className="world-continents">
            {WORLD_LANDMASS_PATHS.map((pathStr, idx) => (
              <path
                key={idx}
                d={pathStr}
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.2"
                strokeLinejoin="round"
                className="transition-colors hover:fill-slate-800/40"
              />
            ))}
          </g>

          {/* Connection Arc Lines */}
          <g className="connection-arcs">
            {visibleConnections.map((conn) => {
              const foreignGeo = !conn.sourceGeo.isPrivate ? conn.sourceGeo : conn.destinationGeo;
              const remotePt = projectGeoToSvg(
                foreignGeo.latitude,
                foreignGeo.longitude,
                MAP_WIDTH,
                MAP_HEIGHT
              );

              // Control point for smooth parabolic curve
              const dx = remotePt.x - sensorCoord.x;
              const dy = remotePt.y - sensorCoord.y;
              const dist = Math.sqrt(dx * dx + dy * dy);

              // Lift arc upwards or downwards based on geometry
              const midX = (sensorCoord.x + remotePt.x) / 2;
              const midY = (sensorCoord.y + remotePt.y) / 2 - Math.min(120, dist * 0.35);

              const pathD = `M ${sensorCoord.x} ${sensorCoord.y} Q ${midX} ${midY} ${remotePt.x} ${remotePt.y}`;

              const isThreat = conn.isThreat;
              const strokeColor = isThreat
                ? 'url(#arc-threat)'
                : conn.protocol === 'DNS'
                ? 'url(#arc-warning)'
                : 'url(#arc-normal)';

              const strokeWidth = Math.min(3.5, 1.2 + Math.log10(conn.packetCount + 1));

              return (
                <g
                  key={conn.id}
                  className="cursor-pointer group"
                  onMouseEnter={() => setHoveredConnection(conn)}
                  onMouseLeave={() => setHoveredConnection(null)}
                  onClick={() => onSelectIpFilter(foreignGeo.ip)}
                >
                  {/* Background wider hit target */}
                  <path d={pathD} fill="none" stroke="transparent" strokeWidth="14" />

                  {/* Base Glow Line */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeOpacity={isThreat ? 0.85 : 0.6}
                    filter={isThreat ? 'url(#threat-glow)' : 'url(#traffic-glow)'}
                  />

                  {/* Animated Dash Particle Flow */}
                  {animateParticles && (
                    <path
                      d={pathD}
                      fill="none"
                      stroke={isThreat ? '#fecdd3' : '#a7f3d0'}
                      strokeWidth={strokeWidth + 0.5}
                      strokeDasharray="6 24"
                      className="animate-dash"
                      opacity={isThreat ? 0.95 : 0.8}
                    />
                  )}
                </g>
              );
            })}
          </g>

          {/* International Origin IP Nodes */}
          <g className="foreign-nodes">
            {nodesByIp.map((item) => {
              const pt = projectGeoToSvg(
                item.geo.latitude,
                item.geo.longitude,
                MAP_WIDTH,
                MAP_HEIGHT
              );

              const radius = Math.min(11, 4 + Math.log2(item.packetCount + 1));
              const isSelected = selectedFilterIp === item.geo.ip;

              return (
                <g
                  key={item.geo.ip}
                  className="cursor-pointer group"
                  transform={`translate(${pt.x}, ${pt.y})`}
                  onMouseEnter={(e) => {
                    const rect = e.currentTarget.getBoundingClientRect();
                    setHoveredNode({
                      geo: item.geo,
                      x: rect.x + rect.width / 2,
                      y: rect.y,
                      packetCount: item.packetCount,
                      byteCount: item.byteCount,
                      isThreat: item.isThreat,
                      threatInfo: item.threatInfo,
                      protocol: item.protocol,
                    });
                  }}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => onSelectIpFilter(item.geo.ip)}
                >
                  {/* Concentric pulsing radar ring for active threats or high volume */}
                  {item.isThreat ? (
                    <circle
                      r={radius * 2.2}
                      fill="none"
                      stroke="#f43f5e"
                      strokeWidth="1.5"
                      opacity="0.5"
                      className="animate-ping"
                    />
                  ) : (
                    <circle
                      r={radius * 1.8}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth="1"
                      opacity="0.3"
                      className="animate-pulse"
                    />
                  )}

                  {/* Selected ring */}
                  {isSelected && (
                    <circle
                      r={radius + 5}
                      fill="none"
                      stroke="#22d3ee"
                      strokeWidth="2.5"
                      strokeDasharray="3 3"
                    />
                  )}

                  {/* Core Node Circle */}
                  <circle
                    r={radius}
                    fill={item.isThreat ? '#e11d48' : '#0284c7'}
                    stroke={item.isThreat ? '#ffe4e6' : '#bae6fd'}
                    strokeWidth="1.5"
                    filter={item.isThreat ? 'url(#threat-glow)' : 'url(#traffic-glow)'}
                    className="transition-transform group-hover:scale-125"
                  />

                  {/* City Label for Top Nodes */}
                  <text
                    x={radius + 4}
                    y="3"
                    fill={item.isThreat ? '#fca5a5' : '#94a3b8'}
                    fontSize="9"
                    fontFamily="monospace"
                    className="pointer-events-none select-none font-bold"
                  >
                    {item.geo.city.split(',')[0]} ({item.geo.flag})
                  </text>
                </g>
              );
            })}
          </g>

          {/* Central Local Sensor Gateway (Silicon Valley Edge Tap) */}
          <g
            className="sensor-node"
            transform={`translate(${sensorCoord.x}, ${sensorCoord.y})`}
          >
            {/* Outer radar wave */}
            <circle
              r="22"
              fill="none"
              stroke="#10b981"
              strokeWidth="1.5"
              opacity="0.4"
              className="animate-ping"
            />
            <circle
              r="14"
              fill="rgba(16, 185, 129, 0.2)"
              stroke="#34d399"
              strokeWidth="2"
              filter="url(#sensor-glow)"
            />
            <circle r="6" fill="#10b981" stroke="#ffffff" strokeWidth="2" />

            {/* Sensor Tag */}
            <rect
              x="-60"
              y="-28"
              width="120"
              height="18"
              rx="4"
              fill="#064e3b"
              stroke="#059669"
              strokeWidth="1"
              opacity="0.9"
            />
            <text
              x="0"
              y="-16"
              fill="#ecfdf5"
              fontSize="9"
              fontFamily="monospace"
              fontWeight="bold"
              textAnchor="middle"
              className="pointer-events-none"
            >
              SOC SENSOR (eth0)
            </text>
          </g>
        </svg>

        {/* Floating Tooltip HUD Card */}
        {hoveredNode && (
          <div
            className="absolute z-20 pointer-events-none bg-slate-900/95 border border-slate-700 rounded-lg p-3 shadow-2xl backdrop-blur-md text-xs font-mono w-64 animate-in fade-in zoom-in-95 duration-150"
            style={{
              top: '12px',
              right: '12px',
            }}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 mb-2">
              <span className="font-bold text-white flex items-center gap-1.5 text-xs">
                <span>{hoveredNode.geo.flag}</span>
                <span>{hoveredNode.geo.city}</span>
              </span>
              {hoveredNode.isThreat ? (
                <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold">
                  THREAT
                </span>
              ) : (
                <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                  BENIGN
                </span>
              )}
            </div>

            <div className="space-y-1 text-[11px] text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-500">IP:</span>
                <span className="text-cyan-400 font-bold">{hoveredNode.geo.ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Country:</span>
                <span>{hoveredNode.geo.country}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">ASN / ISP:</span>
                <span className="truncate max-w-[140px]" title={hoveredNode.geo.org}>
                  {hoveredNode.geo.asn || hoveredNode.geo.org}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Packets:</span>
                <span>{hoveredNode.packetCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Volume:</span>
                <span>{formatBytes(hoveredNode.byteCount)}</span>
              </div>
              {hoveredNode.threatInfo && (
                <div className="mt-1.5 pt-1.5 border-t border-slate-800 text-rose-400 text-[10px] leading-tight">
                  ⚠ {hoveredNode.threatInfo}
                </div>
              )}
            </div>
            <div className="mt-2 text-[10px] text-slate-500 text-center font-sans">
              Click node to filter packet stream by this IP
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-2 left-3 z-10 flex flex-wrap items-center gap-3 bg-slate-900/90 border border-slate-800/80 rounded px-2.5 py-1 text-[11px] font-mono text-slate-400 backdrop-blur-sm">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]" />
            <span>Local Sensor Gateway</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span>Legitimate Traffic</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]" />
            <span>Anomalous Threat Origin</span>
          </div>
        </div>
      </div>

      {/* Country Leaderboard Bottom Bar */}
      <div className="p-3 bg-slate-900/95 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
            Top International Traffic Origins:
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {topOriginCountries.length === 0 ? (
            <span className="text-slate-500 font-mono text-[11px]">
              Capturing international packet traffic...
            </span>
          ) : (
            topOriginCountries.slice(0, 5).map((c) => (
              <div
                key={c.country}
                className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 font-mono text-[11px]"
              >
                <span>{c.flag}</span>
                <span className="text-slate-200 font-medium">{c.country}</span>
                <span className="text-cyan-400">({c.count})</span>
                {c.threats > 0 && (
                  <span className="px-1 py-0.2 rounded bg-rose-950 text-rose-300 text-[10px] font-bold border border-rose-800">
                    {c.threats} Threat{c.threats > 1 ? 's' : ''}
                  </span>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
