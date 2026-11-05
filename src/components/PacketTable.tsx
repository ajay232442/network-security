import React, { useRef, useEffect } from 'react';
import {
  Search,
  Filter,
  ArrowUpDown,
  Lock,
  Unlock,
  AlertTriangle,
  Eye,
  SlidersHorizontal,
} from 'lucide-react';
import { FilterCriteria, NetworkPacket, Protocol } from '../types/network';

interface PacketTableProps {
  packets: NetworkPacket[];
  filteredPackets: NetworkPacket[];
  selectedPacket: NetworkPacket | null;
  onSelectPacket: (packet: NetworkPacket) => void;
  filters: FilterCriteria;
  onUpdateFilters: (newFilters: Partial<FilterCriteria>) => void;
  onResetFilters: () => void;
  autoScroll: boolean;
  onToggleAutoScroll: () => void;
}

export const PacketTable: React.FC<PacketTableProps> = ({
  packets,
  filteredPackets,
  selectedPacket,
  onSelectPacket,
  filters,
  onUpdateFilters,
  onResetFilters,
  autoScroll,
  onToggleAutoScroll,
}) => {
  const tableEndRef = useRef<HTMLTableRowElement>(null);

  // Auto-scroll effect
  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [filteredPackets.length, autoScroll]);

  // Protocol badge color mapper
  const getProtocolStyle = (proto: Protocol) => {
    switch (proto) {
      case 'HTTPS':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
      case 'HTTP':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800';
      case 'DNS':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'TCP':
        return 'bg-blue-950/80 text-blue-300 border-blue-800';
      case 'UDP':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-800';
      case 'ICMP':
        return 'bg-pink-950/80 text-pink-300 border-pink-800';
      case 'SSH':
        return 'bg-purple-950/80 text-purple-300 border-purple-800';
      case 'TELNET':
        return 'bg-rose-950/80 text-rose-300 border-rose-800 font-bold';
      case 'FTP':
        return 'bg-orange-950/80 text-orange-300 border-orange-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const hasActiveFilters =
    filters.search !== '' ||
    filters.protocol !== 'ALL' ||
    filters.direction !== 'ALL' ||
    filters.severity !== 'ALL' ||
    filters.suspiciousOnly;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg shadow-md overflow-hidden flex flex-col h-[520px]">
      {/* Table Toolbar & Filters */}
      <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
        {/* Search bar */}
        <div className="flex items-center gap-2 flex-1 min-w-[220px] max-w-md">
          <div className="relative w-full">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, port, DNS query, flag, info..."
              value={filters.search}
              onChange={(e) => onUpdateFilters({ search: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 placeholder-slate-500 font-mono"
            />
          </div>
        </div>

        {/* Filters and Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Protocol filter */}
          <select
            value={filters.protocol}
            onChange={(e) => onUpdateFilters({ protocol: e.target.value })}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">Protocol: All</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="DNS">DNS</option>
            <option value="HTTPS">HTTPS</option>
            <option value="HTTP">HTTP</option>
            <option value="ICMP">ICMP</option>
            <option value="SSH">SSH</option>
            <option value="TELNET">TELNET</option>
            <option value="FTP">FTP</option>
            <option value="ARP">ARP</option>
          </select>

          {/* Direction filter */}
          <select
            value={filters.direction}
            onChange={(e) => onUpdateFilters({ direction: e.target.value })}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">Direction: All</option>
            <option value="INBOUND">Inbound</option>
            <option value="OUTBOUND">Outbound</option>
            <option value="INTERNAL">Internal</option>
          </select>

          {/* Severity filter */}
          <select
            value={filters.severity}
            onChange={(e) => onUpdateFilters({ severity: e.target.value })}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">Threat: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Suspicious only checkbox button */}
          <button
            onClick={() => onUpdateFilters({ suspiciousOnly: !filters.suspiciousOnly })}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium border transition-colors ${
              filters.suspiciousOnly
                ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Threats Only</span>
          </button>

          {hasActiveFilters && (
            <button
              onClick={onResetFilters}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono px-1"
            >
              Reset
            </button>
          )}

          <div className="h-4 w-px bg-slate-800 hidden sm:block" />

          {/* Auto-scroll toggle */}
          <button
            onClick={onToggleAutoScroll}
            className={`flex items-center gap-1 px-2 py-1.5 rounded text-xs border transition-colors ${
              autoScroll
                ? 'bg-cyan-950/60 border-cyan-800 text-cyan-300'
                : 'bg-slate-950 border-slate-800 text-slate-500'
            }`}
            title={autoScroll ? 'Auto-scroll enabled (click to lock position)' : 'Auto-scroll disabled'}
          >
            {autoScroll ? <Lock className="w-3 h-3 text-cyan-400" /> : <Unlock className="w-3 h-3 text-slate-500" />}
            <span className="font-mono text-[11px] hidden md:inline">Auto-scroll</span>
          </button>
        </div>
      </div>

      {/* Packet Table Count Indicator */}
      <div className="bg-slate-950/90 px-4 py-1.5 border-b border-slate-800 text-[11px] text-slate-400 font-mono flex items-center justify-between">
        <div>
          Showing <span className="text-white font-semibold">{filteredPackets.length}</span> of{' '}
          <span className="text-slate-300">{packets.length}</span> captured packets
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-slate-500">
            <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" /> Flagged Threat
          </span>
          <span className="text-slate-600">•</span>
          <span className="text-slate-500">Click any row to inspect metadata</span>
        </div>
      </div>

      {/* Main Table Scroll Container */}
      <div className="flex-1 overflow-auto bg-slate-950/50 scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-slate-950">
        <table className="w-full text-left text-xs font-mono border-collapse">
          <thead className="bg-slate-900/90 text-slate-400 sticky top-0 z-10 text-[11px] uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-2 px-3 w-12 text-center">#</th>
              <th className="py-2 px-3 w-28">Time</th>
              <th className="py-2 px-3 w-40">Source</th>
              <th className="py-2 px-3 w-40">Destination</th>
              <th className="py-2 px-3 w-20">Proto</th>
              <th className="py-2 px-3 w-16 text-right">Length</th>
              <th className="py-2 px-3 w-24">Flags</th>
              <th className="py-2 px-3 min-w-[200px]">Info</th>
              <th className="py-2 px-3 w-28 text-center">Threat Status</th>
              <th className="py-2 px-2 w-10 text-center"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredPackets.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-16 text-center text-slate-500 font-mono">
                  {packets.length === 0
                    ? 'No packets captured yet. Start live capture or load a PCAP dataset.'
                    : 'No packets match the current filter criteria.'}
                </td>
              </tr>
            ) : (
              filteredPackets.map((pkt) => {
                const isSelected = selectedPacket?.id === pkt.id;
                return (
                  <tr
                    key={pkt.id}
                    onClick={() => onSelectPacket(pkt)}
                    className={`cursor-pointer transition-colors group ${
                      isSelected
                        ? 'bg-cyan-950/50 text-cyan-100 ring-1 ring-cyan-500/40'
                        : pkt.isSuspicious
                        ? 'bg-rose-950/20 hover:bg-rose-950/35 text-rose-200'
                        : 'hover:bg-slate-850 text-slate-300'
                    }`}
                  >
                    {/* ID */}
                    <td className="py-1.5 px-3 text-center text-slate-500 font-mono text-[11px]">
                      {pkt.id}
                    </td>

                    {/* Timestamp */}
                    <td className="py-1.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                      {pkt.timestamp}
                    </td>

                    {/* Source */}
                    <td className="py-1.5 px-3 whitespace-nowrap">
                      <span className="text-slate-200">{pkt.sourceIp}</span>
                      {pkt.sourcePort !== null && (
                        <span className="text-slate-500">:{pkt.sourcePort}</span>
                      )}
                    </td>

                    {/* Destination */}
                    <td className="py-1.5 px-3 whitespace-nowrap">
                      <span className="text-slate-200">{pkt.destinationIp}</span>
                      {pkt.destinationPort !== null && (
                        <span className="text-slate-500">:{pkt.destinationPort}</span>
                      )}
                    </td>

                    {/* Protocol */}
                    <td className="py-1.5 px-3 whitespace-nowrap">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getProtocolStyle(
                          pkt.protocol
                        )}`}
                      >
                        {pkt.protocol}
                      </span>
                    </td>

                    {/* Length */}
                    <td className="py-1.5 px-3 text-right text-slate-400 whitespace-nowrap text-[11px]">
                      {pkt.length}
                    </td>

                    {/* TCP Flags */}
                    <td className="py-1.5 px-3 whitespace-nowrap text-[10px]">
                      {pkt.flags ? (
                        <div className="flex items-center gap-1">
                          {pkt.flags.syn && (
                            <span className="px-1 bg-amber-950 text-amber-300 rounded border border-amber-800">
                              SYN
                            </span>
                          )}
                          {pkt.flags.ack && (
                            <span className="px-1 bg-slate-800 text-slate-300 rounded border border-slate-700">
                              ACK
                            </span>
                          )}
                          {pkt.flags.rst && (
                            <span className="px-1 bg-rose-950 text-rose-300 rounded border border-rose-800 font-bold">
                              RST
                            </span>
                          )}
                          {pkt.flags.fin && (
                            <span className="px-1 bg-blue-950 text-blue-300 rounded border border-blue-800">
                              FIN
                            </span>
                          )}
                          {pkt.flags.psh && (
                            <span className="px-1 bg-purple-950 text-purple-300 rounded border border-purple-800">
                              PSH
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>

                    {/* Info */}
                    <td className="py-1.5 px-3 truncate max-w-xs text-slate-300 text-[11px]" title={pkt.info}>
                      {pkt.info}
                    </td>

                    {/* Threat Status */}
                    <td className="py-1.5 px-3 text-center whitespace-nowrap">
                      {pkt.isSuspicious ? (
                        <span
                          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                            pkt.severity === 'CRITICAL'
                              ? 'bg-rose-900/60 text-rose-300 border-rose-700'
                              : pkt.severity === 'HIGH'
                              ? 'bg-amber-900/60 text-amber-300 border-amber-700'
                              : 'bg-blue-900/60 text-blue-300 border-blue-700'
                          }`}
                        >
                          <AlertTriangle className="w-2.5 h-2.5" />
                          {pkt.severity || 'ALERT'}
                        </span>
                      ) : (
                        <span className="text-slate-600 text-[10px]">-</span>
                      )}
                    </td>

                    {/* Action Icon */}
                    <td className="py-1.5 px-2 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectPacket(pkt);
                        }}
                        className="p-1 rounded text-slate-500 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                        title="Inspect Packet Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
            <tr ref={tableEndRef} />
          </tbody>
        </table>
      </div>
    </div>
  );
};
