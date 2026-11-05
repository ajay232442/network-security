import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertOctagon,
  CheckCircle,
  Download,
  Trash2,
  ExternalLink,
  ChevronRight,
  Shield,
  Filter,
} from 'lucide-react';
import { AlertSeverity, NetworkPacket, SecurityAlert } from '../types/network';

interface AlertsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: SecurityAlert[];
  onAcknowledgeAlert: (id: string) => void;
  onResolveAlert: (id: string) => void;
  onClearResolved: () => void;
  onInspectPacketById: (packetId: number) => void;
  onExportAlertsCsv: () => void;
}

export const AlertsDrawer: React.FC<AlertsDrawerProps> = ({
  isOpen,
  onClose,
  alerts,
  onAcknowledgeAlert,
  onResolveAlert,
  onClearResolved,
  onInspectPacketById,
  onExportAlertsCsv,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  if (!isOpen) return null;

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter === 'ALL') return true;
    return a.severity === severityFilter;
  });

  const getSeverityBadge = (sev: AlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-700';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-700';
      case 'MEDIUM':
        return 'bg-blue-950/80 text-blue-300 border-blue-700';
      case 'LOW':
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm">
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                Security Alerts Center
                <span className="px-2 py-0.2 rounded-full text-xs font-mono bg-rose-950 border border-rose-800 text-rose-400 font-bold">
                  {alerts.length}
                </span>
              </h2>
              <div className="text-xs text-slate-400">Passive IDS Behavioral Threat Stream</div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Severity Filter Bar & Actions */}
        <div className="p-3 border-b border-slate-800 bg-slate-950 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-1">
            <span className="text-slate-500 mr-1 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Severity:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                  severityFilter === sev
                    ? 'bg-cyan-600 text-white font-semibold'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onExportAlertsCsv}
              disabled={alerts.length === 0}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 transition-colors text-[11px]"
              title="Export alerts to CSV file"
            >
              <Download className="w-3 h-3" /> CSV
            </button>
            <button
              onClick={onClearResolved}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-rose-300 transition-colors text-[11px]"
              title="Clear resolved alerts from list"
            >
              <Trash2 className="w-3 h-3" /> Clear Resolved
            </button>
          </div>
        </div>

        {/* Alert List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {filteredAlerts.length === 0 ? (
            <div className="py-20 text-center text-slate-500 font-mono text-xs">
              <CheckCircle className="w-8 h-8 text-emerald-500/60 mx-auto mb-2" />
              <div>No alerts matching the selected filter.</div>
              <div className="text-[11px] text-slate-600 mt-1">Network perimeter status nominal.</div>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-3.5 rounded-lg border transition-all ${
                  alert.resolved
                    ? 'bg-slate-950/40 border-slate-800/60 opacity-60'
                    : alert.severity === 'CRITICAL'
                    ? 'bg-rose-950/30 border-rose-800/80'
                    : alert.severity === 'HIGH'
                    ? 'bg-amber-950/25 border-amber-800/80'
                    : 'bg-slate-950 border-slate-800'
                }`}
              >
                {/* Header info */}
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-xs font-bold text-white">{alert.title}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 shrink-0">
                    {alert.timestamp}
                  </span>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-300 font-sans leading-relaxed mb-2.5">
                  {alert.description}
                </p>

                {/* Metadata & MITRE */}
                <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400 mb-3 bg-slate-900/80 p-2 rounded border border-slate-800">
                  <div>
                    <span className="text-slate-500">Src:</span>{' '}
                    <span className="text-rose-300">{alert.sourceIp}</span>
                  </div>
                  <span>→</span>
                  <div>
                    <span className="text-slate-500">Dst:</span>{' '}
                    <span className="text-slate-200">{alert.destinationIp}</span>
                    {alert.destinationPort && <span>:{alert.destinationPort}</span>}
                  </div>
                  <span className="text-slate-600">•</span>
                  <div>
                    <span className="text-slate-500">MITRE:</span>{' '}
                    <span className="text-cyan-400 font-bold">{alert.mitreId}</span>
                  </div>
                  <span className="text-slate-600">•</span>
                  <div>
                    <span className="text-slate-500">Packet:</span> #{alert.packetId}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-800/60">
                  <button
                    onClick={() => onInspectPacketById(alert.packetId)}
                    className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 text-[11px]"
                  >
                    Inspect Flagged Packet <ChevronRight className="w-3 h-3" />
                  </button>

                  <div className="flex items-center gap-2">
                    {!alert.acknowledged && (
                      <button
                        onClick={() => onAcknowledgeAlert(alert.id)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]"
                      >
                        Acknowledge
                      </button>
                    )}
                    {!alert.resolved ? (
                      <button
                        onClick={() => onResolveAlert(alert.id)}
                        className="px-2 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-[11px]"
                      >
                        Resolve
                      </button>
                    ) : (
                      <span className="text-emerald-400 text-[11px] font-mono flex items-center gap-1">
                        <CheckCircle className="w-3 h-3" /> Resolved
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-900 flex justify-between items-center text-xs text-slate-400">
          <span>Active Heuristics: Port Scan, DoS, DNS Tunnel, Telnet, Brute-Force</span>
          <button
            onClick={onClose}
            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
