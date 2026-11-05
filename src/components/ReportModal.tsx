import React, { useState, useEffect } from 'react';
import {
  X,
  FileText,
  Printer,
  Download,
  ShieldCheck,
  AlertTriangle,
  Sparkles,
  Server,
  Layers,
  ArrowDownLeft,
  ArrowUpRight,
} from 'lucide-react';
import { ExecutiveReportData, SecurityAlert, TrafficStats } from '../types/network';
import { generateSocReportWithAi } from '../services/geminiService';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  stats: TrafficStats;
  alerts: SecurityAlert[];
  topTalkers: Array<{ ip: string; packets: number; bytes: number; role: 'source' | 'destination' }>;
  onExportCsv: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  stats,
  alerts,
  topTalkers,
  onExportCsv,
}) => {
  const [report, setReport] = useState<ExecutiveReportData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      generateSocReportWithAi(stats, alerts, topTalkers)
        .then((res) => setReport(res))
        .finally(() => setLoading(false));
    }
  }, [isOpen, stats.totalPackets, alerts.length]);

  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  const getPostureBadge = (posture?: string) => {
    switch (posture) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-300 border-rose-700';
      case 'ELEVATED':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-700';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-950/80 backdrop-blur-sm print:p-0 print:bg-white">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden print:border-none print:shadow-none print:max-h-none print:w-full">
        {/* Header (Hidden in Print) */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between print:hidden">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-950 border border-blue-800 text-blue-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                Executive Network Traffic & SOC Audit Report
              </h2>
              <div className="text-xs text-slate-400">
                Generated {report?.generatedAt || new Date().toLocaleString()}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
            <button
              onClick={onExportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>CSV Data</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Report Document Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-slate-200 print:text-black print:bg-white print:p-8">
          {loading ? (
            <div className="py-20 text-center space-y-2">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-2 border-cyan-500 border-t-transparent" />
              <div className="text-xs font-mono text-slate-400">
                Synthesizing traffic analytics and executive security audit...
              </div>
            </div>
          ) : report ? (
            <>
              {/* Document Letterhead */}
              <div className="border-b border-slate-800 print:border-black pb-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div>
                  <div className="text-xs font-mono uppercase tracking-widest text-cyan-400 print:text-blue-800 font-bold">
                    CYBERSECURITY INCIDENT RESPONSE TEAM (CIRT)
                  </div>
                  <h1 className="text-xl font-bold text-white print:text-black tracking-tight mt-0.5">
                    Network Traffic Assessment & Threat Audit
                  </h1>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 print:text-gray-600 font-mono">Posture:</span>
                  <span
                    className={`px-3 py-1 rounded text-xs font-bold font-mono border ${getPostureBadge(
                      report.riskPosture
                    )} print:bg-gray-100 print:text-black print:border-black`}
                  >
                    {report.riskPosture} RISK
                  </span>
                </div>
              </div>

              {/* Metric Highlights Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 print:grid-cols-4">
                <div className="bg-slate-950 print:bg-gray-50 p-3 rounded-lg border border-slate-800 print:border-gray-300">
                  <div className="text-[10px] text-slate-400 print:text-gray-600 uppercase font-mono">
                    Total Packets
                  </div>
                  <div className="text-lg font-bold font-mono text-white print:text-black mt-0.5">
                    {stats.totalPackets.toLocaleString()}
                  </div>
                </div>

                <div className="bg-slate-950 print:bg-gray-50 p-3 rounded-lg border border-slate-800 print:border-gray-300">
                  <div className="text-[10px] text-slate-400 print:text-gray-600 uppercase font-mono">
                    Total Volume
                  </div>
                  <div className="text-lg font-bold font-mono text-white print:text-black mt-0.5">
                    {(stats.totalBytes / 1024).toFixed(1)} KB
                  </div>
                </div>

                <div className="bg-slate-950 print:bg-gray-50 p-3 rounded-lg border border-slate-800 print:border-gray-300">
                  <div className="text-[10px] text-slate-400 print:text-gray-600 uppercase font-mono">
                    Flagged Anomalies
                  </div>
                  <div className="text-lg font-bold font-mono text-rose-400 print:text-red-700 mt-0.5">
                    {stats.suspiciousCount}
                  </div>
                </div>

                <div className="bg-slate-950 print:bg-gray-50 p-3 rounded-lg border border-slate-800 print:border-gray-300">
                  <div className="text-[10px] text-slate-400 print:text-gray-600 uppercase font-mono">
                    Critical Alerts
                  </div>
                  <div className="text-lg font-bold font-mono text-white print:text-black mt-0.5">
                    {stats.severityCounts.CRITICAL}
                  </div>
                </div>
              </div>

              {/* Section 1: Executive Summary */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 print:text-blue-800 font-mono">
                  1. Executive Summary
                </h3>
                <div className="bg-slate-950/60 print:bg-gray-50 p-4 rounded-lg border border-slate-800 print:border-gray-300 text-xs text-slate-300 print:text-gray-800 leading-relaxed font-sans">
                  {report.executiveSummary}
                </div>
              </div>

              {/* Section 2: Primary Detected Threats */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 print:text-blue-800 font-mono">
                  2. Primary Threat Vectors Observed
                </h3>
                <div className="bg-slate-950/60 print:bg-gray-50 p-4 rounded-lg border border-slate-800 print:border-gray-300">
                  <ul className="space-y-2 text-xs">
                    {report.primaryThreats.map((threat, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 print:text-amber-600 shrink-0 mt-0.5" />
                        <span className="text-slate-300 print:text-gray-800">{threat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Section 3: Top Talkers */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 print:text-blue-800 font-mono">
                  3. Network Host Volume & Top Talkers
                </h3>
                <div className="bg-slate-950/60 print:bg-gray-50 rounded-lg border border-slate-800 print:border-gray-300 overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900 print:bg-gray-200 text-slate-400 print:text-gray-700 text-[11px] uppercase border-b border-slate-800 print:border-gray-300">
                      <tr>
                        <th className="py-2 px-3">IP Address</th>
                        <th className="py-2 px-3">Role</th>
                        <th className="py-2 px-3 text-right">Packets</th>
                        <th className="py-2 px-3 text-right">Bytes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 print:divide-gray-200">
                      {topTalkers.map((talker, idx) => (
                        <tr key={idx}>
                          <td className="py-2 px-3 text-slate-200 print:text-black font-semibold">
                            {talker.ip}
                          </td>
                          <td className="py-2 px-3 text-slate-400 print:text-gray-700 uppercase text-[10px]">
                            {talker.role}
                          </td>
                          <td className="py-2 px-3 text-right text-slate-300 print:text-gray-800">
                            {talker.packets.toLocaleString()}
                          </td>
                          <td className="py-2 px-3 text-right text-slate-300 print:text-gray-800">
                            {(talker.bytes / 1024).toFixed(1)} KB
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Section 4: Recommended Defensive Remediations */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 print:text-blue-800 font-mono">
                  4. Defense-in-Depth Hardening Recommendations
                </h3>
                <div className="bg-slate-950/60 print:bg-gray-50 p-4 rounded-lg border border-slate-800 print:border-gray-300">
                  <ul className="space-y-2 text-xs">
                    {report.defensiveRecommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 print:text-emerald-600 shrink-0 mt-0.5" />
                        <span className="text-slate-300 print:text-gray-800 font-sans">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          ) : null}
        </div>

        {/* Footer (Hidden in Print) */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-900 flex justify-between items-center text-xs print:hidden">
          <span className="text-slate-500 font-mono">
            Report Type: SOC Passive Perimeter Security Analysis
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
};
