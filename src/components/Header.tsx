import React from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  Upload,
  FileText,
  Download,
  ShieldAlert,
  Flame,
  Radio,
  SlidersHorizontal,
} from 'lucide-react';
import { NetworkInterfaceInfo } from '../types/network';

interface HeaderProps {
  isCapturing: boolean;
  onToggleCapture: () => void;
  onClearCapture: () => void;
  captureSpeed: number;
  onChangeSpeed: (speed: number) => void;
  interfaces: NetworkInterfaceInfo[];
  selectedInterface: string;
  onSelectInterface: (id: string) => void;
  onOpenUpload: () => void;
  onOpenAlerts: () => void;
  onOpenReport: () => void;
  onExportCsv: () => void;
  onInjectThreat: () => void;
  unreadAlertCount: number;
  totalPackets: number;
}

export const Header: React.FC<HeaderProps> = ({
  isCapturing,
  onToggleCapture,
  onClearCapture,
  captureSpeed,
  onChangeSpeed,
  interfaces,
  selectedInterface,
  onSelectInterface,
  onOpenUpload,
  onOpenAlerts,
  onOpenReport,
  onExportCsv,
  onInjectThreat,
  unreadAlertCount,
  totalPackets,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 px-4 py-3 sticky top-0 z-30 shadow-lg">
      <div className="max-w-7xl mx-auto flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
        {/* Brand & Interface Selector */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-500/20 ring-1 ring-cyan-400/40">
            <Radio className="w-5 h-5 text-white animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg tracking-tight text-white flex items-center gap-1.5">
                NETWATCH <span className="text-cyan-400 font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800">SOC IDS</span>
              </h1>
              <span className="text-xs text-slate-400 hidden sm:inline">| Network Traffic Analyzer</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
              <span className="flex items-center gap-1">
                <span
                  className={`w-2 h-2 rounded-full ${
                    isCapturing ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'bg-amber-400'
                  }`}
                />
                <span className="font-mono">{isCapturing ? 'STREAMING' : 'PAUSED'}</span>
              </span>
              <span>•</span>
              <div className="flex items-center gap-1">
                <span className="text-slate-500">Interface:</span>
                <select
                  value={selectedInterface}
                  onChange={(e) => onSelectInterface(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2 py-0.5 focus:outline-none focus:border-cyan-500"
                >
                  {interfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>
                      {iface.name} ({iface.ip}) {iface.promiscuous ? '[Promisc]' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* Capture Controls & Speed */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Play/Pause Button */}
          <button
            onClick={onToggleCapture}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
              isCapturing
                ? 'bg-amber-600/20 text-amber-300 border border-amber-500/40 hover:bg-amber-600/30'
                : 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30 hover:bg-emerald-500'
            }`}
            title={isCapturing ? 'Pause Live Capture' : 'Start Live Capture'}
          >
            {isCapturing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isCapturing ? 'Pause' : 'Start Capture'}</span>
          </button>

          {/* Speed Selector */}
          <div className="flex items-center bg-slate-800/80 rounded-md border border-slate-700/80 p-0.5 text-xs text-slate-300">
            <span className="px-2 text-slate-400 flex items-center gap-1">
              <SlidersHorizontal className="w-3 h-3" />
              <span className="hidden sm:inline">Rate:</span>
            </span>
            {[1, 2, 5, 10].map((spd) => (
              <button
                key={spd}
                onClick={() => onChangeSpeed(spd)}
                className={`px-2 py-0.5 rounded text-xs transition-colors ${
                  captureSpeed === spd
                    ? 'bg-cyan-600 text-white font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {spd}x
              </button>
            ))}
          </div>

          {/* Inject Test Threat */}
          <button
            onClick={onInjectThreat}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/40 hover:border-rose-600 transition-colors"
            title="Inject an anomalous or attack packet into the stream to test IDS triggers"
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span className="hidden sm:inline">Simulate Threat</span>
          </button>

          {/* Clear Buffer */}
          <button
            onClick={onClearCapture}
            disabled={totalPackets === 0}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            title="Clear captured packets buffer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Clear</span>
          </button>

          <div className="h-4 w-px bg-slate-800 hidden lg:block" />

          {/* PCAP Upload & Presets */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-cyan-950/50 text-cyan-300 border border-cyan-800/60 hover:bg-cyan-900/40 hover:border-cyan-600 transition-colors"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>PCAP Files</span>
          </button>

          {/* Security Alerts Drawer */}
          <button
            onClick={onOpenAlerts}
            className="relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-750 transition-colors"
          >
            <ShieldAlert className={`w-3.5 h-3.5 ${unreadAlertCount > 0 ? 'text-amber-400' : 'text-slate-400'}`} />
            <span>Alerts</span>
            {unreadAlertCount > 0 && (
              <span className="px-1.5 py-0.2 bg-rose-600 text-white font-mono text-[10px] rounded-full font-bold animate-pulse">
                {unreadAlertCount}
              </span>
            )}
          </button>

          {/* Export CSV */}
          <button
            onClick={onExportCsv}
            disabled={totalPackets === 0}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            title="Export captured packets to CSV"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">CSV</span>
          </button>

          {/* Executive SOC Report */}
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-md shadow-blue-600/20 hover:from-blue-500 hover:to-indigo-500 transition-all"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Audit Report</span>
          </button>
        </div>
      </div>
    </header>
  );
};
