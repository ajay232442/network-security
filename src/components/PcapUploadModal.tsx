import React, { useState, useRef } from 'react';
import {
  X,
  Upload,
  FileCode,
  CheckCircle,
  AlertCircle,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { NetworkPacket } from '../types/network';
import { parsePcapArrayBuffer } from '../utils/pcapParser';
import { PRESET_SCENARIOS, PresetScenario } from '../utils/samplePcaps';

interface PcapUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadPackets: (packets: NetworkPacket[], sourceName: string) => void;
}

export const PcapUploadModal: React.FC<PcapUploadModalProps> = ({
  isOpen,
  onClose,
  onLoadPackets,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const processFile = async (file: File) => {
    setErrorMessage(null);
    setLoading(true);

    try {
      if (!file.name.endsWith('.pcap') && !file.name.endsWith('.cap') && !file.name.endsWith('.pcapng')) {
        // Warning but proceed to inspect buffer magic
      }

      const buffer = await file.arrayBuffer();
      const parsedPackets = parsePcapArrayBuffer(buffer, 2500);

      if (parsedPackets.length === 0) {
        throw new Error('No IP or Ethernet packets could be decoded from this capture file.');
      }

      onLoadPackets(parsedPackets, file.name);
      onClose();
    } catch (err: unknown) {
      console.error('PCAP parsing error:', err);
      setErrorMessage(
        err instanceof Error ? err.message : 'Failed to parse PCAP file. Ensure it is a valid libpcap capture.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleSelectScenario = (scenario: PresetScenario) => {
    const packets = scenario.generatePackets();
    onLoadPackets(packets, scenario.name);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                Import PCAP Capture or Incident Scenario
              </h2>
              <div className="text-xs text-slate-400">
                Inspect real libpcap (.pcap/.cap) files or launch pre-configured cyber attack scenarios
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* File Upload Zone */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Upload Custom PCAP Capture
            </label>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                isDragging
                  ? 'border-cyan-400 bg-cyan-950/30'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-950/60'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.cap,.pcapng"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    processFile(e.target.files[0]);
                  }
                }}
              />

              <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-3 text-cyan-400">
                <FileCode className="w-6 h-6" />
              </div>

              <div className="text-xs font-semibold text-white mb-1">
                Drag & drop your .pcap or .cap file here, or click to browse
              </div>
              <div className="text-[11px] text-slate-400 font-mono">
                Decodes Ethernet II, IPv4, TCP, UDP, ICMP, DNS & ARP frames
              </div>
            </div>

            {loading && (
              <div className="mt-2 text-xs text-cyan-400 font-mono flex items-center justify-center gap-2">
                <span className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                Parsing binary packet structures...
              </div>
            )}

            {errorMessage && (
              <div className="mt-2 p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}
          </div>

          <div className="relative flex py-1 items-center">
            <div className="flex-grow border-t border-slate-800"></div>
            <span className="flex-shrink mx-4 text-xs text-slate-500 uppercase tracking-widest font-mono">
              Or Load Curated Attack Scenarios
            </span>
            <div className="flex-grow border-t border-slate-800"></div>
          </div>

          {/* Preset Attack Scenarios */}
          <div className="space-y-2.5">
            {PRESET_SCENARIOS.map((sc) => (
              <div
                key={sc.id}
                onClick={() => handleSelectScenario(sc)}
                className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 hover:bg-slate-850 hover:border-slate-700 cursor-pointer transition-all flex items-center justify-between group"
              >
                <div className="space-y-1 pr-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                      {sc.name}
                    </span>
                    <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${sc.badgeColor}`}>
                      {sc.badge}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-sans leading-relaxed">
                    {sc.description}
                  </p>
                </div>

                <div className="shrink-0 p-2 rounded-lg bg-slate-900 group-hover:bg-cyan-950 text-slate-400 group-hover:text-cyan-400 transition-colors">
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-900 flex justify-between items-center text-xs">
          <span className="text-slate-500 font-mono">
            Supported: Libpcap 2.4, Wireshark, tcpdump captures
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
