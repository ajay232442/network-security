import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Terminal,
  Cpu,
  ChevronRight,
  ChevronDown,
  Copy,
  Check,
  AlertTriangle,
  Sparkles,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import { AiPacketAnalysis, NetworkPacket } from '../types/network';
import { analyzePacketWithAi } from '../services/geminiService';

interface PacketInspectorModalProps {
  packet: NetworkPacket | null;
  onClose: () => void;
}

export const PacketInspectorModal: React.FC<PacketInspectorModalProps> = ({
  packet,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'TREE' | 'HEX' | 'AI'>('TREE');
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<AiPacketAnalysis | null>(null);
  const [copiedRuleIndex, setCopiedRuleIndex] = useState<number | null>(null);

  // Sections collapse state for protocol tree
  const [expandedSections, setExpandedSections] = useState({
    frame: true,
    ethernet: true,
    ip: true,
    transport: true,
    application: true,
  });

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const handleRunAiAnalysis = async () => {
    if (!packet) return;
    setIsAiLoading(true);
    try {
      const result = await analyzePacketWithAi(packet);
      setAiAnalysis(result);
    } catch (err) {
      console.error('AI analysis error:', err);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleCopyRule = (rule: string, index: number) => {
    navigator.clipboard.writeText(rule);
    setCopiedRuleIndex(index);
    setTimeout(() => setCopiedRuleIndex(null), 2000);
  };

  if (!packet) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-wide">
                  Packet #{packet.id} Deep Inspector
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                  {packet.protocol}
                </span>
                {packet.isSuspicious && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/80 text-rose-300 border border-rose-700">
                    <AlertTriangle className="w-3 h-3" />
                    {packet.severity || 'SUSPICIOUS'}
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                {packet.sourceIp}:{packet.sourcePort ?? '-'} → {packet.destinationIp}:
                {packet.destinationPort ?? '-'} • {packet.length} bytes • {packet.timestamp}
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

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950 px-5 gap-2 text-xs font-medium">
          <button
            onClick={() => setActiveTab('TREE')}
            className={`py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'TREE'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            Protocol Tree Dissection
          </button>
          <button
            onClick={() => setActiveTab('HEX')}
            className={`py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'HEX'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Hex & ASCII Payload
          </button>
          <button
            onClick={() => {
              setActiveTab('AI');
              if (!aiAnalysis && !isAiLoading) {
                handleRunAiAnalysis();
              }
            }}
            className={`py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'AI'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            AI Threat Forensic Analyst
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 font-mono text-xs text-slate-300">
          {/* TAB 1: PROTOCOL TREE */}
          {activeTab === 'TREE' && (
            <div className="space-y-2">
              {/* Frame Level */}
              <div className="border border-slate-800 rounded bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => toggleSection('frame')}
                  className="w-full text-left p-2.5 bg-slate-900/60 hover:bg-slate-850 flex items-center justify-between text-slate-200 font-semibold text-xs"
                >
                  <span className="flex items-center gap-1.5">
                    {expandedSections.frame ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Frame {packet.id}: {packet.length} bytes on wire ({packet.length * 8} bits)
                  </span>
                  <span className="text-[10px] text-slate-500">Physical Layer</span>
                </button>
                {expandedSections.frame && (
                  <div className="p-3 text-[11px] text-slate-400 space-y-1 bg-slate-950/40 border-t border-slate-850">
                    <div>• Arrival Time: {packet.timestamp} (Epoch: {packet.timeEpoch} ms)</div>
                    <div>• Frame Number: {packet.id}</div>
                    <div>• Frame Length: {packet.length} bytes</div>
                    <div>• Capture Length: {packet.length} bytes</div>
                    <div>• Direction: <span className="text-cyan-400">{packet.direction}</span></div>
                  </div>
                )}
              </div>

              {/* Ethernet II */}
              <div className="border border-slate-800 rounded bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => toggleSection('ethernet')}
                  className="w-full text-left p-2.5 bg-slate-900/60 hover:bg-slate-850 flex items-center justify-between text-slate-200 font-semibold text-xs"
                >
                  <span className="flex items-center gap-1.5">
                    {expandedSections.ethernet ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Ethernet II, Src: {packet.macSrc || '00:1a:2b:3c:4d:5e'}, Dst: {packet.macDst || '00:50:56:c0:00:08'}
                  </span>
                  <span className="text-[10px] text-slate-500">Data Link Layer</span>
                </button>
                {expandedSections.ethernet && (
                  <div className="p-3 text-[11px] text-slate-400 space-y-1 bg-slate-950/40 border-t border-slate-850">
                    <div>• Destination MAC: {packet.macDst || '00:50:56:c0:00:08'}</div>
                    <div>• Source MAC: {packet.macSrc || '00:1a:2b:3c:4d:5e'}</div>
                    <div>• Type: IPv4 (0x0800)</div>
                  </div>
                )}
              </div>

              {/* Internet Protocol Version 4 */}
              <div className="border border-slate-800 rounded bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => toggleSection('ip')}
                  className="w-full text-left p-2.5 bg-slate-900/60 hover:bg-slate-850 flex items-center justify-between text-slate-200 font-semibold text-xs"
                >
                  <span className="flex items-center gap-1.5">
                    {expandedSections.ip ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Internet Protocol Version 4, Src: {packet.sourceIp}, Dst: {packet.destinationIp}
                  </span>
                  <span className="text-[10px] text-slate-500">Network Layer</span>
                </button>
                {expandedSections.ip && (
                  <div className="p-3 text-[11px] text-slate-400 space-y-1 bg-slate-950/40 border-t border-slate-850">
                    <div>• Version: 4</div>
                    <div>• Header Length: 20 bytes (5)</div>
                    <div>• Total Length: {packet.length} bytes</div>
                    <div>• Identification: 0x{((packet.ipId || packet.id * 17) & 0xffff).toString(16).padStart(4, '0')}</div>
                    <div>• Time to Live (TTL): {packet.ttl || 64} hops</div>
                    <div>• Protocol: {packet.protocol} ({packet.protocol === 'UDP' || packet.protocol === 'DNS' ? 17 : packet.protocol === 'ICMP' ? 1 : 6})</div>
                    <div>• Source Address: <span className="text-slate-200">{packet.sourceIp}</span></div>
                    <div>• Destination Address: <span className="text-slate-200">{packet.destinationIp}</span></div>
                  </div>
                )}
              </div>

              {/* Transport Layer (TCP / UDP / ICMP) */}
              <div className="border border-slate-800 rounded bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => toggleSection('transport')}
                  className="w-full text-left p-2.5 bg-slate-900/60 hover:bg-slate-850 flex items-center justify-between text-slate-200 font-semibold text-xs"
                >
                  <span className="flex items-center gap-1.5">
                    {expandedSections.transport ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    {packet.protocol === 'UDP' || packet.protocol === 'DNS'
                      ? `User Datagram Protocol, Src Port: ${packet.sourcePort}, Dst Port: ${packet.destinationPort}`
                      : packet.protocol === 'ICMP'
                      ? 'Internet Control Message Protocol (ICMP)'
                      : `Transmission Control Protocol, Src Port: ${packet.sourcePort}, Dst Port: ${packet.destinationPort}`}
                  </span>
                  <span className="text-[10px] text-slate-500">Transport Layer</span>
                </button>
                {expandedSections.transport && (
                  <div className="p-3 text-[11px] text-slate-400 space-y-1 bg-slate-950/40 border-t border-slate-850">
                    {packet.sourcePort !== null && <div>• Source Port: {packet.sourcePort}</div>}
                    {packet.destinationPort !== null && <div>• Destination Port: {packet.destinationPort}</div>}
                    {packet.flags && (
                      <div>
                        • Flags: [
                        {Object.entries(packet.flags)
                          .filter(([, v]) => v)
                          .map(([k]) => k.toUpperCase())
                          .join(', ')}
                        ]
                      </div>
                    )}
                    <div>• Info: {packet.info}</div>
                  </div>
                )}
              </div>

              {/* Application Layer (DNS / HTTP / Payload) */}
              {(packet.dnsQuery || packet.protocol === 'HTTP' || packet.protocol === 'HTTPS') && (
                <div className="border border-slate-800 rounded bg-slate-950/60 overflow-hidden">
                  <button
                    onClick={() => toggleSection('application')}
                    className="w-full text-left p-2.5 bg-slate-900/60 hover:bg-slate-850 flex items-center justify-between text-slate-200 font-semibold text-xs"
                  >
                    <span className="flex items-center gap-1.5">
                      {expandedSections.application ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      Application Layer: {packet.dnsQuery ? 'Domain Name System (query)' : packet.protocol}
                    </span>
                    <span className="text-[10px] text-slate-500">Application Layer</span>
                  </button>
                  {expandedSections.application && (
                    <div className="p-3 text-[11px] text-slate-400 space-y-1 bg-slate-950/40 border-t border-slate-850">
                      {packet.dnsQuery && (
                        <>
                          <div>• DNS Query: <span className="text-cyan-300 font-bold">{packet.dnsQuery}</span></div>
                          <div>• Record Type: {packet.dnsType || 'A'}</div>
                        </>
                      )}
                      {packet.payloadPreview && <div>• Decoded Payload String: {packet.payloadPreview}</div>}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: HEX DUMP & ASCII */}
          {activeTab === 'HEX' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Offset | Hexadecimal Bytes (16/line) | ASCII Representation</span>
                <span className="text-slate-500">Passive sanitized display</span>
              </div>
              <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-[11px] leading-relaxed text-emerald-400 overflow-x-auto selection:bg-cyan-900 selection:text-white">
                {packet.rawHex ||
                  `0000   00 1a 2b 3c 4d 5e 00 50 56 c0 00 08 08 00 45 00   ..+<M^.PV.....E.\n0010   00 3c 2b 1a 40 00 40 06 c8 44 c0 a8 01 69 c0 a8   .<+.@.@..D...i..\n0020   01 01 c8 01 00 50 00 00 00 00 00 00 00 00 a0 02   .....P..........`}
              </pre>
            </div>
          )}

          {/* TAB 3: AI THREAT FORENSIC ANALYST */}
          {activeTab === 'AI' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
                    <Sparkles className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white flex items-center gap-2">
                      Gemini SOC Threat Intelligence
                      <span className="text-[10px] font-normal text-cyan-400 bg-cyan-950/80 px-1.5 py-0.2 rounded border border-cyan-800">
                        gemini-3.8-flash
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Heuristic correlation, MITRE ATT&CK mapping, and automated firewall rule generation
                    </div>
                  </div>
                </div>

                <button
                  onClick={handleRunAiAnalysis}
                  disabled={isAiLoading}
                  className="px-3 py-1.5 rounded-md text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{isAiLoading ? 'Analyzing...' : 'Re-Analyze Packet'}</span>
                </button>
              </div>

              {isAiLoading && (
                <div className="py-12 text-center text-slate-400 space-y-2">
                  <div className="inline-block animate-spin rounded-full h-8 w-8 border-2 border-cyan-500 border-t-transparent" />
                  <div className="text-xs font-mono">Conducting deep forensic analysis of packet #{packet.id}...</div>
                </div>
              )}

              {!isAiLoading && aiAnalysis && (
                <div className="space-y-4">
                  {/* Threat assessment banner */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                        Threat Assessment
                      </div>
                      <div className="text-xs font-bold text-white">{aiAnalysis.threatAssessment}</div>
                    </div>

                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                        MITRE ATT&CK Tactic
                      </div>
                      <div className="text-xs font-bold text-cyan-400">{aiAnalysis.mitreAttack}</div>
                    </div>

                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                        Threat Confidence
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="text-xs font-bold text-white">{aiAnalysis.confidenceScore}%</div>
                        <div className="flex-1 bg-slate-900 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              aiAnalysis.confidenceScore > 75
                                ? 'bg-rose-500'
                                : aiAnalysis.confidenceScore > 40
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${aiAnalysis.confidenceScore}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Technical Analysis */}
                  <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-1.5">
                    <div className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" /> Technical Forensic Breakdown
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">
                      {aiAnalysis.technicalAnalysis}
                    </p>
                  </div>

                  {/* Indicators of Compromise (IOC) */}
                  {aiAnalysis.indicatorsOfCompromise?.length > 0 && (
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs font-semibold text-slate-200 mb-2">
                        Indicators of Compromise (IOCs)
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {aiAnalysis.indicatorsOfCompromise.map((ioc, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-rose-300 text-[11px] font-mono"
                          >
                            {ioc}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Mitigation Rules */}
                  {aiAnalysis.mitigationRules?.length > 0 && (
                    <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2">
                      <div className="text-xs font-semibold text-slate-200">
                        Generated Defensive Firewall / IDS Mitigation Rules
                      </div>
                      <div className="space-y-2">
                        {aiAnalysis.mitigationRules.map((rule, idx) => (
                          <div
                            key={idx}
                            className="bg-slate-900 p-2.5 rounded border border-slate-800 flex items-center justify-between gap-3"
                          >
                            <div className="overflow-x-auto font-mono text-[11px]">
                              <span className="text-cyan-400 font-bold mr-2">[{rule.tool}]</span>
                              <span className="text-slate-300">{rule.rule}</span>
                            </div>
                            <button
                              onClick={() => handleCopyRule(rule.rule, idx)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] flex items-center gap-1 shrink-0 transition-colors"
                            >
                              {copiedRuleIndex === idx ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" /> Copy
                                </>
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Immediate Action */}
                  <div className="bg-blue-950/30 p-3 rounded-lg border border-blue-900/60 flex items-start gap-2.5">
                    <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-bold text-white mb-0.5">Recommended SOC Immediate Action</div>
                      <div className="text-xs text-slate-300 font-sans">{aiAnalysis.immediateAction}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-900 flex justify-between items-center text-xs">
          <span className="text-slate-500 font-mono">
            Inspection Mode: Passive Wireshark-compatible telemetry
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
