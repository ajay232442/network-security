import { NetworkPacket, Protocol, TrafficDirection } from '../types/network';

/**
 * Libpcap standard header magic numbers:
 * 0xa1b2c3d4 (standard microseconds, big-endian or same endian)
 * 0xd4c3b2a1 (standard microseconds, little-endian)
 * 0xa1b23c4d (nanoseconds, big-endian)
 * 0x4d3cb2a1 (nanoseconds, little-endian)
 */
export function isPcapFile(buffer: ArrayBuffer): boolean {
  if (buffer.byteLength < 24) return false;
  const view = new DataView(buffer);
  const magic = view.getUint32(0, false);
  return (
    magic === 0xa1b2c3d4 ||
    magic === 0xd4c3b2a1 ||
    magic === 0xa1b23c4d ||
    magic === 0x4d3cb2a1
  );
}

function formatMac(bytes: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(bytes[offset + i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

function formatIpv4(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

export function formatHexDump(bytes: Uint8Array, maxBytes = 256): string {
  const lines: string[] = [];
  const limit = Math.min(bytes.length, maxBytes);

  for (let i = 0; i < limit; i += 16) {
    const offsetHex = i.toString(16).padStart(4, '0');
    const chunk = bytes.slice(i, Math.min(i + 16, limit));

    // Hex representation
    const hexPart: string[] = [];
    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        hexPart.push(chunk[j].toString(16).padStart(2, '0'));
      } else {
        hexPart.push('  ');
      }
      if (j === 7) hexPart.push(' ');
    }

    // ASCII representation (printable characters)
    let asciiPart = '';
    for (let j = 0; j < chunk.length; j++) {
      const b = chunk[j];
      asciiPart += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }

    lines.push(`${offsetHex}   ${hexPart.join(' ')}   |${asciiPart}|`);
  }

  if (bytes.length > maxBytes) {
    lines.push(`... [${bytes.length - maxBytes} bytes truncated for display]`);
  }

  return lines.join('\n');
}

function parseDnsQuery(payload: Uint8Array): { query?: string; type?: string } {
  try {
    if (payload.length < 12) return {};
    let offset = 12; // Skip DNS Header (ID, Flags, QDCount, etc.)
    const labels: string[] = [];

    while (offset < payload.length) {
      const len = payload[offset++];
      if (len === 0) break;
      if (offset + len > payload.length) break;
      let label = '';
      for (let i = 0; i < len; i++) {
        label += String.fromCharCode(payload[offset + i]);
      }
      labels.push(label);
      offset += len;
    }

    const query = labels.join('.');
    let type = 'A';
    if (offset + 2 <= payload.length) {
      const qtype = (payload[offset] << 8) | payload[offset + 1];
      if (qtype === 1) type = 'A';
      else if (qtype === 28) type = 'AAAA';
      else if (qtype === 5) type = 'CNAME';
      else if (qtype === 16) type = 'TXT';
      else if (qtype === 15) type = 'MX';
      else type = `TYPE${qtype}`;
    }

    return { query, type };
  } catch {
    return {};
  }
}

/**
 * Parses binary libpcap files into an array of NetworkPacket records.
 */
export function parsePcapArrayBuffer(buffer: ArrayBuffer, maxPackets = 1000): NetworkPacket[] {
  if (buffer.byteLength < 24) {
    throw new Error('File is too short to be a valid PCAP capture (minimum 24 bytes).');
  }

  const view = new DataView(buffer);
  const rawBytes = new Uint8Array(buffer);
  const magic = view.getUint32(0, false);

  let littleEndian = false;
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    littleEndian = true;
  } else {
    throw new Error('Unsupported capture format. Please provide a standard libpcap (.pcap) file.');
  }

  const linkType = view.getUint32(20, littleEndian);
  // 1 = LINKTYPE_ETHERNET, 101 = LINKTYPE_RAW (IP)
  const isEthernet = linkType === 1;

  const packets: NetworkPacket[] = [];
  let offset = 24;
  let packetIndex = 1;

  while (offset + 16 <= buffer.byteLength && packets.length < maxPackets) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    const origLen = view.getUint32(offset + 12, littleEndian);
    offset += 16;

    if (offset + inclLen > buffer.byteLength) {
      break; // Truncated final packet
    }

    const packetData = rawBytes.subarray(offset, offset + inclLen);
    offset += inclLen;

    const timeEpoch = tsSec * 1000 + Math.floor(tsUsec / 1000);
    const date = new Date(timeEpoch);
    const timestamp = date.toTimeString().split(' ')[0] + '.' + String(date.getMilliseconds()).padStart(3, '0');

    let macSrc: string | undefined;
    let macDst: string | undefined;
    let ethType = 0x0800;
    let ipOffset = 0;

    if (isEthernet && packetData.length >= 14) {
      macDst = formatMac(packetData, 0);
      macSrc = formatMac(packetData, 6);
      ethType = (packetData[12] << 8) | packetData[13];
      ipOffset = 14;

      // Handle 802.1Q VLAN Tagging (0x8100)
      if (ethType === 0x8100 && packetData.length >= 18) {
        ethType = (packetData[16] << 8) | packetData[17];
        ipOffset = 18;
      }
    }

    // ARP
    if (ethType === 0x0806 && packetData.length >= ipOffset + 28) {
      const op = (packetData[ipOffset + 6] << 8) | packetData[ipOffset + 7];
      const senderIp = formatIpv4(packetData, ipOffset + 14);
      const targetIp = formatIpv4(packetData, ipOffset + 24);
      const info = op === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${macSrc}`;

      packets.push({
        id: packetIndex++,
        timestamp,
        timeEpoch,
        sourceIp: senderIp,
        destinationIp: targetIp,
        sourcePort: null,
        destinationPort: null,
        protocol: 'ARP',
        length: origLen,
        info,
        direction: 'INTERNAL',
        isSuspicious: false,
        rawHex: formatHexDump(packetData),
        macSrc,
        macDst,
      });
      continue;
    }

    // IPv4
    if (ethType === 0x0800 && packetData.length >= ipOffset + 20) {
      const verIhl = packetData[ipOffset];
      const ihl = (verIhl & 0x0f) * 4;
      const ttl = packetData[ipOffset + 8];
      const ipProto = packetData[ipOffset + 9];
      const ipId = (packetData[ipOffset + 4] << 8) | packetData[ipOffset + 5];
      const sourceIp = formatIpv4(packetData, ipOffset + 12);
      const destinationIp = formatIpv4(packetData, ipOffset + 16);

      const l4Offset = ipOffset + ihl;
      let protocol: Protocol = 'TCP';
      let sourcePort: number | null = null;
      let destinationPort: number | null = null;
      let info = '';
      let flags = undefined;
      let dnsQuery = undefined;
      let dnsType = undefined;
      let payloadPreview = undefined;

      const isPrivateSrc = sourceIp.startsWith('192.168.') || sourceIp.startsWith('10.') || sourceIp.startsWith('172.16.');
      const isPrivateDst = destinationIp.startsWith('192.168.') || destinationIp.startsWith('10.') || destinationIp.startsWith('172.16.');
      const direction: TrafficDirection = isPrivateSrc && !isPrivateDst ? 'OUTBOUND' : !isPrivateSrc && isPrivateDst ? 'INBOUND' : 'INTERNAL';

      // TCP
      if (ipProto === 6 && packetData.length >= l4Offset + 20) {
        protocol = 'TCP';
        sourcePort = (packetData[l4Offset] << 8) | packetData[l4Offset + 1];
        destinationPort = (packetData[l4Offset + 2] << 8) | packetData[l4Offset + 3];
        const tcpFlagsByte = packetData[l4Offset + 13];

        const isSyn = (tcpFlagsByte & 0x02) !== 0;
        const isAck = (tcpFlagsByte & 0x10) !== 0;
        const isFin = (tcpFlagsByte & 0x01) !== 0;
        const isRst = (tcpFlagsByte & 0x04) !== 0;
        const isPsh = (tcpFlagsByte & 0x08) !== 0;
        const isUrg = (tcpFlagsByte & 0x20) !== 0;

        flags = {
          syn: isSyn,
          ack: isAck,
          fin: isFin,
          rst: isRst,
          psh: isPsh,
          urg: isUrg,
        };

        const flagLabels: string[] = [];
        if (isSyn) flagLabels.push('SYN');
        if (isAck) flagLabels.push('ACK');
        if (isFin) flagLabels.push('FIN');
        if (isRst) flagLabels.push('RST');
        if (isPsh) flagLabels.push('PSH');
        if (isUrg) flagLabels.push('URG');

        if (destinationPort === 443 || sourcePort === 443) {
          protocol = 'HTTPS';
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] TLS Payload`;
        } else if (destinationPort === 80 || sourcePort === 80) {
          protocol = 'HTTP';
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] HTTP Traffic`;
        } else if (destinationPort === 22 || sourcePort === 22) {
          protocol = 'SSH';
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] SSH Encrypted Channel`;
        } else if (destinationPort === 23 || sourcePort === 23) {
          protocol = 'TELNET';
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] Unencrypted Telnet`;
        } else if (destinationPort === 21 || sourcePort === 21) {
          protocol = 'FTP';
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] FTP Control Stream`;
        } else {
          info = `${sourcePort} → ${destinationPort} [${flagLabels.join(', ')}] Len=${inclLen - l4Offset}`;
        }

        const dataOffset = ((packetData[l4Offset + 12] >> 4) & 0x0f) * 4;
        const payloadStart = l4Offset + dataOffset;
        if (packetData.length > payloadStart) {
          const payload = packetData.subarray(payloadStart);
          payloadPreview = Array.from(payload.subarray(0, 48))
            .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
            .join('');
        }
      }
      // UDP
      else if (ipProto === 17 && packetData.length >= l4Offset + 8) {
        protocol = 'UDP';
        sourcePort = (packetData[l4Offset] << 8) | packetData[l4Offset + 1];
        destinationPort = (packetData[l4Offset + 2] << 8) | packetData[l4Offset + 3];

        if (destinationPort === 53 || sourcePort === 53) {
          protocol = 'DNS';
          const payload = packetData.subarray(l4Offset + 8);
          const parsed = parseDnsQuery(payload);
          dnsQuery = parsed.query;
          dnsType = parsed.type;
          info = dnsQuery ? `Standard query ${dnsType || 'A'} ${dnsQuery}` : `DNS Message (${sourcePort} → ${destinationPort})`;
        } else {
          info = `${sourcePort} → ${destinationPort} Len=${inclLen - l4Offset}`;
        }

        const payload = packetData.subarray(l4Offset + 8);
        if (payload.length > 0) {
          payloadPreview = Array.from(payload.subarray(0, 48))
            .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
            .join('');
        }
      }
      // ICMP
      else if (ipProto === 1) {
        protocol = 'ICMP';
        const type = packetData[l4Offset];
        const code = packetData[l4Offset + 1];
        const icmpDesc =
          type === 8 ? 'Echo (ping) request' : type === 0 ? 'Echo (ping) reply' : type === 3 ? `Destination Unreachable (Code ${code})` : `ICMP Type ${type}`;
        info = icmpDesc;
      }

      packets.push({
        id: packetIndex++,
        timestamp,
        timeEpoch,
        sourceIp,
        destinationIp,
        sourcePort,
        destinationPort,
        protocol,
        length: origLen,
        info,
        direction,
        flags,
        isSuspicious: false,
        rawHex: formatHexDump(packetData),
        payloadPreview,
        ttl,
        ipId,
        macSrc,
        macDst,
        dnsQuery,
        dnsType,
      });
      continue;
    }

    // Generic or IPv6 fallback
    packets.push({
      id: packetIndex++,
      timestamp,
      timeEpoch,
      sourceIp: '0.0.0.0',
      destinationIp: '0.0.0.0',
      sourcePort: null,
      destinationPort: null,
      protocol: 'TCP',
      length: origLen,
      info: `Raw Frame #${packetIndex} (${origLen} bytes)`,
      direction: 'INTERNAL',
      isSuspicious: false,
      rawHex: formatHexDump(packetData),
    });
  }

  return packets;
}
