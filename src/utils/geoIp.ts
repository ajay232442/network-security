import { GeoLocation } from '../types/network';

// Local sensor location (default monitoring tap)
export const SENSOR_LOCATION: GeoLocation = {
  ip: '192.168.1.145',
  country: 'Internal Sensor Network',
  countryCode: 'US',
  flag: '🛡️',
  city: 'Silicon Valley Gateway (eth0)',
  latitude: 37.7749,
  longitude: -122.4194,
  asn: 'AS-LOCAL',
  org: 'Enterprise Edge SOC Tap',
  isPrivate: true,
};

// Known threat actors and major internet cloud infrastructure
const KNOWN_GEO_LOOKUP: Record<string, Partial<GeoLocation>> = {
  // Google / YouTube
  '142.250.190.46': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'Mountain View, CA',
    latitude: 37.422,
    longitude: -122.0841,
    asn: 'AS15169',
    org: 'Google LLC Cloud Edge',
  },
  '8.8.8.8': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'Ashburn, VA',
    latitude: 39.0438,
    longitude: -77.4874,
    asn: 'AS15169',
    org: 'Google Public DNS',
  },
  '216.239.35.0': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'Council Bluffs, IA',
    latitude: 41.2619,
    longitude: -95.8608,
    asn: 'AS15169',
    org: 'Google Network Time Protocol',
  },
  // GitHub / Microsoft
  '140.82.121.6': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'San Francisco, CA',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS36459',
    org: 'GitHub, Inc. (Microsoft)',
  },
  '140.82.121.3': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'San Francisco, CA',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS36459',
    org: 'GitHub Production',
  },
  '13.107.42.14': {
    country: 'Ireland',
    countryCode: 'IE',
    flag: '🇮🇪',
    city: 'Dublin',
    latitude: 53.3498,
    longitude: -6.2603,
    asn: 'AS8075',
    org: 'Microsoft 365 European Cloud',
  },
  // Cloudflare
  '104.16.132.229': {
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    city: 'San Jose, CA',
    latitude: 37.3382,
    longitude: -121.8863,
    asn: 'AS13335',
    org: 'Cloudflare Edge Anycast',
  },
  '1.1.1.1': {
    country: 'Australia',
    countryCode: 'AU',
    flag: '🇦🇺',
    city: 'Sydney',
    latitude: -33.8688,
    longitude: 151.2093,
    asn: 'AS13335',
    org: 'APNIC / Cloudflare DNS',
  },
  // Fastly
  '151.101.1.140': {
    country: 'Germany',
    countryCode: 'DE',
    flag: '🇩🇪',
    city: 'Frankfurt',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS54113',
    org: 'Fastly European Edge CDN',
  },
  // Adversary & Threat Actor Nodes
  '198.51.100.44': {
    country: 'Russia',
    countryCode: 'RU',
    flag: '🇷🇺',
    city: 'St. Petersburg',
    latitude: 59.9343,
    longitude: 30.3351,
    asn: 'AS48287',
    org: 'Adversary Reconnaissance / Port Scanner',
  },
  '203.0.113.195': {
    country: 'China',
    countryCode: 'CN',
    flag: '🇨🇳',
    city: 'Shanghai',
    latitude: 31.2304,
    longitude: 121.4737,
    asn: 'AS4134',
    org: 'ChinaNet Automated SSH Prober',
  },
  '45.33.32.156': {
    country: 'United Kingdom',
    countryCode: 'GB',
    flag: '🇬🇧',
    city: 'London',
    latitude: 51.5074,
    longitude: -0.1278,
    asn: 'AS63949',
    org: 'SYN Flood Botnet Agent (Akamai/Linode)',
  },
  '185.220.101.5': {
    country: 'Netherlands',
    countryCode: 'NL',
    flag: '🇳🇱',
    city: 'Amsterdam',
    latitude: 52.3676,
    longitude: 4.9041,
    asn: 'AS208248',
    org: 'Zwiebelfreunde Tor Exit Node',
  },
  '194.26.29.112': {
    country: 'Bulgaria',
    countryCode: 'BG',
    flag: '🇧🇬',
    city: 'Sofia',
    latitude: 42.6977,
    longitude: 23.3219,
    asn: 'AS49981',
    org: 'Bulletproof SYN Flood Node',
  },
  '91.240.118.172': {
    country: 'Romania',
    countryCode: 'RO',
    flag: '🇷🇴',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS57169',
    org: 'Suspicious Relay / C2 Proxy',
  },
};

// Global pool of international data centers & hubs for deterministic resolution of any IP
const INTERNATIONAL_HUBS = [
  { city: 'Tokyo', country: 'Japan', countryCode: 'JP', flag: '🇯🇵', lat: 35.6762, lon: 139.6503, asn: 'AS2516 KDDI Telehouse' },
  { city: 'Seoul', country: 'South Korea', countryCode: 'KR', flag: '🇰🇷', lat: 37.5665, lon: 126.978, asn: 'AS4766 Korea Telecom' },
  { city: 'Singapore', country: 'Singapore', countryCode: 'SG', flag: '🇸🇬', lat: 1.3521, lon: 103.8198, asn: 'AS4657 StarHub Global' },
  { city: 'Mumbai', country: 'India', countryCode: 'IN', flag: '🇮🇳', lat: 19.076, lon: 72.8777, asn: 'AS4755 Tata Communications' },
  { city: 'London', country: 'United Kingdom', countryCode: 'GB', flag: '🇬🇧', lat: 51.5074, lon: -0.1278, asn: 'AS2856 British Telecom' },
  { city: 'Frankfurt', country: 'Germany', countryCode: 'DE', flag: '🇩🇪', lat: 50.1109, lon: 8.6821, asn: 'AS3320 Deutsche Telekom' },
  { city: 'Paris', country: 'France', countryCode: 'FR', flag: '🇫🇷', lat: 48.8566, lon: 2.3522, asn: 'AS5511 Orange S.A.' },
  { city: 'Amsterdam', country: 'Netherlands', countryCode: 'NL', flag: '🇳🇱', lat: 52.3676, lon: 4.9041, asn: 'AS1103 SURFnet' },
  { city: 'Stockholm', country: 'Sweden', countryCode: 'SE', flag: '🇸🇪', lat: 59.3293, lon: 18.0686, asn: 'AS1257 Tele2 Sweden' },
  { city: 'Zurich', country: 'Switzerland', countryCode: 'CH', flag: '🇨🇭', lat: 47.3769, lon: 8.5417, asn: 'AS3303 Swisscom' },
  { city: 'Toronto', country: 'Canada', countryCode: 'CA', flag: '🇨🇦', lat: 43.6532, lon: -79.3832, asn: 'AS852 Rogers Telecom' },
  { city: 'São Paulo', country: 'Brazil', countryCode: 'BR', flag: '🇧🇷', lat: -23.5505, lon: -46.6333, asn: 'AS28573 Claro Brasil' },
  { city: 'Sydney', country: 'Australia', countryCode: 'AU', flag: '🇦🇺', lat: -33.8688, lon: 151.2093, asn: 'AS1221 Telstra' },
  { city: 'Johannesburg', country: 'South Africa', countryCode: 'ZA', flag: '🇿🇦', lat: -26.2041, lon: 28.0473, asn: 'AS16637 MTN Group' },
  { city: 'Dubai', country: 'United Arab Emirates', countryCode: 'AE', flag: '🇦🇪', lat: 25.2048, lon: 55.2708, asn: 'AS5384 Emirates Telecom' },
  { city: 'Taipei', country: 'Taiwan', countryCode: 'TW', flag: '🇹🇼', lat: 25.033, lon: 121.5654, asn: 'AS3462 Chunghwa Telecom' },
  { city: 'Warsaw', country: 'Poland', countryCode: 'PL', flag: '🇵🇱', lat: 52.2297, lon: 21.0122, asn: 'AS5617 Orange Polska' },
  { city: 'Madrid', country: 'Spain', countryCode: 'ES', flag: '🇪🇸', lat: 40.4168, lon: -3.7038, asn: 'AS3352 Telefonica' },
  { city: 'Helsinki', country: 'Finland', countryCode: 'FI', flag: '🇫🇮', lat: 60.1699, lon: 24.9384, asn: 'AS719 Elisa Oyj' },
  { city: 'Rome', country: 'Italy', countryCode: 'IT', flag: '🇮🇹', lat: 41.9028, lon: 12.4964, asn: 'AS3269 TIM Telecom Italia' },
  { city: 'Hong Kong', country: 'Hong Kong', countryCode: 'HK', flag: '🇭🇰', lat: 22.3193, lon: 114.1694, asn: 'AS9304 HGC Global' },
  { city: 'Buenos Aires', country: 'Argentina', countryCode: 'AR', flag: '🇦🇷', lat: -34.6037, lon: -58.3816, asn: 'AS7303 Telecom Argentina' },
];

export function isPrivateIp(ip: string): boolean {
  if (!ip || ip === '0.0.0.0') return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true;

  // 172.16.0.0 – 172.31.255.255
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }

  return false;
}

/**
 * Resolves any IP address to geographical metadata and coordinates.
 */
export function resolveGeoIp(ip: string): GeoLocation {
  if (isPrivateIp(ip)) {
    return {
      ...SENSOR_LOCATION,
      ip,
    };
  }

  // Exact known table match
  if (KNOWN_GEO_LOOKUP[ip]) {
    const entry = KNOWN_GEO_LOOKUP[ip];
    return {
      ip,
      country: entry.country || 'Unknown Country',
      countryCode: entry.countryCode || 'XX',
      flag: entry.flag || '🌐',
      city: entry.city || 'Internet Node',
      latitude: entry.latitude || 0,
      longitude: entry.longitude || 0,
      asn: entry.asn || 'AS-UNKNOWN',
      org: entry.org || 'Internet Service Provider',
      isPrivate: false,
    };
  }

  // Deterministic hash distribution for any other arbitrary external IP (e.g. from user uploaded PCAPs)
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = (hash << 5) - hash + ip.charCodeAt(i);
    hash |= 0;
  }
  const hub = INTERNATIONAL_HUBS[Math.abs(hash) % INTERNATIONAL_HUBS.length];

  // Slight jitter to prevent overlapping exact dots
  const jitterLat = (((Math.abs(hash * 7) % 100) - 50) / 100) * 1.5;
  const jitterLon = (((Math.abs(hash * 13) % 100) - 50) / 100) * 1.5;

  return {
    ip,
    country: hub.country,
    countryCode: hub.countryCode,
    flag: hub.flag,
    city: hub.city,
    latitude: hub.lat + jitterLat,
    longitude: hub.lon + jitterLon,
    asn: hub.asn,
    org: `${hub.city} Regional Gateway`,
    isPrivate: false,
  };
}

/**
 * Projects latitude (-90 to 90) and longitude (-180 to 180) to 2D SVG canvas (x, y) coordinates
 * Using an Equirectangular / Plate Carrée projection with padding.
 */
export function projectGeoToSvg(
  lat: number,
  lon: number,
  width: number,
  height: number
): { x: number; y: number } {
  // Longitude: -180 to 180 maps to 0 to width
  const x = ((lon + 180) / 360) * width;

  // Latitude: 90 to -90 maps to 0 to height (inverted for SVG y-axis)
  // Clamp latitude to [-80, 84] to prevent polar distortion
  const clampedLat = Math.max(-80, Math.min(84, lat));
  const y = ((90 - clampedLat) / 180) * height;

  return {
    x: Math.round(x * 10) / 10,
    y: Math.round(y * 10) / 10,
  };
}
