// Shared type definitions for Loxten extension

export interface Threat {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details?: any;
  showDetails?: boolean;
  ignored?: boolean;
}

export interface SecurityData {
  isSecure: boolean;
  riskScore: number;
  threats: Threat[];
  trackersBlocked: number;
  lastScan: Date | null;
}

export interface Settings {
  realTimeProtection: boolean;
  blockMaliciousSites: boolean;
  blockPhishing: boolean;
  blockTrackers: boolean;
  blockCryptominers: boolean;
  showWarnings: boolean;
  autoScan: boolean;
  notificationLevel: 'low' | 'medium' | 'high';
  scanFrequency: 'realtime' | 'periodic' | 'manual';
  whitelistMode: boolean;
}

export interface Stats {
  sitesScanned: number;
  threatsBlocked: number;
  trackersBlocked: number;
  malwareDetected: number;
  phishingBlocked: number;
}

export interface WhitelistEntry {
  domain: string;
  addedAt: number;
}

export interface BreachResult {
  email: string;
  breached: boolean;
  breachCount: number;
  lastChecked: number;
}

export interface ChromeResponse {
  riskScore?: number;
  threats?: Threat[];
  trackersBlocked?: number;
  timestamp?: number;
}

export interface ChromeStorageResult {
  loxten_settings?: Settings;
  loxten_stats?: Stats;
  loxten_whitelist?: WhitelistEntry[];
  loxten_breach?: BreachResult;
}