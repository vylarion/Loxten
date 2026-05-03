// Loxten v2 — Shared type definitions

export interface Threat {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details?: any;
  showDetails?: boolean;
  ignored?: boolean;
}

export interface HeaderCheck {
  name: string;
  status: 'pass' | 'fail';
  detail: string;
}

export interface HeaderAudit {
  checks: HeaderCheck[];
  score: number;
  total: number;
  grade: string;
}

export interface DomainAge {
  registeredDate: string;
  ageDays: number;
}

export interface SecurityData {
  isSecure: boolean;
  riskScore: number;
  threats: Threat[];
  trackersBlocked: number;
  lastScan: Date | null;
  headerAudit?: HeaderAudit | null;
  domainAge?: DomainAge | null;
}

export interface Settings {
  realTimeProtection: boolean;
  blockPhishing: boolean;
  blockTrackers: boolean;
  blockAnnoyances: boolean;
  showWarnings: boolean;
  autoScan: boolean;
  notificationLevel: 'low' | 'medium' | 'high';
}

export interface Stats {
  sitesScanned: number;
  threatsBlocked: number;
  trackersBlocked: number;
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