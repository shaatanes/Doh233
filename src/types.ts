/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface User {
  id: string;
  uuid: string;
  apiToken: string;
  username: string;
  displayName: string;
  description: string;
  createdDate: string;
  expireDate: string;
  trafficLimit: number; // in bytes (0 means unlimited if unlimitedTraffic is true)
  consumedTraffic: number; // in bytes
  unlimitedTraffic: boolean;
  unlimitedTime: boolean;
  status: 'active' | 'suspended' | 'disabled';
  allowedUpstreams: string[]; // List of upstream IDs
  allowedDomains: string[]; // List of glob or regex patterns
  maxRpm: number;
  maxConcurrent: number;
  lastLogin: string;
  lastRequest: string;
  country: string;
  notes: string;
}

export interface Upstream {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  priority: number;
  timeout: number; // ms
  retries: number;
  weight: number;
  healthStatus: 'healthy' | 'unhealthy' | 'unknown';
}

export interface DnsLog {
  id: string;
  timestamp: string;
  userId: string;
  username: string;
  clientIp: string;
  country: string;
  domain: string;
  type: string;
  reqSize: number;
  resSize: number;
  duration: number; // ms
  status: number; // HTTP status code
  upstream: string;
  cacheHit: boolean;
}

export interface AuthLog {
  id: string;
  timestamp: string;
  username: string;
  clientIp: string;
  action: string;
  status: 'success' | 'failed' | 'blocked';
  reason?: string;
}

export interface SystemConfig {
  defaultUpstream: string;
  fallbackUpstream: string;
  allowedMethods: string[]; // e.g. ["GET", "POST"]
  cacheTtl: number; // seconds
  cacheEnabled: boolean;
  maxCacheSize: number; // entries
  rateLimitPerIp: number; // rpm
  rateLimitPerUser: number; // rpm
  loggingEnabled: boolean;
  adminPasswordHash: string;
}
