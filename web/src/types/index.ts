// System Status Types
export interface SystemStatus {
  status: 'running' | 'stopped' | 'degraded';
  uptime: number;
  version: string;
  lastUpdate: Date;
  healthy: boolean;
}

export interface HealthCheck {
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  timestamp: Date;
}

// SLA Types
export type SLALevel = 'Platinum' | 'Gold' | 'Silver' | 'Bronze';

export interface SLAMetric {
  id: string;
  name: string;
  type: 'Availability' | 'Latency' | 'Throughput' | 'ErrorRate' | 'Custom';
  slaLevel: SLALevel;
  targetValue: number;
  currentValue: number;
  unit: string;
  withinSLA: boolean;
  lastUpdated: Date;
}

export interface SLAViolation {
  id: string;
  metricId: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  startTime: Date;
  endTime?: Date;
  breachValue: number;
  thresholdValue: number;
  description: string;
}

// Audit Types
export type AuditLevel = 'Info' | 'Warning' | 'Error' | 'Critical';
export type AuditCategory = 'Authentication' | 'Authorization' | 'DataAccess' | 'Configuration' | 'Backup' | 'Restore' | 'UserManagement' | 'RoleManagement' | 'SystemEvent';

export interface AuditEvent {
  id: string;
  timestamp: Date;
  level: AuditLevel;
  category: AuditCategory;
  actor: string;
  action: string;
  resource: string;
  status: 'success' | 'failure';
  sourceIP?: string;
  details: Record<string, string>;
}

// Scan Types
export interface Scan {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  target: string;
  startTime: Date;
  endTime?: Date;
  vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  scanId: string;
  vulnerability: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss: number;
  description: string;
  remediation: string;
  status: 'open' | 'fixed' | 'in_progress';
}

// Backup Types
export type BackupType = 'Full' | 'Incremental' | 'Differential';
export type BackupStatus = 'Pending' | 'Running' | 'Completed' | 'Failed';

export interface BackupJob {
  id: string;
  name: string;
  type: BackupType;
  status: BackupStatus;
  startTime: Date;
  endTime?: Date;
  dataSize: number;
  compressedSize: number;
  compressionRatio: number;
  location: string;
  retentionDays: number;
  checksum: string;
}

export interface BackupSchedule {
  id: string;
  name: string;
  type: BackupType;
  frequency: 'hourly' | 'daily' | 'weekly' | 'monthly';
  retentionDays: number;
  active: boolean;
  lastBackup?: Date;
  nextBackup?: Date;
}

// Deployment Types
export interface Deployment {
  id: string;
  environment: 'dev' | 'staging' | 'production';
  status: 'healthy' | 'degraded' | 'failed';
  version: string;
  replicas: number;
  readyReplicas: number;
  desiredReplicas: number;
  deployTime: Date;
  lastUpdate: Date;
  image: string;
}

export interface DeploymentMetrics {
  cpu: number;
  memory: number;
  network: number;
  latency: number;
  errorRate: number;
  uptime: number;
}

// RBAC Types
export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  createdAt: Date;
  updatedAt: Date;
}

export type Permission =
  | 'Read' | 'Write' | 'Delete' | 'Execute' | 'Admin'
  | 'Audit' | 'UserManagement' | 'RoleManagement'
  | 'BackupRestore' | 'DisasterRecovery' | string;

export interface User {
  id: string;
  username: string;
  email: string;
  roles: Role[];
  active: boolean;
  lastLogin?: Date;
  createdAt: Date;
}

// Disaster Recovery Types
export type DRStrategy = 'RPO' | 'RTO' | 'Combined';

export interface DRPlan {
  id: string;
  name: string;
  strategy: DRStrategy;
  rtoMinutes: number;
  rpoMinutes: number;
  criticalSystems: string[];
  lastTested?: Date;
  createdAt: Date;
}

export interface DRDrill {
  id: string;
  planId: string;
  status: 'Planned' | 'InProgress' | 'Completed' | 'Failed';
  startTime: Date;
  endTime?: Date;
  systemsRecovered: string[];
  issuesFound: string[];
  passed: boolean;
  actualRtoMinutes?: number;
}

export interface FailoverEvent {
  id: string;
  timestamp: Date;
  triggerReason: string;
  recoveryPointUsed: string;
  success: boolean;
  systemsAffected: string[];
  notes: string;
}

// Dashboard Types
export interface DashboardData {
  systemStatus: SystemStatus;
  healthCheck: HealthCheck;
  slaMetrics: SLAMetric[];
  recentAuditEvents: AuditEvent[];
  activeScans: Scan[];
  recentBackups: BackupJob[];
  deployments: Deployment[];
  slaViolations: SLAViolation[];
}

export interface DateRange {
  startDate: Date;
  endDate: Date;
}

export interface FilterOptions {
  dateRange?: DateRange;
  category?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}
