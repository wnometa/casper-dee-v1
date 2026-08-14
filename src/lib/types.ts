export type Role = "owner" | "admin" | "analyst" | "viewer";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingStatus = "open" | "in_progress" | "resolved" | "accepted";

export type AssetType = "web" | "server" | "database" | "cloud" | "endpoint" | "network";
export type Criticality = "critical" | "high" | "medium" | "low";
export type ExposureState = "internet" | "restricted" | "internal" | "unknown";
export type AssetStatus = "active" | "inactive" | "unknown";

export type ScenarioStatus = "active" | "mitigated" | "accepted";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  created_at: string;
}

export interface OrganizationMember {
  id: string;
  organization_id: string;
  user_id: string;
  role: Role;
  created_at: string;
}

export interface Asset {
  id: string;
  organization_id: string;
  name: string;
  asset_type: AssetType;
  hostname: string | null;
  ip_address: string | null;
  criticality: Criticality;
  exposure_state: ExposureState;
  status: AssetStatus;
  last_seen_at: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  organization_id: string;
  asset_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  status: FindingStatus;
  cvss_score: number | null;
  is_externally_exposed: boolean;
  evidence: string | null;
  remediation: string | null;
  scan_job_id: string | null;
  discovered_at: string;
  resolved_at: string | null;
  asset?: Pick<Asset, "id" | "name" | "hostname">;
}

export interface ThreatScenario {
  id: string;
  organization_id: string;
  title: string;
  summary: string;
  risk_score: number;
  status: ScenarioStatus;
  created_at: string;
}

export interface AttackPathNode {
  id: string;
  label: string;
  type: "entry" | "pivot" | "asset" | "objective";
  detail?: string;
}

export interface AttackPathEdge {
  from: string;
  to: string;
  label?: string;
}

export interface AttackPath {
  id: string;
  organization_id: string;
  scenario_id: string | null;
  title: string;
  summary: string;
  risk_score: number;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  created_at: string;
}

export type TargetType = "host" | "cidr" | "url" | "range";
export type TargetStatus = "pending" | "authorized" | "revoked";
export type ScanJobStatus = "queued" | "running" | "completed" | "failed";

export interface ScanTarget {
  id: string;
  organization_id: string;
  name: string;
  target_value: string;
  target_type: TargetType;
  authorization_document: string | null;
  status: TargetStatus;
  created_at: string;
}

export interface ScanJob {
  id: string;
  organization_id: string;
  target_id: string | null;
  status: ScanJobStatus;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  summary: string | null;
  created_at: string;
  target?: Pick<ScanTarget, "id" | "name" | "target_value">;
}

export interface AuditLog {
  id: string;
  organization_id: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}
