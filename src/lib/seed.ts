import { supabase } from "./supabase";

const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

export async function seedWorkspaceForUser(userId: string, orgName: string) {
  const slug = `${slugify(orgName)}-${userId.slice(0, 6)}`;

  const { data: org, error: orgError } = await supabase
    .from("organizations")
    .insert({ name: orgName, slug, owner_id: userId })
    .select()
    .single();

  if (orgError || !org) return { error: "We couldn't create your workspace. Please try again." };

  const orgId = org.id;

  await supabase.from("organization_members").insert({
    organization_id: orgId,
    user_id: userId,
    role: "owner",
  });

  const assets = [
    { name: "api-gateway-prod", asset_type: "web", hostname: "api.casperdee.io", ip_address: "44.231.10.2", criticality: "critical", exposure_state: "internet", status: "active" },
    { name: "billing-service", asset_type: "server", hostname: "billing.internal", ip_address: "10.0.4.12", criticality: "high", exposure_state: "restricted", status: "active" },
    { name: "customer-db-primary", asset_type: "database", hostname: "pg-primary.internal", ip_address: "10.0.8.5", criticality: "critical", exposure_state: "internal", status: "active" },
    { name: "bastion-host", asset_type: "server", hostname: "bastion.casperdee.io", ip_address: "44.231.10.9", criticality: "high", exposure_state: "internet", status: "active" },
    { name: "object-store-backups", asset_type: "cloud", hostname: "s3://casperdee-backups", criticality: "high", exposure_state: "restricted", status: "active" },
    { name: "employee-laptop-fleet", asset_type: "endpoint", hostname: null, ip_address: null, criticality: "medium", exposure_state: "unknown", status: "active" },
    { name: "vpn-concentrator", asset_type: "network", hostname: "vpn.casperdee.io", ip_address: "44.231.10.4", criticality: "high", exposure_state: "internet", status: "active" },
    { name: "ci-runner-pool", asset_type: "server", hostname: "runner.internal", ip_address: "10.0.6.20", criticality: "medium", exposure_state: "internal", status: "active" },
  ] as const;

  const { data: insertedAssets } = await supabase
    .from("assets")
    .insert(assets.map((a) => ({ ...a, organization_id: orgId })))
    .select("id,name");

  const assetMap = new Map((insertedAssets ?? []).map((a) => [a.name, a.id]));
  const byName = (n: string) => assetMap.get(n) ?? null;

  const findings = [
    {
      asset_id: byName("api-gateway-prod"),
      title: "TLS 1.0 enabled on public endpoint",
      description: "The API gateway accepts TLS 1.0 connections, exposing users to downgrade attacks.",
      severity: "high", status: "open", cvss_score: 7.4, is_externally_exposed: true,
      evidence: "Nmap ssl-enum-ciphers scan on 44.231.10.2:443",
      remediation: "Restrict minimum TLS version to 1.2 and disable legacy cipher suites.",
    },
    {
      asset_id: byName("bastion-host"),
      title: "SSH exposed to internet with password auth",
      description: "Bastion host accepts password-based SSH from any source IP.",
      severity: "critical", status: "open", cvss_score: 9.1, is_externally_exposed: true,
      evidence: "Shodan record + authenticated config review",
      remediation: "Enforce key-based auth and restrict source IPs to corporate CIDR.",
    },
    {
      asset_id: byName("customer-db-primary"),
      title: "Postgres instance missing security patches",
      description: "Database engine is 4 minor versions behind current release.",
      severity: "high", status: "in_progress", cvss_score: 7.8, is_externally_exposed: false,
      evidence: "Version banner returned on internal port scan",
      remediation: "Apply latest minor release in the next maintenance window.",
    },
    {
      asset_id: byName("billing-service"),
      title: "Overly permissive IAM role on billing service",
      description: "Service role grants s3:* across all buckets, not just the billing bucket.",
      severity: "medium", status: "open", cvss_score: 5.3, is_externally_exposed: false,
      evidence: "IAM policy export review",
      remediation: "Scope policy to the billing bucket ARN only.",
    },
    {
      asset_id: byName("vpn-concentrator"),
      title: "Outdated VPN client firmware",
      description: "Remote access clients on a vulnerable firmware branch.",
      severity: "medium", status: "accepted", cvss_score: 4.2, is_externally_exposed: true,
      evidence: "Endpoint agent inventory",
      remediation: "Scheduled firmware rollout in Q3.",
    },
    {
      asset_id: byName("object-store-backups"),
      title: "Backup bucket allows public read on one prefix",
      description: "A misconfigured prefix exposes archived logs to unauthenticated reads.",
      severity: "critical", status: "open", cvss_score: 9.0, is_externally_exposed: true,
      evidence: "Public bucket scanner alert",
      remediation: "Block all public access and audit ACLs.",
    },
    {
      asset_id: byName("ci-runner-pool"),
      title: "CI runners run long-lived tokens",
      description: "Deploy tokens in CI config do not rotate.",
      severity: "low", status: "open", cvss_score: 3.1, is_externally_exposed: false,
      evidence: "CI config audit",
      remediation: "Move to short-lived OIDC tokens.",
    },
    {
      asset_id: byName("employee-laptop-fleet"),
      title: "Disk encryption not enforced on 12 endpoints",
      description: "MDM reports 12 laptops without FileVault active.",
      severity: "medium", status: "in_progress", cvss_score: 5.1, is_externally_exposed: false,
      evidence: "MDM compliance dashboard",
      remediation: "Push enforcement profile and notify users.",
    },
  ];

  await supabase.from("findings").insert(findings.map((f) => ({ ...f, organization_id: orgId })));

  const scenarios = [
    {
      title: "External actor pivots from bastion to customer database",
      summary: "An internet-exposed bastion with weak SSH auth gives an initial foothold. From there, the actor can reach the internal database segment using stolen credentials or lateral movement tools.",
      risk_score: 88, status: "active",
    },
    {
      title: "Public backup bucket leaks customer archives",
      summary: "A misconfigured backup bucket exposes archived customer data to the public internet, bypassing application-layer controls entirely.",
      risk_score: 81, status: "active",
    },
    {
      title: "CI token theft enables supply-chain compromise",
      summary: "Long-lived deploy tokens in CI runners, if stolen, allow an attacker to push malicious builds into production without review.",
      risk_score: 54, status: "active",
    },
  ];

  const { data: insertedScenarios } = await supabase
    .from("threat_scenarios")
    .insert(scenarios.map((s) => ({ ...s, organization_id: orgId })))
    .select("id,title");

  const scenarioMap = new Map((insertedScenarios ?? []).map((s) => [s.title, s.id]));
  const scenarioId = scenarioMap.get("External actor pivots from bastion to customer database") ?? null;

  const attackPaths = [
    {
      scenario_id: scenarioId,
      title: "Bastion SSH → internal DB",
      summary: "Compromise the internet-facing bastion via password SSH, then pivot to the customer database over the internal network.",
      risk_score: 88,
      nodes: [
        { id: "n1", label: "Internet", type: "entry" },
        { id: "n2", label: "Bastion host (password SSH)", type: "pivot", detail: "44.231.10.9:22 — password auth enabled" },
        { id: "n3", label: "Internal network", type: "pivot", detail: "10.0.0.0/16 reachable" },
        { id: "n4", label: "Customer DB", type: "objective", detail: "pg-primary.internal:5432" },
      ],
      edges: [
        { from: "n1", to: "n2", label: "brute force" },
        { from: "n2", to: "n3", label: "tunnel" },
        { from: "n3", to: "n4", label: "stolen creds" },
      ],
    },
    {
      scenario_id: null,
      title: "Public S3 prefix → data exfiltration",
      summary: "A public-read prefix on the backup bucket allows unauthenticated download of archived customer records.",
      risk_score: 81,
      nodes: [
        { id: "n1", label: "Public internet", type: "entry" },
        { id: "n2", label: "Backup bucket prefix", type: "pivot", detail: "s3://casperdee-backups/archive/" },
        { id: "n3", label: "Customer PII archive", type: "objective", detail: "Unauthenticated GET" },
      ],
      edges: [
        { from: "n1", to: "n2", label: "list" },
        { from: "n2", to: "n3", label: "download" },
      ],
    },
  ];

  await supabase.from("attack_paths").insert(attackPaths.map((p) => ({ ...p, organization_id: orgId })));

  const scanTargets = [
    { name: "API Gateway", target_value: "api.casperdee.io", target_type: "host", authorization_document: "SOW-2024-014, signed 2024-03-01", status: "authorized" },
    { name: "Bastion Host", target_value: "44.231.10.9", target_type: "host", authorization_document: "SOW-2024-014, signed 2024-03-01", status: "authorized" },
    { name: "Internal Network", target_value: "10.0.0.0/16", target_type: "cidr", authorization_document: "Internal assessment policy, approved 2024-01-15", status: "authorized" },
    { name: "VPN Endpoint", target_value: "https://vpn.casperdee.io", target_type: "url", authorization_document: null, status: "pending" },
  ] as const;

  const { data: insertedTargets } = await supabase
    .from("scan_targets")
    .insert(scanTargets.map((t) => ({ ...t, organization_id: orgId })))
    .select("id,name");

  const targetMap = new Map((insertedTargets ?? []).map((t) => [t.name, t.id]));
  const apiTargetId = targetMap.get("API Gateway") ?? null;
  const bastionTargetId = targetMap.get("Bastion Host") ?? null;

  if (apiTargetId) {
    await supabase.from("scan_jobs").insert({
      organization_id: orgId,
      target_id: apiTargetId,
      status: "completed",
      findings_count: 3,
      started_at: new Date(Date.now() - 86400000).toISOString(),
      completed_at: new Date(Date.now() - 86000000).toISOString(),
      summary: "Assessment of api.casperdee.io completed. TLS 1.0 acceptance detected. 2 medium-severity cipher findings logged.",
    });
  }
  if (bastionTargetId) {
    await supabase.from("scan_jobs").insert({
      organization_id: orgId,
      target_id: bastionTargetId,
      status: "completed",
      findings_count: 1,
      started_at: new Date(Date.now() - 172800000).toISOString(),
      completed_at: new Date(Date.now() - 172000000).toISOString(),
      summary: "Assessment of bastion host 44.231.10.9 completed. Password-based SSH authentication detected — critical exposure.",
    });
  }

  await supabase.from("audit_logs").insert({
    organization_id: orgId,
    actor_id: userId,
    action: "workspace.created",
    resource_type: "organization",
    resource_id: orgId,
    metadata: { name: orgName },
  });

  return { error: null };
}
