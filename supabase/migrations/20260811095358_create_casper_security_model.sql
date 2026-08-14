/*
# Create CASPER DEE security command center model

1. New Tables
- `organizations` stores tenant workspaces and their owner.
- `organization_members` stores role-based membership per workspace.
- `assets` stores authorized hosts, services, criticality, and exposure state.
- `findings` stores normalized vulnerability and exposure findings.
- `threat_scenarios` stores correlated Threat DNA scenarios.
- `attack_paths` stores ordered potential routes through an environment.
- `audit_logs` stores security-relevant administrative actions.

2. Security
- Row-level security is enabled on every table.
- Authenticated users can only access records for organizations where they are members.
- Organization creation is restricted to the authenticated owner, who can add the initial membership.
- Member roles are limited to owner, admin, analyst, and viewer.

3. Important Notes
- This is a non-destructive foundation migration; it creates new tables only.
- Findings and attack paths represent evidence-backed potential risk, not proof of compromise.
*/

CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  owner_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organization_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  asset_type text NOT NULL CHECK (asset_type IN ('web', 'server', 'database', 'cloud', 'endpoint', 'network')),
  hostname text,
  ip_address text,
  criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
  exposure_state text NOT NULL DEFAULT 'internal' CHECK (exposure_state IN ('internet', 'restricted', 'internal', 'unknown')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'unknown')),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id uuid REFERENCES assets(id) ON DELETE SET NULL,
  title text NOT NULL,
  description text,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted')),
  cvss_score numeric(3,1),
  is_externally_exposed boolean NOT NULL DEFAULT false,
  evidence text,
  remediation text,
  discovered_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS threat_scenarios (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title text NOT NULL,
  summary text NOT NULL,
  risk_score integer NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'mitigated', 'accepted')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_paths (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scenario_id uuid REFERENCES threat_scenarios(id) ON DELETE SET NULL,
  title text NOT NULL,
  summary text NOT NULL,
  risk_score integer NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  nodes jsonb NOT NULL DEFAULT '[]'::jsonb,
  edges jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS assets_organization_id_idx ON assets(organization_id);
CREATE INDEX IF NOT EXISTS findings_organization_id_idx ON findings(organization_id);
CREATE INDEX IF NOT EXISTS findings_status_severity_idx ON findings(status, severity);
CREATE INDEX IF NOT EXISTS threat_scenarios_organization_id_idx ON threat_scenarios(organization_id);
CREATE INDEX IF NOT EXISTS attack_paths_organization_id_idx ON attack_paths(organization_id);
CREATE INDEX IF NOT EXISTS audit_logs_organization_id_created_at_idx ON audit_logs(organization_id, created_at DESC);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_scenarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "owners create organizations" ON organizations;
CREATE POLICY "owners create organizations" ON organizations FOR INSERT TO authenticated WITH CHECK (auth.uid() = owner_id);
DROP POLICY IF EXISTS "members read organizations" ON organizations;
CREATE POLICY "members read organizations" ON organizations FOR SELECT TO authenticated USING (owner_id = auth.uid() OR EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = organizations.id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "owners update organizations" ON organizations;
CREATE POLICY "owners update organizations" ON organizations FOR UPDATE TO authenticated USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
DROP POLICY IF EXISTS "owners delete organizations" ON organizations;
CREATE POLICY "owners delete organizations" ON organizations FOR DELETE TO authenticated USING (owner_id = auth.uid());

DROP POLICY IF EXISTS "members read membership" ON organization_members;
CREATE POLICY "members read membership" ON organization_members FOR SELECT TO authenticated USING (user_id = auth.uid() OR EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_members.organization_id AND o.owner_id = auth.uid()));
DROP POLICY IF EXISTS "owners add membership" ON organization_members;
CREATE POLICY "owners add membership" ON organization_members FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_members.organization_id AND o.owner_id = auth.uid()));
DROP POLICY IF EXISTS "owners update membership" ON organization_members;
CREATE POLICY "owners update membership" ON organization_members FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_members.organization_id AND o.owner_id = auth.uid())) WITH CHECK (EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_members.organization_id AND o.owner_id = auth.uid()));
DROP POLICY IF EXISTS "owners delete membership" ON organization_members;
CREATE POLICY "owners delete membership" ON organization_members FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organizations o WHERE o.id = organization_members.organization_id AND o.owner_id = auth.uid()));

DROP POLICY IF EXISTS "members read assets" ON assets;
CREATE POLICY "members read assets" ON assets FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assets.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "admins insert assets" ON assets;
CREATE POLICY "admins insert assets" ON assets FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "admins update assets" ON assets;
CREATE POLICY "admins update assets" ON assets FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst'))) WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "admins delete assets" ON assets;
CREATE POLICY "admins delete assets" ON assets FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));

DROP POLICY IF EXISTS "members read findings" ON findings;
CREATE POLICY "members read findings" ON findings FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "analysts insert findings" ON findings;
CREATE POLICY "analysts insert findings" ON findings FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "analysts update findings" ON findings;
CREATE POLICY "analysts update findings" ON findings FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst'))) WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "admins delete findings" ON findings;
CREATE POLICY "admins delete findings" ON findings FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));

DROP POLICY IF EXISTS "members read threat scenarios" ON threat_scenarios;
CREATE POLICY "members read threat scenarios" ON threat_scenarios FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = threat_scenarios.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "analysts insert threat scenarios" ON threat_scenarios;
CREATE POLICY "analysts insert threat scenarios" ON threat_scenarios FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = threat_scenarios.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "analysts update threat scenarios" ON threat_scenarios;
CREATE POLICY "analysts update threat scenarios" ON threat_scenarios FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = threat_scenarios.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst'))) WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = threat_scenarios.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "admins delete threat scenarios" ON threat_scenarios;
CREATE POLICY "admins delete threat scenarios" ON threat_scenarios FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = threat_scenarios.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));

DROP POLICY IF EXISTS "members read attack paths" ON attack_paths;
CREATE POLICY "members read attack paths" ON attack_paths FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = attack_paths.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "analysts insert attack paths" ON attack_paths;
CREATE POLICY "analysts insert attack paths" ON attack_paths FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = attack_paths.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "analysts update attack paths" ON attack_paths;
CREATE POLICY "analysts update attack paths" ON attack_paths FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = attack_paths.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst'))) WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = attack_paths.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));
DROP POLICY IF EXISTS "admins delete attack paths" ON attack_paths;
CREATE POLICY "admins delete attack paths" ON attack_paths FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = attack_paths.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));

DROP POLICY IF EXISTS "members read audit logs" ON audit_logs;
CREATE POLICY "members read audit logs" ON audit_logs FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "members write audit logs" ON audit_logs;
CREATE POLICY "members write audit logs" ON audit_logs FOR INSERT TO authenticated WITH CHECK (actor_id = auth.uid() AND EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid()));
DROP POLICY IF EXISTS "admins update audit logs" ON audit_logs;
CREATE POLICY "admins update audit logs" ON audit_logs FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))) WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));
DROP POLICY IF EXISTS "admins delete audit logs" ON audit_logs;
CREATE POLICY "admins delete audit logs" ON audit_logs FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));
