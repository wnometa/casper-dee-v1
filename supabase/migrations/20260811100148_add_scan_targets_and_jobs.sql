/*
# Add authorized scan targets and scan jobs

1. New Tables
- `scan_targets` stores authorized in-scope assets for assessment, per organization.
  - `id` (uuid, primary key)
  - `organization_id` (uuid, FK to organizations)
  - `name` (text) human label for the target
  - `target_value` (text) the host/IP/CIDR being assessed
  - `target_type` (text) host | cidr | url | range
  - `authorization_document` (text) reference to proof of authorization
  - `status` (text) pending | authorized | revoked
  - `created_at` (timestamptz)
- `scan_jobs` stores persistent records of each scan execution.
  - `id` (uuid, primary key)
  - `organization_id` (uuid, FK to organizations)
  - `target_id` (uuid, FK to scan_targets, SET NULL on delete)
  - `status` (text) queued | running | completed | failed
  - `findings_count` (int) number of findings produced
  - `started_at` (timestamptz)
  - `completed_at` (timestamptz)
  - `summary` (text) human-readable result summary
  - `created_at` (timestamptz)

2. Security
- RLS enabled on both tables.
- Members can read scan targets and jobs for their organization.
- Analysts+ can create/update scan targets; admins can delete.
- Analysts+ can create scan jobs; admins can delete.

3. Important Notes
- Non-destructive: only adds new tables.
- Scan jobs persist across requests so results survive instance restarts.
*/

CREATE TABLE IF NOT EXISTS scan_targets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  target_value text NOT NULL,
  target_type text NOT NULL DEFAULT 'host' CHECK (target_type IN ('host','cidr','url','range')),
  authorization_document text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','authorized','revoked')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_id uuid REFERENCES scan_targets(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
  findings_count integer NOT NULL DEFAULT 0,
  started_at timestamptz,
  completed_at timestamptz,
  summary text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_targets_organization_id_idx ON scan_targets(organization_id);
CREATE INDEX IF NOT EXISTS scan_jobs_organization_id_idx ON scan_jobs(organization_id);

ALTER TABLE scan_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "members read scan targets" ON scan_targets;
CREATE POLICY "members read scan targets" ON scan_targets FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_targets.organization_id AND m.user_id = auth.uid()));

DROP POLICY IF EXISTS "analysts insert scan targets" ON scan_targets;
CREATE POLICY "analysts insert scan targets" ON scan_targets FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_targets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));

DROP POLICY IF EXISTS "analysts update scan targets" ON scan_targets;
CREATE POLICY "analysts update scan targets" ON scan_targets FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_targets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')))
  WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_targets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));

DROP POLICY IF EXISTS "admins delete scan targets" ON scan_targets;
CREATE POLICY "admins delete scan targets" ON scan_targets FOR DELETE TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_targets.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));

DROP POLICY IF EXISTS "members read scan jobs" ON scan_jobs;
CREATE POLICY "members read scan jobs" ON scan_jobs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_jobs.organization_id AND m.user_id = auth.uid()));

DROP POLICY IF EXISTS "analysts insert scan jobs" ON scan_jobs;
CREATE POLICY "analysts insert scan jobs" ON scan_jobs FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_jobs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));

DROP POLICY IF EXISTS "analysts update scan jobs" ON scan_jobs;
CREATE POLICY "analysts update scan jobs" ON scan_jobs FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_jobs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')))
  WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_jobs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','analyst')));

DROP POLICY IF EXISTS "admins delete scan jobs" ON scan_jobs;
CREATE POLICY "admins delete scan jobs" ON scan_jobs FOR DELETE TO authenticated
  USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = scan_jobs.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin')));
