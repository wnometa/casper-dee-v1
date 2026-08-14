/*
# Fix recursive organization access policies

1. New Functions
- `is_org_member` checks membership without re-entering row policies.
- `is_org_owner` checks workspace ownership without re-entering row policies.
- `has_org_role` checks organization roles for protected writes.

2. Modified Security
- Replaces organization and membership policies that recursively queried each other.
- Rewrites organization-scoped policies to use fixed SECURITY DEFINER helpers with a fixed search path.
- Grants helper execution only to authenticated users and revokes it from anon.

3. Important Notes
- No application data is deleted or changed.
- The helpers derive the caller from `auth.uid()` and do not trust a caller-supplied user ID.
- This restores reads for existing workspaces and keeps tenant isolation intact.
*/

CREATE OR REPLACE FUNCTION public.is_org_member(p_organization_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
  );
$$;

CREATE OR REPLACE FUNCTION public.is_org_owner(p_organization_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.organizations
    WHERE id = p_organization_id
      AND owner_id = auth.uid()
  );
$$;

CREATE OR REPLACE FUNCTION public.has_org_role(p_organization_id uuid, p_roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND role = ANY (p_roles)
  ) OR public.is_org_owner(p_organization_id);
$$;

REVOKE ALL ON FUNCTION public.is_org_member(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_org_owner(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.has_org_role(uuid, text[]) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_org_member(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_org_owner(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.has_org_role(uuid, text[]) TO authenticated;

DROP POLICY IF EXISTS "members read organizations" ON organizations;
CREATE POLICY "members read organizations" ON organizations FOR SELECT TO authenticated
  USING (owner_id = auth.uid() OR public.is_org_member(id));

DROP POLICY IF EXISTS "members read membership" ON organization_members;
CREATE POLICY "members read membership" ON organization_members FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_org_owner(organization_id));

DROP POLICY IF EXISTS "owners add membership" ON organization_members;
CREATE POLICY "owners add membership" ON organization_members FOR INSERT TO authenticated
  WITH CHECK (public.is_org_owner(organization_id));

DROP POLICY IF EXISTS "owners update membership" ON organization_members;
CREATE POLICY "owners update membership" ON organization_members FOR UPDATE TO authenticated
  USING (public.is_org_owner(organization_id))
  WITH CHECK (public.is_org_owner(organization_id));

DROP POLICY IF EXISTS "owners delete membership" ON organization_members;
CREATE POLICY "owners delete membership" ON organization_members FOR DELETE TO authenticated
  USING (public.is_org_owner(organization_id));

DROP POLICY IF EXISTS "members read assets" ON assets;
CREATE POLICY "members read assets" ON assets FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "admins insert assets" ON assets;
CREATE POLICY "admins insert assets" ON assets FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins update assets" ON assets;
CREATE POLICY "admins update assets" ON assets FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete assets" ON assets;
CREATE POLICY "admins delete assets" ON assets FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read findings" ON findings;
CREATE POLICY "members read findings" ON findings FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "analysts insert findings" ON findings;
CREATE POLICY "analysts insert findings" ON findings FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "analysts update findings" ON findings;
CREATE POLICY "analysts update findings" ON findings FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete findings" ON findings;
CREATE POLICY "admins delete findings" ON findings FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read threat scenarios" ON threat_scenarios;
CREATE POLICY "members read threat scenarios" ON threat_scenarios FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "analysts insert threat scenarios" ON threat_scenarios;
CREATE POLICY "analysts insert threat scenarios" ON threat_scenarios FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "analysts update threat scenarios" ON threat_scenarios;
CREATE POLICY "analysts update threat scenarios" ON threat_scenarios FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete threat scenarios" ON threat_scenarios;
CREATE POLICY "admins delete threat scenarios" ON threat_scenarios FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read attack paths" ON attack_paths;
CREATE POLICY "members read attack paths" ON attack_paths FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "analysts insert attack paths" ON attack_paths;
CREATE POLICY "analysts insert attack paths" ON attack_paths FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "analysts update attack paths" ON attack_paths;
CREATE POLICY "analysts update attack paths" ON attack_paths FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete attack paths" ON attack_paths;
CREATE POLICY "admins delete attack paths" ON attack_paths FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read audit logs" ON audit_logs;
CREATE POLICY "members read audit logs" ON audit_logs FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "members write audit logs" ON audit_logs;
CREATE POLICY "members write audit logs" ON audit_logs FOR INSERT TO authenticated
  WITH CHECK (actor_id = auth.uid() AND public.is_org_member(organization_id));
DROP POLICY IF EXISTS "admins update audit logs" ON audit_logs;
CREATE POLICY "admins update audit logs" ON audit_logs FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin']));
DROP POLICY IF EXISTS "admins delete audit logs" ON audit_logs;
CREATE POLICY "admins delete audit logs" ON audit_logs FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read scan targets" ON scan_targets;
CREATE POLICY "members read scan targets" ON scan_targets FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "analysts insert scan targets" ON scan_targets;
CREATE POLICY "analysts insert scan targets" ON scan_targets FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "analysts update scan targets" ON scan_targets;
CREATE POLICY "analysts update scan targets" ON scan_targets FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete scan targets" ON scan_targets;
CREATE POLICY "admins delete scan targets" ON scan_targets FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));

DROP POLICY IF EXISTS "members read scan jobs" ON scan_jobs;
CREATE POLICY "members read scan jobs" ON scan_jobs FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id));
DROP POLICY IF EXISTS "analysts insert scan jobs" ON scan_jobs;
CREATE POLICY "analysts insert scan jobs" ON scan_jobs FOR INSERT TO authenticated
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "analysts update scan jobs" ON scan_jobs;
CREATE POLICY "analysts update scan jobs" ON scan_jobs FOR UPDATE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']))
  WITH CHECK (public.has_org_role(organization_id, ARRAY['owner','admin','analyst']));
DROP POLICY IF EXISTS "admins delete scan jobs" ON scan_jobs;
CREATE POLICY "admins delete scan jobs" ON scan_jobs FOR DELETE TO authenticated
  USING (public.has_org_role(organization_id, ARRAY['owner','admin']));
