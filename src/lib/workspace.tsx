import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { supabase } from "./supabase";
import { useAuth } from "./auth";
import type { Organization, OrganizationMember, Role } from "./types";

interface WorkspaceContextValue {
  organization: Organization | null;
  members: OrganizationMember[];
  role: Role | null;
  loading: boolean;
  refresh: () => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextValue | undefined>(undefined);

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    if (!user) {
      setOrganization(null);
      setMembers([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    const { data: orgData } = await supabase
      .from("organizations")
      .select("*")
      .eq("owner_id", user.id)
      .maybeSingle();

    let org = orgData as Organization | null;

    if (!org) {
      const { data: memberLink } = await supabase
        .from("organization_members")
        .select("organization_id")
        .eq("user_id", user.id)
        .maybeSingle();

      if (memberLink) {
        const { data: linkedOrg } = await supabase
          .from("organizations")
          .select("*")
          .eq("id", memberLink.organization_id)
          .maybeSingle();
        org = linkedOrg as Organization | null;
      }
    }

    if (org) {
      const { data: memberData } = await supabase
        .from("organization_members")
        .select("*")
        .eq("organization_id", org.id);
      setMembers((memberData as OrganizationMember[]) ?? []);
    } else {
      setMembers([]);
    }

    setOrganization(org);
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, [user]);

  const role = members.find((m) => m.user_id === user?.id)?.role ?? (organization?.owner_id === user?.id ? "owner" : null);

  return (
    <WorkspaceContext.Provider value={{ organization, members, role, loading, refresh: load }}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error("useWorkspace must be used within WorkspaceProvider");
  return ctx;
}
