import { useAuth } from "../lib/auth";
import { useWorkspace } from "../lib/workspace";
import {
  LayoutDashboard, ShieldAlert, Server, Crosshair, Route, ScrollText,
  LogOut, Radar, Sparkles, Zap, Wrench, FileText, ShieldCheck,
  Building2, Users, Plug, Settings,
} from "lucide-react";

export type View =
  | "overview" | "assets" | "exposure"
  | "threats" | "findings" | "scans" | "incidents"
  | "remediation" | "reports"
  | "casper-ai"
  | "compliance" | "audit"
  | "organization" | "team" | "integrations" | "settings";

interface SidebarProps {
  view: View;
  onNavigate: (v: View) => void;
  counts: { findings: number; scenarios: number };
}

interface NavSection {
  label: string;
  items: { id: View; label: string; icon: typeof LayoutDashboard }[];
}

const navSections: NavSection[] = [
  {
    label: "Command Center",
    items: [{ id: "overview", label: "Overview", icon: LayoutDashboard }],
  },
  {
    label: "Discover",
    items: [{ id: "assets", label: "Assets", icon: Server }],
  },
  {
    label: "Detect",
    items: [
      { id: "threats", label: "Threat DNA", icon: Crosshair },
      { id: "findings", label: "Vulnerabilities", icon: ShieldAlert },
      { id: "scans", label: "Scans", icon: Radar },
    ],
  },
  {
    label: "Respond",
    items: [
      { id: "incidents", label: "Incidents", icon: Zap },
      { id: "remediation", label: "Remediation", icon: Wrench },
      { id: "reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Intelligence",
    items: [{ id: "casper-ai", label: "CASPER AI", icon: Sparkles }],
  },
  {
    label: "Governance",
    items: [
      { id: "compliance", label: "Compliance", icon: ShieldCheck },
      { id: "audit", label: "Audit Log", icon: ScrollText },
    ],
  },
  {
    label: "Admin",
    items: [
      { id: "organization", label: "Organization", icon: Building2 },
      { id: "team", label: "Team & Access", icon: Users },
      { id: "integrations", label: "Integrations", icon: Plug },
      { id: "settings", label: "Settings", icon: Settings },
    ],
  },
];

export function Sidebar({ view, onNavigate, counts }: SidebarProps) {
  const { user, signOut } = useAuth();
  const { organization, role } = useWorkspace();
  const email = user?.email ?? "";
  const initials = email.slice(0, 2).toUpperCase();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div>
          <div className="sidebar-brand-name">CASPER DEE</div>
          <div className="sidebar-brand-sub">Assess. Detect. Protect. Respond.</div>
        </div>
      </div>

      <div className="nav-section-label">Workspace</div>
      <div style={{ padding: "0 10px 8px", fontSize: 12, color: "var(--text-1)", fontWeight: 500 }}>
        {organization?.name ?? "—"}
      </div>

      {navSections.map((section) => (
        <div key={section.label} className="nav-section">
          <div className="nav-section-label">{section.label}</div>
          {section.items.map((item) => {
            const Icon = item.icon;
            const badge = item.id === "findings" ? counts.findings : item.id === "threats" ? counts.scenarios : null;
            return (
              <button
                key={item.id}
                className={`nav-item ${view === item.id ? "active" : ""}`}
                onClick={() => onNavigate(item.id)}
              >
                <Icon size={16} />
                <span>{item.label}</span>
                {badge != null && badge > 0 && <span className="nav-badge">{badge}</span>}
              </button>
            );
          })}
        </div>
      ))}

      <div className="sidebar-footer">
        <div className="powered-by">
          <Sparkles size={11} />
          <span>Powered by <strong>Wiltecon Technologies</strong></span>
        </div>
        <div className="sidebar-user">
          <div className="sidebar-user-avatar">{initials}</div>
          <div className="sidebar-user-info">
            <div className="sidebar-user-email">{email}</div>
            <div className="sidebar-user-role">{role ?? "member"}</div>
          </div>
          <button onClick={signOut} title="Sign out" style={{ padding: 4, color: "var(--text-3)" }}>
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </aside>
  );
}
