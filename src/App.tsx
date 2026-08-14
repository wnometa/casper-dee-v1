import { useState } from "react";
import { AuthProvider, useAuth } from "./lib/auth";
import { WorkspaceProvider, useWorkspace } from "./lib/workspace";
import { AuthScreen } from "./components/AuthScreen";
import { Sidebar, type View } from "./components/Sidebar";
import { OverviewView } from "./components/views/OverviewView";
import { FindingsView } from "./components/views/FindingsView";
import { AssetsView } from "./components/views/AssetsView";
import { ThreatsView } from "./components/views/ThreatsView";
import { ScansView } from "./components/views/ScansView";
import { AuditView } from "./components/views/AuditView";
import { CasperAIView } from "./components/views/CasperAIView";
import { PlaceholderView } from "./components/views/PlaceholderView";
import { seedWorkspaceForUser } from "./lib/seed";
import { ShieldCheck, Sparkles } from "lucide-react";

const viewTitles: Record<View, { title: string; subtitle: string }> = {
  overview: { title: "Overview", subtitle: "Your security posture at a glance" },
  assets: { title: "Assets", subtitle: "Authorized hosts, services, and cloud resources" },
  exposure: { title: "Exposure", subtitle: "Internet-facing assets and attack surface" },
  threats: { title: "Threat DNA", subtitle: "Correlated risk scenarios from your findings" },
  findings: { title: "Vulnerabilities", subtitle: "Findings and exposures across your assets" },
  scans: { title: "Scans", subtitle: "Authorized assessment targets and scan history" },
  incidents: { title: "Incidents", subtitle: "Active security incidents and response timeline" },
  remediation: { title: "Remediation", subtitle: "What to fix, why it matters, and how to fix it" },
  reports: { title: "Reports", subtitle: "Executive and technical security reports" },
  "casper-ai": { title: "CASPER AI", subtitle: "Ask questions about your security posture" },
  compliance: { title: "Compliance", subtitle: "Security control visibility across frameworks" },
  audit: { title: "Audit Log", subtitle: "Security-relevant administrative actions" },
  organization: { title: "Organization", subtitle: "Workspace settings and configuration" },
  team: { title: "Team & Access", subtitle: "Members, roles, and permissions" },
  integrations: { title: "Integrations", subtitle: "Connect external tools and services" },
  settings: { title: "Settings", subtitle: "Application preferences and configuration" },
};

function Shell() {
  const { user, loading: authLoading } = useAuth();
  const { organization, loading: wsLoading, refresh } = useWorkspace();
  const [view, setView] = useState<View>("overview");
  const [seeding, setSeeding] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);
  const [counts, setCounts] = useState({ findings: 0, scenarios: 0 });

  if (authLoading) {
    return <div className="loading-screen"><div className="spinner" /></div>;
  }

  if (!user) {
    return <AuthScreen />;
  }

  if (wsLoading || seeding) {
    return (
      <div className="loading-screen">
        <div className="spinner" />
        <p>{seeding ? "Provisioning your security workspace…" : "Loading workspace…"}</p>
      </div>
    );
  }

  if (!organization && !seeding) {
    return (
      <OnboardingScreen
        email={user.email ?? ""}
        onProvision={async (name) => {
          setSeeding(true);
          setSeedError(null);
          const res = await seedWorkspaceForUser(user.id, name);
          if (res.error) {
            setSeedError(res.error);
            setSeeding(false);
          } else {
            await refresh();
            setSeeding(false);
          }
        }}
        error={seedError}
      />
    );
  }

  const t = viewTitles[view];

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={setView} counts={counts} />
      <div className="main">
        <div className="topbar">
          <div>
            <div className="topbar-title">{t.title}</div>
            <div className="topbar-subtitle">{t.subtitle}</div>
          </div>
          <div className="topbar-spacer" />
          <div className="topbar-signal"><span className="pulse-dot" /><span>DEFENSE MODE</span></div>
          <div className="row gap-8">
            <ShieldCheck size={15} style={{ color: "var(--success)" }} />
            <span className="text-sm text-muted">Evidence-based posture</span>
          </div>
        </div>
        <div className="content">
          {view === "overview" && <OverviewView onNavigate={(v) => setView(v as View)} />}
          {view === "findings" && <FindingsView />}
          {view === "assets" && <AssetsView />}
          {view === "threats" && <ThreatsView />}
          {view === "scans" && <ScansView />}
          {view === "audit" && <AuditView />}
          {view === "exposure" && (
            <PlaceholderView
              view="exposure"
              title="Exposure Management"
              description="Internet-facing asset discovery and attack surface management. This module will show what's exposed, where, and how reachable it is from the public internet."
              v2Features={["External attack surface management", "Subdomain discovery", "Port mapping", "Service fingerprinting"]}
            />
          )}
          {view === "incidents" && (
            <PlaceholderView
              view="incidents"
              title="Incident Management"
              description="Track and respond to security incidents. Create incidents, assign severity, attach affected assets, and follow a structured response timeline."
              v2Features={["Incident timeline", "Status workflow", "Asset linkage", "Evidence collection"]}
            />
          )}
          {view === "remediation" && (
            <PlaceholderView
              view="remediation"
              title="Remediation Workflow"
              description="See what to fix, why it matters, how to fix it, and who should fix it. Track remediation progress with due dates and assignments."
              v2Features={["Prioritized fix list", "Assignment & due dates", "Remediation plans from CASPER AI", "Progress tracking"]}
            />
          )}
          {view === "reports" && (
            <PlaceholderView
              view="reports"
              title="Security Reports"
              description="Generate executive security summaries and technical reports. Share posture with leadership, auditors, and stakeholders."
              v2Features={["Executive summary", "Technical report", "PDF export", "Scheduled reports"]}
            />
          )}
          {view === "casper-ai" && <CasperAIView />}
          {view === "compliance" && (
            <PlaceholderView
              view="compliance"
              title="Compliance Foundation"
              description="Security control visibility across NIST CSF, ISO 27001, SOC 2, PCI DSS, and GDPR. This module shows control coverage — not certification."
              v2Features={["NIST CSF mapping", "ISO 27001 controls", "SOC 2 tracking", "PCI DSS & GDPR visibility"]}
            />
          )}
          {view === "organization" && (
            <PlaceholderView
              view="organization"
              title="Organization"
              description="Workspace settings, organization configuration, and security posture preferences."
              v2Features={["Workspace configuration", "Security policies", "Notification preferences"]}
            />
          )}
          {view === "team" && (
            <PlaceholderView
              view="team"
              title="Team & Access"
              description="Manage workspace members, roles, and permissions. Roles: Owner, Admin, Security Analyst, Viewer."
              v2Features={["Member invitations", "Role management", "Access audit"]}
            />
          )}
          {view === "integrations" && (
            <PlaceholderView
              view="integrations"
              title="Integrations"
              description="Connect external tools and services to extend CASPER DEE's capabilities."
              v2Features={["Slack", "Microsoft Teams", "Jira", "Webhooks", "SIEM connectors"]}
            />
          )}
          {view === "settings" && (
            <PlaceholderView
              view="settings"
              title="Settings"
              description="Application preferences, API keys, and system configuration."
              v2Features={["API access", "Notification settings", "Theme preferences"]}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function OnboardingScreen({
  email, onProvision, error,
}: {
  email: string;
  onProvision: (name: string) => Promise<void>;
  error: string | null;
}) {
  const [name, setName] = useState("");
  const defaultName = email.split("@")[1]?.split(".")[0] ?? "My Company";
  const orgName = name || defaultName.charAt(0).toUpperCase() + defaultName.slice(1);

  return (
    <div className="auth-screen">
      <div className="auth-orbit auth-orbit-one" />
      <div className="auth-orbit auth-orbit-two" />
      <div className="auth-card slide-up" style={{ maxWidth: 480 }}>
        <div className="auth-brand">
          <div className="auth-brand-text">
            <h1>CASPER DEE</h1>
            <p>Security Command Center</p>
          </div>
        </div>

        <div className="auth-tagline">Know what matters.<br />Fix what matters first.</div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20, padding: 14, background: "var(--primary-soft)", borderRadius: "var(--radius-sm)", border: "1px solid rgba(24,168,255,0.2)" }}>
          <Sparkles size={18} style={{ color: "var(--primary)" }} />
          <p className="text-sm" style={{ color: "var(--text-1)" }}>
            Your account is ready. Let's set up your security workspace with sample data so you can explore the platform immediately.
          </p>
        </div>

        {error && <div className="auth-error">{error}</div>}

        <div className="form-group">
          <label className="form-label">Organization name</label>
          <input
            className="form-input"
            value={orgName}
            onChange={(e) => setName(e.target.value)}
            placeholder="Your company name"
          />
          <div className="form-hint">We'll seed your workspace with sample assets, findings, and threat scenarios so you can see how CASPER DEE works.</div>
        </div>

        <button className="btn btn-primary w-full" style={{ justifyContent: "center" }} onClick={() => onProvision(orgName)}>
          <Sparkles size={15} /> Provision my workspace
        </button>

        <div className="auth-powered">
          <Sparkles size={12} /> Powered by <strong>Wiltecon Technologies</strong>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <WorkspaceProvider>
        <Shell />
      </WorkspaceProvider>
    </AuthProvider>
  );
}
