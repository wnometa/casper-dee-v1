import { useMemo } from "react";
import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { Asset, Finding, ThreatScenario, AttackPath } from "../../lib/types";
import {
  ShieldAlert, Server, Globe, Crosshair, TrendingDown, ArrowRight, Activity,
} from "lucide-react";
import { severityBadge, riskColor } from "../ui";
import { ScoreGauge } from "../ScoreGauge";

export function OverviewView({ onNavigate }: { onNavigate: (v: "findings" | "threats" | "paths") => void }) {
  const { organization } = useWorkspace();
  const orgId = organization?.id;

  const { data, loading } = useAsyncData(async () => {
    if (!orgId) return null;
    const [assets, findings, scenarios, paths] = await Promise.all([
      supabase.from("assets").select("*").eq("organization_id", orgId).then((r) => r.data as Asset[] | null),
      supabase.from("findings").select("*, asset:assets(id,name,hostname)").eq("organization_id", orgId).then((r) => r.data as Finding[] | null),
      supabase.from("threat_scenarios").select("*").eq("organization_id", orgId).then((r) => r.data as ThreatScenario[] | null),
      supabase.from("attack_paths").select("*").eq("organization_id", orgId).then((r) => r.data as AttackPath[] | null),
    ]);
    return { assets: assets ?? [], findings: findings ?? [], scenarios: scenarios ?? [], paths: paths ?? [] };
  }, [orgId]);

  const metrics = useMemo(() => {
    if (!data) return null;
    const openFindings = data.findings.filter((f) => f.status === "open" || f.status === "in_progress");
    const critical = openFindings.filter((f) => f.severity === "critical").length;
    const high = openFindings.filter((f) => f.severity === "high").length;
    const exposed = data.findings.filter((f) => f.is_externally_exposed && (f.status === "open" || f.status === "in_progress")).length;
    const internetAssets = data.assets.filter((a) => a.exposure_state === "internet").length;
    const avgRisk = data.scenarios.length ? Math.round(data.scenarios.reduce((s, sc) => s + sc.risk_score, 0) / data.scenarios.length) : 0;
    const securityScore = Math.max(0, Math.min(100, 100 - (critical * 12 + high * 6 + exposed * 4)));
    return { openFindings: openFindings.length, critical, high, exposed, internetAssets, avgRisk, securityScore, totalAssets: data.assets.length };
  }, [data]);

  if (loading || !data || !metrics) {
    return <div className="loading-screen"><div className="spinner" /><p>Loading posture…</p></div>;
  }

  const topFindings = [...data.findings]
    .filter((f) => f.status === "open" || f.status === "in_progress")
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 5);

  return (
    <div className="fade-in">
      <div className="stat-grid">
        <div className="stat-tile">
          <div className="stat-tile-label"><ShieldAlert size={13} /> Open Findings</div>
          <div className="stat-tile-value">{metrics.openFindings}</div>
          <div className="stat-tile-delta">{metrics.critical} critical · {metrics.high} high</div>
        </div>
        <div className="stat-tile">
          <div className="stat-tile-label"><Globe size={13} /> Internet-Exposed</div>
          <div className="stat-tile-value">{metrics.exposed}</div>
          <div className="stat-tile-delta">{metrics.internetAssets} assets face the public internet</div>
        </div>
        <div className="stat-tile">
          <div className="stat-tile-label"><Server size={13} /> Tracked Assets</div>
          <div className="stat-tile-value">{metrics.totalAssets}</div>
          <div className="stat-tile-delta">Across web, server, cloud, endpoint</div>
        </div>
        <div className="stat-tile">
          <div className="stat-tile-label"><Crosshair size={13} /> Active Scenarios</div>
          <div className="stat-tile-value">{data.scenarios.filter((s) => s.status === "active").length}</div>
          <div className="stat-tile-delta">Avg risk {metrics.avgRisk}/100</div>
        </div>
      </div>

      <div className="grid-2 mb-24">
        <div className="card">
          <div className="card-header">
            <Activity size={15} />
            <span className="card-title">Security Score</span>
          </div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <ScoreGauge value={metrics.securityScore} />
            <p className="text-sm text-muted" style={{ textAlign: "center", maxWidth: 320 }}>
              Score reflects open critical and high findings weighted by external exposure. Higher is better.
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <TrendingDown size={15} />
            <span className="card-title">Priority Findings</span>
            <button className="btn btn-ghost btn-sm" style={{ marginLeft: "auto" }} onClick={() => onNavigate("findings")}>
              View all <ArrowRight size={13} />
            </button>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Finding</th><th>Severity</th><th>Asset</th></tr>
              </thead>
              <tbody>
                {topFindings.map((f) => (
                  <tr key={f.id}>
                    <td style={{ maxWidth: 220 }} className="truncate">{f.title}</td>
                    <td>{severityBadge(f.severity)}</td>
                    <td className="mono">{f.asset?.name ?? "—"}</td>
                  </tr>
                ))}
                {topFindings.length === 0 && (
                  <tr><td colSpan={3} style={{ textAlign: "center", color: "var(--text-3)" }}>No open findings. Nice.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <Crosshair size={15} />
          <span className="card-title">Active Threat Scenarios</span>
          <button className="btn btn-ghost btn-sm" style={{ marginLeft: "auto" }} onClick={() => onNavigate("threats")}>
            View all <ArrowRight size={13} />
          </button>
        </div>
        <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {data.scenarios.filter((s) => s.status === "active").slice(0, 3).map((s) => (
            <div key={s.id} style={{ padding: 14, background: "var(--bg-2)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)" }}>
              <div className="row-between mb-8">
                <span className="fw-600">{s.title}</span>
                <span className="badge" style={{ background: "var(--bg-3)", color: riskColor(s.risk_score) }}>
                  Risk {s.risk_score}
                </span>
              </div>
              <p className="text-sm text-muted">{s.summary}</p>
            </div>
          ))}
          {data.scenarios.length === 0 && <div className="empty-state">No threat scenarios yet.</div>}
        </div>
      </div>
    </div>
  );
}

function severityRank(s: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  return order[s] ?? 5;
}
