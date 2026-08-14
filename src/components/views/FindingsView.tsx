import { useMemo, useState } from "react";
import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { Finding, Severity, FindingStatus } from "../../lib/types";
import { severityBadge, statusBadge } from "../ui";
import { ShieldAlert, Filter, X, ExternalLink } from "lucide-react";

const severities: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "informational"];
const statuses: (FindingStatus | "all")[] = ["all", "open", "in_progress", "resolved", "accepted"];

export function FindingsView() {
  const { organization, role } = useWorkspace();
  const orgId = organization?.id;
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const [exposedOnly, setExposedOnly] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);

  const { data: findings, loading, reload } = useAsyncData(async () => {
    if (!orgId) return [];
    const { data } = await supabase
      .from("findings")
      .select("*, asset:assets(id,name,hostname)")
      .eq("organization_id", orgId)
      .order("discovered_at", { ascending: false });
    return (data as Finding[]) ?? [];
  }, [orgId]);

  const filtered = useMemo(() => {
    if (!findings) return [];
    return findings.filter((f) => {
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (exposedOnly && !f.is_externally_exposed) return false;
      return true;
    });
  }, [findings, sevFilter, statusFilter, exposedOnly]);

  const canEdit = role === "owner" || role === "admin" || role === "analyst";

  const updateStatus = async (id: string, status: FindingStatus) => {
    const resolved_at = status === "resolved" ? new Date().toISOString() : null;
    await supabase.from("findings").update({ status, resolved_at }).eq("id", id);
    setSelected((s) => (s ? { ...s, status, resolved_at } : s));
    reload();
  };

  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;

  return (
    <div className="fade-in">
      <div className="chip-row">
        <Filter size={14} style={{ alignSelf: "center", color: "var(--text-3)" }} />
        {severities.map((s) => (
          <button key={s} className={`chip ${sevFilter === s ? "active" : ""}`} onClick={() => setSevFilter(s)}>
            {s === "all" ? "All severities" : s}
          </button>
        ))}
        <span style={{ width: 1, height: 24, background: "var(--border-soft)", margin: "0 4px" }} />
        {statuses.map((s) => (
          <button key={s} className={`chip ${statusFilter === s ? "active" : ""}`} onClick={() => setStatusFilter(s)}>
            {s === "all" ? "All statuses" : s.replace("_", " ")}
          </button>
        ))}
        <span style={{ width: 1, height: 24, background: "var(--border-soft)", margin: "0 4px" }} />
        <button className={`chip ${exposedOnly ? "active" : ""}`} onClick={() => setExposedOnly(!exposedOnly)}>
          Internet-exposed only
        </button>
      </div>

      <div className="card">
        <div className="card-header">
          <ShieldAlert size={15} />
          <span className="card-title">{filtered.length} Findings</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Asset</th>
                <th>Exposure</th>
                <th>CVSS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor: "pointer" }}>
                  <td style={{ maxWidth: 280 }} className="truncate">{f.title}</td>
                  <td>{severityBadge(f.severity)}</td>
                  <td>{statusBadge(f.status)}</td>
                  <td className="mono">{f.asset?.name ?? "—"}</td>
                  <td>{f.is_externally_exposed ? <span className="badge badge-critical"><ExternalLink size={10} /> Public</span> : <span className="badge badge-neutral">Internal</span>}</td>
                  <td className="mono">{f.cvss_score?.toFixed(1) ?? "—"}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-3)", padding: 32 }}>No findings match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <FindingDetail finding={selected} onClose={() => setSelected(null)} canEdit={canEdit} onStatusChange={updateStatus} />
      )}
    </div>
  );
}

function FindingDetail({
  finding, onClose, canEdit, onStatusChange,
}: {
  finding: Finding;
  onClose: () => void;
  canEdit: boolean;
  onStatusChange: (id: string, status: FindingStatus) => void;
}) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="row gap-8">
            {severityBadge(finding.severity)}
            <span className="modal-title">{finding.title}</span>
          </div>
          <button onClick={onClose} style={{ color: "var(--text-3)" }}><X size={18} /></button>
        </div>
        <div className="modal-body">
          {finding.description && <p className="mb-16">{finding.description}</p>}

          <div className="grid-2 mb-16">
            <div>
              <div className="text-xs text-muted mb-8">Asset</div>
              <div className="mono">{finding.asset?.name ?? "—"}</div>
              {finding.asset?.hostname && <div className="mono text-sm text-muted">{finding.asset.hostname}</div>}
            </div>
            <div>
              <div className="text-xs text-muted mb-8">CVSS Score</div>
              <div className="mono" style={{ fontSize: 18 }}>{finding.cvss_score?.toFixed(1) ?? "—"}</div>
            </div>
          </div>

          {finding.evidence && (
            <div className="mb-16">
              <div className="text-xs text-muted mb-8">Evidence</div>
              <div className="card-body" style={{ background: "var(--bg-2)", borderRadius: "var(--radius-sm)", padding: 12, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-1)" }}>
                {finding.evidence}
              </div>
            </div>
          )}

          {finding.remediation && (
            <div className="mb-16">
              <div className="text-xs text-muted mb-8">Remediation</div>
              <p className="text-sm">{finding.remediation}</p>
            </div>
          )}

          <div>
            <div className="text-xs text-muted mb-8">Status</div>
            <div className="row gap-8">
              {(["open", "in_progress", "resolved", "accepted"] as FindingStatus[]).map((s) => (
                <button
                  key={s}
                  className={`btn btn-sm ${finding.status === s ? "btn-primary" : "btn-ghost"}`}
                  disabled={!canEdit || finding.status === s}
                  onClick={() => onStatusChange(finding.id, s)}
                >
                  {s.replace("_", " ")}
                </button>
              ))}
            </div>
            {!canEdit && <p className="text-xs text-muted mt-8">You need analyst or admin permissions to change status.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}
