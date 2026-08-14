import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { ThreatScenario } from "../../lib/types";
import { riskColor } from "../ui";
import { Crosshair, X } from "lucide-react";
import { useState } from "react";

export function ThreatsView() {
  const { organization } = useWorkspace();
  const orgId = organization?.id;
  const [selected, setSelected] = useState<ThreatScenario | null>(null);

  const { data: scenarios, loading } = useAsyncData(async () => {
    if (!orgId) return [];
    const { data } = await supabase.from("threat_scenarios").select("*").eq("organization_id", orgId).order("risk_score", { ascending: false });
    return (data as ThreatScenario[]) ?? [];
  }, [orgId]);

  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;

  const list = scenarios ?? [];
  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <Crosshair size={15} />
          <span className="card-title">Threat DNA Scenarios</span>
        </div>
        <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {list.map((s) => (
            <div
              key={s.id}
              onClick={() => setSelected(s)}
              style={{ padding: 16, background: "var(--bg-2)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)", cursor: "pointer", transition: "border-color 0.15s" }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-soft)")}
            >
              <div className="row-between mb-8">
                <span className="fw-600">{s.title}</span>
                <div className="row gap-8">
                  <span className="badge" style={{ background: "var(--bg-3)", color: riskColor(s.risk_score) }}>Risk {s.risk_score}</span>
                  <span className={`badge ${s.status === "active" ? "badge-warning" : s.status === "mitigated" ? "badge-success" : "badge-neutral"}`}>{s.status}</span>
                </div>
              </div>
              <p className="text-sm text-muted">{s.summary}</p>
            </div>
          ))}
          {list.length === 0 && <div className="empty-state">No threat scenarios yet.</div>}
        </div>
      </div>

      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">{selected.title}</span>
              <button onClick={() => setSelected(null)} style={{ color: "var(--text-3)" }}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <div className="row gap-8 mb-16">
                <span className="badge" style={{ background: "var(--bg-3)", color: riskColor(selected.risk_score), fontSize: 12, padding: "5px 10px" }}>
                  Risk Score: {selected.risk_score}/100
                </span>
                <span className={`badge ${selected.status === "active" ? "badge-warning" : selected.status === "mitigated" ? "badge-success" : "badge-neutral"}`} style={{ fontSize: 12, padding: "5px 10px" }}>
                  {selected.status}
                </span>
              </div>
              <p className="text-sm">{selected.summary}</p>
              <div className="mt-16" style={{ padding: 14, background: "var(--bg-2)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)" }}>
                <div className="text-xs text-muted mb-8">Risk Assessment</div>
                <div style={{ height: 8, background: "var(--bg-3)", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ width: `${selected.risk_score}%`, height: "100%", background: riskColor(selected.risk_score), borderRadius: 4, transition: "width 0.6s ease" }} />
                </div>
                <div className="row-between mt-8 text-xs text-muted">
                  <span>Low</span><span>Moderate</span><span>High</span><span>Critical</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
