import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { AttackPath, AttackPathNode } from "../../lib/types";
import { riskColor } from "../ui";
import { Route, X, ArrowRight, Target, Zap, Flag, Globe } from "lucide-react";
import { useState } from "react";

const nodeTypeIcon: Record<AttackPathNode["type"], typeof Globe> = {
  entry: Globe, pivot: Zap, asset: Flag, objective: Target,
};

const nodeTypeCls: Record<AttackPathNode["type"], string> = {
  entry: "path-node entry", pivot: "path-node pivot", asset: "path-node", objective: "path-node objective",
};

export function AttackPathsView() {
  const { organization } = useWorkspace();
  const orgId = organization?.id;
  const [selected, setSelected] = useState<AttackPath | null>(null);

  const { data: paths, loading } = useAsyncData(async () => {
    if (!orgId) return [];
    const { data } = await supabase.from("attack_paths").select("*").eq("organization_id", orgId).order("risk_score", { ascending: false });
    return (data as AttackPath[]) ?? [];
  }, [orgId]);

  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;

  const list = paths ?? [];
  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <Route size={15} />
          <span className="card-title">Potential Attack Paths</span>
        </div>
        <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {list.map((p) => (
            <div
              key={p.id}
              onClick={() => setSelected(p)}
              style={{ padding: 16, background: "var(--bg-2)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)", cursor: "pointer", transition: "border-color 0.15s" }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-soft)")}
            >
              <div className="row-between mb-8">
                <span className="fw-600">{p.title}</span>
                <span className="badge" style={{ background: "var(--bg-3)", color: riskColor(p.risk_score) }}>Risk {p.risk_score}</span>
              </div>
              <p className="text-sm text-muted mb-8">{p.summary}</p>
              <div className="path-flow">
                {p.nodes.map((n, i) => (
                  <div key={n.id} className="row gap-8">
                    <span className="text-xs" style={{ color: "var(--text-2)" }}>{n.label}</span>
                    {i < p.nodes.length - 1 && <ArrowRight size={12} style={{ color: "var(--text-3)" }} />}
                  </div>
                ))}
              </div>
            </div>
          ))}
          {list.length === 0 && <div className="empty-state">No attack paths mapped yet.</div>}
        </div>
      </div>

      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 720 }}>
            <div className="modal-header">
              <span className="modal-title">{selected.title}</span>
              <button onClick={() => setSelected(null)} style={{ color: "var(--text-3)" }}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <div className="row gap-8 mb-16">
                <span className="badge" style={{ background: "var(--bg-3)", color: riskColor(selected.risk_score), fontSize: 12, padding: "5px 10px" }}>
                  Risk {selected.risk_score}/100
                </span>
              </div>
              <p className="text-sm mb-16">{selected.summary}</p>

              <div className="text-xs text-muted mb-8">Attack Flow</div>
              <div className="path-graph" style={{ background: "var(--bg-2)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)" }}>
                <div className="path-flow">
                  {selected.nodes.map((n, i) => {
                    const Icon = nodeTypeIcon[n.type];
                    return (
                      <div key={n.id} className="row gap-8">
                        <div className={nodeTypeCls[n.type]}>
                          <Icon size={13} />
                          <span>{n.label}</span>
                          {n.detail && <span className="path-node-detail">{n.detail}</span>}
                        </div>
                        {i < selected.nodes.length - 1 && (
                          <div className="path-arrow">
                            <ArrowRight size={18} />
                            {selected.edges[i]?.label && (
                              <span style={{ fontSize: 10, color: "var(--text-3)", marginLeft: 4 }}>{selected.edges[i].label}</span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="mt-16 text-xs text-muted">
                <strong style={{ color: "var(--text-1)" }}>Disclaimer:</strong> These paths represent evidence-backed potential risk based on current findings and asset exposure — not proof of active compromise.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
