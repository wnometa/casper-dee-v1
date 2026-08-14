import { useMemo, useState } from "react";
import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { Asset, AssetType, Criticality, ExposureState } from "../../lib/types";
import { Server, Globe, Lock, Network, Cloud, Monitor } from "lucide-react";

const typeIcons: Record<AssetType, typeof Server> = {
  web: Globe, server: Server, database: Server, cloud: Cloud, endpoint: Monitor, network: Network,
};

const criticalityBadge: Record<Criticality, string> = {
  critical: "badge badge-critical", high: "badge badge-high", medium: "badge badge-medium", low: "badge badge-low",
};

const exposureBadge: Record<ExposureState, { cls: string; label: string }> = {
  internet: { cls: "badge badge-critical", label: "Internet" },
  restricted: { cls: "badge badge-warning", label: "Restricted" },
  internal: { cls: "badge badge-success", label: "Internal" },
  unknown: { cls: "badge badge-neutral", label: "Unknown" },
};

export function AssetsView() {
  const { organization } = useWorkspace();
  const orgId = organization?.id;
  const [typeFilter, setTypeFilter] = useState<AssetType | "all">("all");

  const { data: assets, loading } = useAsyncData(async () => {
    if (!orgId) return [];
    const { data } = await supabase.from("assets").select("*").eq("organization_id", orgId).order("name");
    return (data as Asset[]) ?? [];
  }, [orgId]);

  const filtered = useMemo(() => {
    if (!assets) return [];
    return typeFilter === "all" ? assets : assets.filter((a) => a.asset_type === typeFilter);
  }, [assets, typeFilter]);

  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;

  const types: (AssetType | "all")[] = ["all", "web", "server", "database", "cloud", "endpoint", "network"];

  return (
    <div className="fade-in">
      <div className="chip-row">
        {types.map((t) => (
          <button key={t} className={`chip ${typeFilter === t ? "active" : ""}`} onClick={() => setTypeFilter(t)}>
            {t === "all" ? "All types" : t}
          </button>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <Server size={15} />
          <span className="card-title">{filtered.length} Assets</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr><th>Asset</th><th>Type</th><th>Host / IP</th><th>Criticality</th><th>Exposure</th><th>Status</th><th>Last Seen</th></tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const Icon = typeIcons[a.asset_type];
                return (
                  <tr key={a.id}>
                    <td>
                      <div className="row gap-8">
                        <Icon size={14} style={{ color: "var(--text-3)" }} />
                        <span className="fw-600">{a.name}</span>
                      </div>
                    </td>
                    <td className="text-sm text-muted">{a.asset_type}</td>
                    <td className="mono text-sm">{a.hostname ?? a.ip_address ?? "—"}</td>
                    <td><span className={criticalityBadge[a.criticality]}>{a.criticality}</span></td>
                    <td><span className={exposureBadge[a.exposure_state].cls}>{exposureBadge[a.exposure_state].label}</span></td>
                    <td>
                      {a.status === "active"
                        ? <span className="badge badge-success"><Lock size={10} /> Active</span>
                        : <span className="badge badge-neutral">{a.status}</span>}
                    </td>
                    <td className="text-sm text-muted">{a.last_seen_at ? new Date(a.last_seen_at).toLocaleDateString() : "—"}</td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr><td colSpan={7} style={{ textAlign: "center", color: "var(--text-3)", padding: 32 }}>No assets found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
