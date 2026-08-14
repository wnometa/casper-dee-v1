import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { AuditLog } from "../../lib/types";
import { ScrollText } from "lucide-react";

export function AuditView() {
  const { organization } = useWorkspace();
  const orgId = organization?.id;

  const { data: logs, loading } = useAsyncData(async () => {
    if (!orgId) return [];
    const { data } = await supabase
      .from("audit_logs")
      .select("*")
      .eq("organization_id", orgId)
      .order("created_at", { ascending: false })
      .limit(100);
    return (data as AuditLog[]) ?? [];
  }, [orgId]);

  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;

  const list = logs ?? [];
  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <ScrollText size={15} />
          <span className="card-title">Audit Log</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Action</th><th>Resource</th><th>Details</th></tr>
            </thead>
            <tbody>
              {list.map((l) => (
                <tr key={l.id}>
                  <td className="mono text-sm text-muted">{new Date(l.created_at).toLocaleString()}</td>
                  <td className="mono text-sm">{l.action}</td>
                  <td className="text-sm">{l.resource_type}{l.resource_id ? ` · ${l.resource_id.slice(0, 8)}` : ""}</td>
                  <td className="mono text-sm text-muted">
                    {Object.keys(l.metadata).length > 0 ? JSON.stringify(l.metadata) : "—"}
                  </td>
                </tr>
              ))}
              {list.length === 0 && (
                <tr><td colSpan={4} style={{ textAlign: "center", color: "var(--text-3)", padding: 32 }}>No audit events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
