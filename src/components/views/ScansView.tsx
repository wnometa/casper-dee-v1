import { useState } from "react";
import { useWorkspace } from "../../lib/workspace";
import { supabase } from "../../lib/supabase";
import { useAsyncData } from "../../lib/hooks";
import type { ScanTarget, ScanJob, TargetType, TargetStatus, ScanJobStatus, Finding } from "../../lib/types";
import {
  Radar, Plus, X, Play, FileCheck, ShieldCheck, Clock, CheckCircle2,
  AlertCircle, Loader, ChevronRight, ExternalLink, Bug, Pencil, Trash2, ShieldOff, ShieldCheck as ShieldCheckIcon, MoreHorizontal,
} from "lucide-react";

const targetStatusBadge: Record<TargetStatus, { cls: string; label: string }> = {
  pending: { cls: "badge badge-warning", label: "Pending" },
  authorized: { cls: "badge badge-success", label: "Authorized" },
  revoked: { cls: "badge badge-neutral", label: "Revoked" },
};

const jobStatusIcon: Record<ScanJobStatus, typeof Clock> = {
  queued: Clock,
  running: Loader,
  completed: CheckCircle2,
  failed: AlertCircle,
};

const jobStatusCls: Record<ScanJobStatus, string> = {
  queued: "badge badge-neutral",
  running: "badge badge-warning",
  completed: "badge badge-success",
  failed: "badge badge-critical",
};

const severityCls: Record<string, string> = {
  critical: "badge badge-critical",
  high: "badge badge-warning",
  medium: "badge badge-info",
  low: "badge badge-neutral",
  informational: "badge badge-neutral",
};

export function ScansView() {
  const { organization, role } = useWorkspace();
  const orgId = organization?.id;
  const [showAdd, setShowAdd] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [targetToDelete, setTargetToDelete] = useState<ScanTarget | null>(null);
  const [deletedTargetIds, setDeletedTargetIds] = useState<string[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);

  const { data, loading, reload } = useAsyncData(async () => {
    if (!orgId) return { targets: [], jobs: [] };
    const [targets, jobs] = await Promise.all([
      supabase
        .from("scan_targets")
        .select("*")
        .eq("organization_id", orgId)
        .order("created_at", { ascending: false })
        .then((r) => r.data as ScanTarget[] | null),
      supabase
        .from("scan_jobs")
        .select("*, target:scan_targets(id,name,target_value)")
        .eq("organization_id", orgId)
        .order("created_at", { ascending: false })
        .limit(20)
        .then((r) => r.data as ScanJob[] | null),
    ]);
    return { targets: targets ?? [], jobs: jobs ?? [] };
  }, [orgId]);

  const canEdit = role === "owner" || role === "admin" || role === "analyst";
  const canDelete = role === "owner" || role === "admin";

  const deleteTarget = async (target: ScanTarget) => {
    if (deletingId) return;

    setDeletingId(target.id);
    setScanError(null);

    const { error } = await supabase
      .from("scan_targets")
      .delete()
      .eq("id", target.id);

    setDeletingId(null);
    setTargetToDelete(null);

    if (error) {
      setScanError(`Could not delete the target "${target.name}". Please try again.`);
      return;
    }

    setDeletedTargetIds((prev) => prev.includes(target.id) ? prev : [...prev, target.id]);
    if (selectedJob && data?.jobs.some((job) => job.id === selectedJob && (job.target_id === target.id || job.target?.id === target.id))) {
      setSelectedJob(null);
    }
    reload();
  };

  const runScan = async (target: ScanTarget) => {
    setRunning(target.id);
    setScanError(null);

    const { data: job, error: jobError } = await supabase
      .from("scan_jobs")
      .insert({
        organization_id: orgId,
        target_id: target.id,
        status: "queued",
      })
      .select("id")
      .single();

    if (jobError || !job) {
      setScanError("Could not start the scan. Please try again.");
      setRunning(null);
      return;
    }

    try {
      const { data: userData } = await supabase.auth.getUser();
      const apiUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/scan-target`;
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`,
        },
        body: JSON.stringify({
          target_id: target.id,
          target_value: target.target_value,
          organization_id: orgId,
          scan_job_id: job.id,
          user_id: userData.user?.id,
        }),
      });

      if (!response.ok) {
        throw new Error(`Scanner returned ${response.status}`);
      }

      const result = await response.json();
      if (result.error) throw new Error(result.error);
    } catch (err) {
      await supabase.from("scan_jobs").update({
        status: "failed",
        completed_at: new Date().toISOString(),
        summary: "The scan could not complete. The target may be unreachable or blocking automated requests.",
      }).eq("id", job.id);
      setScanError("The scan could not reach the target. This may be due to a firewall, invalid URL, or the site blocking automated requests.");
    }

    setRunning(null);
    reload();
  };

  if (loading || !data) return <div className="loading-screen"><div className="spinner" /></div>;

  const visibleTargets = data.targets.filter((target) => !deletedTargetIds.includes(target.id));
  const expandedJob = selectedJob ? data.jobs.find((j) => j.id === selectedJob) : null;

  return (
    <div className="fade-in">
      <div className="row-between mb-16">
        <div className="row gap-8">
          <FileCheck size={15} style={{ color: "var(--text-3)" }} />
          <span className="text-sm text-muted">Real URL scans — the scanner fetches your target and analyzes security headers, TLS, and HTML for evidence-based findings.</span>
        </div>
        {canEdit && (
          <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(true)}>
            <Plus size={14} /> Add target
          </button>
        )}
      </div>

      {scanError && (
        <div className="auth-error mb-16" style={{ maxWidth: "none" }}>{scanError}</div>
      )}

      <div className="grid-2 mb-24">
        <div className="card">
          <div className="card-header">
            <Radar size={15} />
            <span className="card-title">Authorized Targets ({visibleTargets.length})</span>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Target</th><th>Type</th><th>Authorization</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {visibleTargets.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <div className="fw-600">{t.name}</div>
                      <div className="mono text-sm text-muted">{t.target_value}</div>
                    </td>
                    <td className="text-sm text-muted">{t.target_type}</td>
                    <td className="text-sm text-muted">{t.authorization_document ?? "—"}</td>
                    <td>
                      {targetStatusBadge[t.status] && (
                        <span className={targetStatusBadge[t.status].cls}>{targetStatusBadge[t.status].label}</span>
                      )}
                    </td>
                    <td>
                      {canEdit && t.status === "authorized" && (
                        <div className="row gap-8">
                          <button
                            className="btn btn-ghost btn-sm"
                            disabled={running === t.id}
                            onClick={() => runScan(t)}
                          >
                            {running === t.id ? <><span className="spinner" /> Scanning…</> : <><Play size={12} /> Run scan</>}
                          </button>
                          {canDelete && (
                            <button
                              className="btn btn-ghost btn-sm"
                              style={{ color: "var(--danger, #ef4444)", borderColor: "var(--border-soft)" }}
                              disabled={deletingId === t.id}
                              onClick={() => setTargetToDelete(t)}
                            >
                              {deletingId === t.id ? <><span className="spinner" /> Deleting…</> : <><Trash2 size={12} /> Delete</>}
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
                {visibleTargets.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-3)", padding: 32 }}>No scan targets yet. Add a URL to get started.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <Clock size={15} />
            <span className="card-title">Recent Scan Jobs</span>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Target</th><th>Status</th><th>Findings</th><th>Completed</th><th></th></tr>
              </thead>
              <tbody>
                {data.jobs.map((j) => {
                  const Icon = jobStatusIcon[j.status];
                  return (
                    <tr key={j.id}>
                      <td className="fw-600">{j.target?.name ?? "—"}</td>
                      <td>
                        <span className={jobStatusCls[j.status]}>
                          <Icon size={10} /> {j.status}
                        </span>
                      </td>
                      <td className="mono">{j.findings_count}</td>
                      <td className="text-sm text-muted">
                        {j.completed_at ? new Date(j.completed_at).toLocaleString() : "—"}
                      </td>
                      <td>
                        {j.status === "completed" && (
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => setSelectedJob(selectedJob === j.id ? null : j.id)}
                          >
                            <ChevronRight
                              size={12}
                              style={{ transform: selectedJob === j.id ? "rotate(90deg)" : "none", transition: "transform 150ms" }}
                            />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {data.jobs.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-3)", padding: 32 }}>No scans run yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {expandedJob && (
        <ScanResults jobId={expandedJob.id} job={expandedJob} onClose={() => setSelectedJob(null)} />
      )}

      {showAdd && (
        <AddTargetModal
          orgId={orgId!}
          onClose={() => setShowAdd(false)}
          onSaved={() => { setShowAdd(false); reload(); }}
        />
      )}

      {targetToDelete && (
        <div className="modal-overlay" onClick={() => setTargetToDelete(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Delete scan target?</span>
              <button onClick={() => setTargetToDelete(null)} style={{ color: "var(--text-3)" }}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              <p className="text-sm text-muted">
                This will permanently remove this scan target. Existing scan results and findings will not be deleted.
              </p>
            </div>

            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setTargetToDelete(null)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                disabled={deletingId === targetToDelete.id}
                onClick={() => deleteTarget(targetToDelete)}
                style={{ background: "var(--danger, #ef4444)", borderColor: "var(--danger, #ef4444)" }}
              >
                {deletingId === targetToDelete.id ? <><span className="spinner" /> Deleting…</> : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ScanResults({ jobId, job, onClose }: { jobId: string; job: ScanJob; onClose: () => void }) {
  const { data: findings, loading } = useAsyncData(async () => {
    const { data } = await supabase
      .from("findings")
      .select("*")
      .eq("scan_job_id", jobId)
      .order("severity", { ascending: false });
    return (data as Finding[]) ?? [];
  }, [jobId]);

  return (
    <div className="card mb-24">
      <div className="card-header">
        <Bug size={15} />
        <span className="card-title">Scan Findings — {job.target?.name ?? "Unknown target"}</span>
        <button className="btn btn-ghost btn-sm" onClick={onClose} style={{ marginLeft: "auto" }}>
          <X size={14} />
        </button>
      </div>
      <div className="card-body">
        {job.summary && (
          <div style={{ padding: "12px 16px", background: "var(--bg-2)", borderRadius: "var(--radius-sm)", marginBottom: 16, border: "1px solid var(--border-soft)" }}>
            <p className="text-sm">{job.summary}</p>
          </div>
        )}

        {loading ? (
          <div className="row gap-8" style={{ padding: 24, justifyContent: "center" }}>
            <span className="spinner" /> <span className="text-sm text-muted">Loading findings…</span>
          </div>
        ) : findings && findings.length > 0 ? (
          <div className="space-y-12" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {findings.map((f) => (
              <div key={f.id} style={{ padding: 16, border: "1px solid var(--border-soft)", borderRadius: "var(--radius-sm)" }}>
                <div className="row-between mb-8">
                  <div className="row gap-8" style={{ alignItems: "center" }}>
                    <span className={severityCls[f.severity] ?? "badge badge-neutral"}>{f.severity}</span>
                    <span className="fw-600 text-sm">{f.title}</span>
                  </div>
                  {f.cvss_score && (
                    <span className="mono text-xs text-muted">CVSS {f.cvss_score}</span>
                  )}
                </div>
                <p className="text-sm text-muted mb-8">{f.description}</p>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", borderRadius: "var(--radius-sm)", marginBottom: 8 }}>
                  <div className="text-xs text-muted mb-4" style={{ marginBottom: 4 }}>EVIDENCE</div>
                  <p className="mono text-xs" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.evidence}</p>
                </div>
                <div className="row gap-8" style={{ alignItems: "flex-start" }}>
                  <ShieldCheck size={12} style={{ color: "var(--success)", marginTop: 2, flexShrink: 0 }} />
                  <p className="text-sm">{f.remediation}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="row gap-8" style={{ padding: 24, justifyContent: "center" }}>
            <ShieldCheck size={16} style={{ color: "var(--success)" }} />
            <span className="text-sm text-muted">No security issues detected. The target has strong security posture.</span>
          </div>
        )}
      </div>
    </div>
  );
}

function AddTargetModal({ orgId, onClose, onSaved }: { orgId: string; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [authDoc, setAuthDoc] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setError(null);

    const trimmedName = name.trim();
    const trimmedValue = value.trim();
    const trimmedAuthDoc = authDoc.trim();

    if (!trimmedName) {
      setError("Enter a name for this target.");
      return;
    }

    if (!trimmedValue) {
      setError("Enter a target URL.");
      return;
    }

    let parsedUrl: URL;

    try {
      parsedUrl = new URL(
        /^https?:\/\//i.test(trimmedValue)
          ? trimmedValue
          : `https://${trimmedValue}`,
      );
    } catch {
      setError("Enter a valid URL, such as https://example.com.");
      return;
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      setError("Only HTTP and HTTPS URLs are supported.");
      return;
    }

    if (!parsedUrl.hostname || parsedUrl.hostname.includes(" ")) {
      setError("Enter a valid hostname.");
      return;
    }

    if (!confirmed) {
      setError("You must confirm you own or have permission to assess this target.");
      return;
    }

    setBusy(true);

    const { data: existing } = await supabase
      .from("scan_targets")
      .select("id")
      .eq("organization_id", orgId)
      .ilike("target_value", trimmedValue)
      .limit(1);

    if (existing && existing.length > 0) {
      setBusy(false);
      setError("This target already exists in your organization.");
      return;
    }

    const { error: insertError } = await supabase.from("scan_targets").insert({
      organization_id: orgId,
      name: trimmedName,
      target_value: parsedUrl.toString(),
      target_type: "url",
      authorization_document: trimmedAuthDoc || null,
      status: "authorized",
    });

    setBusy(false);

    if (insertError) {
      setError("Could not add the target. Please try again.");
      return;
    }

    onSaved();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Add Scan Target</span>
          <button onClick={onClose} style={{ color: "var(--text-3)" }}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {error && <div className="auth-error">{error}</div>}

          <div className="form-group">
            <label className="form-label">Target name</label>
            <input
              className="form-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Production Website"
              maxLength={100}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Target URL</label>
            <input
              className="form-input"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="e.g. https://example.com"
              type="url"
              autoComplete="url"
            />
            <div className="form-hint">
              CASPER DEE v1.0 currently performs authorized web URL assessments.
              The scanner analyzes security headers, TLS behavior, and HTML.
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Authorization reference</label>
            <input
              className="form-input"
              value={authDoc}
              onChange={(e) => setAuthDoc(e.target.value)}
              placeholder="e.g. SOW-2026-014 or authorization ticket"
              maxLength={200}
            />
            <div className="form-hint">
              Optional reference to the authorization record. Adding this
              reference does not automatically authorize the target.
            </div>
          </div>

          <div
            style={{
              padding: "12px 14px",
              background: "var(--bg-2)",
              border: "1px solid var(--border-soft)",
              borderRadius: "var(--radius-sm)",
              marginTop: 8,
            }}
          >
            <label className="row gap-8" style={{ cursor: "pointer", alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                style={{ marginTop: 2 }}
              />
              <div>
                <div className="fw-600 text-sm">
                  <ShieldCheck size={14} style={{ color: "var(--success)", marginRight: 6, verticalAlign: "-2px" }} />
                  I confirm that I own or have permission to assess this target.
                </div>
                <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                  By checking this box, you take responsibility for confirming
                  authorization. The target will be marked Authorized immediately
                  and made available for scanning.
                </div>
              </div>
            </label>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={busy || !name.trim() || !value.trim() || !confirmed}
            onClick={save}
          >
            {busy ? <span className="spinner" /> : "Add target"}
          </button>
        </div>
      </div>
    </div>
  );
}
