import type { Severity, FindingStatus } from "../lib/types";
import { CheckCircle2, Clock, AlertCircle, CircleDot } from "lucide-react";

export function severityBadge(sev: Severity) {
  const cls = `badge badge-${sev === "informational" ? "info" : sev}`;
  return <span className={cls}>{sev}</span>;
}

export function statusBadge(status: FindingStatus) {
  const map: Record<FindingStatus, { cls: string; icon: typeof Clock; label: string }> = {
    open: { cls: "badge badge-neutral", icon: AlertCircle, label: "Open" },
    in_progress: { cls: "badge badge-warning", icon: Clock, label: "In Progress" },
    resolved: { cls: "badge badge-success", icon: CheckCircle2, label: "Resolved" },
    accepted: { cls: "badge badge-info", icon: CircleDot, label: "Accepted" },
  };
  const { cls, icon: Icon, label } = map[status];
  return <span className={cls}><Icon size={10} /> {label}</span>;
}

export function riskColor(score: number): string {
  if (score >= 75) return "var(--critical)";
  if (score >= 50) return "var(--high)";
  if (score >= 25) return "var(--medium)";
  return "var(--success)";
}
