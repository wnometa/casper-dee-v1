import type { View } from "../Sidebar";
import { Construction, ArrowRight } from "lucide-react";
import { useWorkspace } from "../../lib/workspace";

interface PlaceholderViewProps {
  view: View;
  title: string;
  description: string;
  v2Features?: string[];
}

export function PlaceholderView({ title, description, v2Features }: PlaceholderViewProps) {
  const { organization } = useWorkspace();
  return (
    <div className="fade-in">
      <div className="placeholder-hero">
        <div className="placeholder-icon">
          <Construction size={32} />
        </div>
        <h2 className="placeholder-title">{title}</h2>
        <p className="placeholder-desc">{description}</p>

        {v2Features && v2Features.length > 0 && (
          <div className="placeholder-v2">
            <div className="placeholder-v2-label">PLANNED FOR V2</div>
            <ul>
              {v2Features.map((f, i) => (
                <li key={i}><ArrowRight size={12} /> {f}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="placeholder-org">
          Workspace: {organization?.name ?? "—"}
        </div>
      </div>
    </div>
  );
}
