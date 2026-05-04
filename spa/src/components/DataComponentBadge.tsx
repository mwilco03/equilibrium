import type { DataComponent } from "@/types/equilibrium";
import { Database, ExternalLink } from "lucide-react";

const ATTACK_DATASOURCES_BASE = "https://attack.mitre.org/datasources";

export function DataComponentBadge({ dc }: { dc: DataComponent }) {
  const dsHref = dc.url || `${ATTACK_DATASOURCES_BASE}/${dc.data_source_id}/`;
  return (
    <div className="flex flex-col gap-1 rounded border border-zinc-800 bg-zinc-900/60 p-3">
      <div className="flex items-center gap-2 text-xs text-zinc-400">
        <Database className="h-3.5 w-3.5" aria-hidden />
        <a
          href={dsHref}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 font-mono hover:text-cyan-400"
        >
          {dc.data_source_id}
          <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
        <span>·</span>
        <span>{dc.data_source_name}</span>
      </div>
      <div className="font-medium text-zinc-100">{dc.name}</div>
      {dc.definition ? (
        <div className="text-sm text-zinc-400">{dc.definition}</div>
      ) : null}
      {dc.relevant_events && dc.relevant_events.length > 0 ? (
        <ul className="mt-1 list-disc pl-5 text-sm text-zinc-300">
          {dc.relevant_events.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
