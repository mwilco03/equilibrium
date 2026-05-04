import { Link } from "react-router-dom";
import { ExternalLink, Database } from "lucide-react";
import { TECHNIQUES } from "@/lib/data";
import type { TechniqueRecord } from "@/types/equilibrium";

const ATTACK_DATASOURCES_BASE = "https://attack.mitre.org/datasources";

interface AggregatedDC {
  data_source_id: string;
  data_source_name: string;
  name: string;
  url: string;
  references: TechniqueRecord[];
}

function aggregate(): AggregatedDC[] {
  // Key on (data_source_id, data_component_name) so the same component
  // declared independently on multiple techniques merges into one row.
  const map = new Map<string, AggregatedDC>();
  for (const t of TECHNIQUES) {
    for (const dc of t.data_components) {
      const key = `${dc.data_source_id}::${dc.name}`;
      const existing = map.get(key);
      if (existing) {
        existing.references.push(t);
      } else {
        map.set(key, {
          data_source_id: dc.data_source_id,
          data_source_name: dc.data_source_name,
          name: dc.name,
          url: dc.url || `${ATTACK_DATASOURCES_BASE}/${dc.data_source_id}/`,
          references: [t],
        });
      }
    }
  }
  return [...map.values()].sort((a, b) => {
    if (a.data_source_id !== b.data_source_id)
      return a.data_source_id.localeCompare(b.data_source_id);
    return a.name.localeCompare(b.name);
  });
}

export function DataComponentsPage() {
  const rows = aggregate();
  const sourceCount = new Set(rows.map((r) => r.data_source_id)).size;

  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-4 p-4 sm:p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold sm:text-2xl">Data Components</h1>
        <p className="text-sm text-zinc-400">
          The detection contract. Every vendor detection in equilibrium is anchored on at
          least one of these. {rows.length} components across {sourceCount} data sources.
        </p>
      </header>

      <div className="grid gap-3 md:grid-cols-2">
        {rows.map((r) => (
          <article
            key={`${r.data_source_id}-${r.name}`}
            className="flex flex-col gap-2 rounded border border-zinc-800 bg-zinc-900/60 p-3"
          >
            <div className="flex items-center gap-2 text-xs text-zinc-400">
              <Database className="h-3.5 w-3.5" aria-hidden />
              <a
                href={r.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 font-mono hover:text-cyan-400"
              >
                {r.data_source_id}
                <ExternalLink className="h-3 w-3" aria-hidden />
              </a>
              <span>·</span>
              <span>{r.data_source_name}</span>
            </div>
            <div className="font-medium text-zinc-100">{r.name}</div>
            <div>
              <div className="text-xs uppercase tracking-wide text-zinc-500">
                Referenced by
              </div>
              <ul className="mt-1 flex flex-wrap gap-1 text-sm">
                {r.references.map((t) => (
                  <li key={t.id}>
                    <Link
                      to={`/techniques/${t.mitre_attack.technique_id}`}
                      className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-cyan-300 hover:bg-zinc-700"
                    >
                      {t.mitre_attack.technique_id} {t.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
