import { Link } from "react-router-dom";
import { TACTICS, type MitreTactic, type TechniqueRecord } from "@/types/equilibrium";

const TACTIC_LABELS: Record<MitreTactic, string> = {
  reconnaissance: "Reconnaissance",
  resource_development: "Resource Dev",
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege Esc",
  defense_evasion: "Defense Evasion",
  credential_access: "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  command_and_control: "C2",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

interface Props {
  techniques: TechniqueRecord[];
}

export function MatrixGrid({ techniques }: Props) {
  // Group techniques by primary MITRE tactic. A technique that lists multiple
  // tactics appears in each column (mirrors ATT&CK Navigator behavior).
  const byTactic = new Map<MitreTactic, TechniqueRecord[]>();
  for (const tactic of TACTICS) byTactic.set(tactic, []);
  for (const t of techniques) {
    for (const tactic of t.mitre_attack.tactics) {
      byTactic.get(tactic)?.push(t);
    }
  }

  // Hide empty tactics so a small dataset does not render a wall of empty
  // columns. As the dataset grows this becomes a no-op.
  const populated = TACTICS.filter((tac) => (byTactic.get(tac)?.length ?? 0) > 0);

  return (
    <div className="overflow-x-auto">
      <div
        className="grid min-w-max gap-2 p-4"
        style={{ gridTemplateColumns: `repeat(${populated.length}, minmax(220px, 1fr))` }}
      >
        {populated.map((tactic) => (
          <div key={tactic} className="flex flex-col gap-2">
            <div
              className="rounded-t bg-zinc-900 px-3 py-2 text-xs font-semibold uppercase tracking-wide"
              style={{ borderBottom: `2px solid var(--tactic-${tactic}, #71717a)` }}
            >
              {TACTIC_LABELS[tactic]}
            </div>
            {(byTactic.get(tactic) ?? []).map((t) => (
              <Link
                key={t.id + tactic}
                to={`/techniques/${t.mitre_attack.technique_id}`}
                className="rounded border border-zinc-800 bg-zinc-900/60 p-3 text-sm hover:border-cyan-500 hover:bg-zinc-900"
              >
                <div className="font-mono text-xs text-zinc-500">
                  {t.mitre_attack.technique_id}
                </div>
                <div className="font-medium">{t.title}</div>
                <div className="mt-1 text-xs text-zinc-400">
                  MS: {t.microsoft_k8s_matrix.name}
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {t.data_components.slice(0, 3).map((dc) => (
                    <span
                      key={dc.name}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-300"
                    >
                      {dc.name}
                    </span>
                  ))}
                  {t.data_components.length > 3 ? (
                    <span className="text-[10px] text-zinc-500">
                      +{t.data_components.length - 3}
                    </span>
                  ) : null}
                </div>
              </Link>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
