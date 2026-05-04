import { Link } from "react-router-dom";
import {
  TACTICS,
  VENDORS,
  type MitreTactic,
  type TechniqueRecord,
  type Vendor,
} from "@/types/equilibrium";

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

// Three-letter vendor abbreviations for the matrix card pills. Keeping the
// mapping centralized so other surfaces (search facets, tooltips) can reuse it.
const VENDOR_ABBR: Record<Vendor, string> = {
  wiz: "WIZ",
  upwind: "UPW",
  lacework: "LCW",
  sysdig: "SDG",
  snowflake: "SNF",
  crowdstrike: "CRD",
  prisma_cloud: "PRC",
  orca: "ORC",
  datadog_cloud_siem: "DDG",
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
        // Phone (default): one tactic per row stacked vertically.
        // Tablet+ (`sm:`): ATT&CK Navigator-style grid, horizontal scroll if
        // the columns exceed the viewport. CSS grid ignores
        // `grid-template-columns` when display isn't grid, so the same node
        // works in both modes.
        className="flex flex-col gap-4 p-3 sm:grid sm:min-w-max sm:gap-2 sm:p-4"
        style={{
          gridTemplateColumns: `repeat(${populated.length}, minmax(220px, 1fr))`,
        }}
      >
        {populated.map((tactic) => (
          <div key={tactic} className="flex flex-col gap-2">
            <div
              className="sticky top-0 z-10 rounded-t bg-zinc-900 px-3 py-2 text-xs font-semibold uppercase tracking-wide"
              style={{ borderBottom: `2px solid var(--tactic-${tactic})` }}
            >
              {TACTIC_LABELS[tactic]}
              <span className="ml-2 text-zinc-500">
                {byTactic.get(tactic)?.length ?? 0}
              </span>
            </div>
            {(byTactic.get(tactic) ?? []).map((t) => (
              <TechniqueCard key={t.id + tactic} t={t} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function TechniqueCard({ t }: { t: TechniqueRecord }) {
  const presentVendors = new Set<Vendor>(
    (t.vendor_detections ?? []).map((vd) => vd.vendor),
  );

  return (
    <Link
      to={`/techniques/${t.mitre_attack.technique_id}`}
      className="rounded border border-zinc-800 bg-zinc-900/60 p-3 text-sm hover:border-cyan-500 hover:bg-zinc-900"
    >
      <div className="font-mono text-xs text-zinc-500">
        {t.mitre_attack.technique_id}
      </div>
      <div className="font-medium">{t.title}</div>
      <div className="mt-1 text-xs text-zinc-400">MS: {t.microsoft_k8s_matrix.name}</div>

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

      <div className="mt-2 flex flex-wrap gap-1" aria-label="Vendor coverage">
        {VENDORS.map((v) => {
          const present = presentVendors.has(v);
          return (
            <span
              key={v}
              title={`${v}: ${present ? "detection present" : "no detection yet"}`}
              className={
                "rounded px-1 py-0.5 text-[9px] font-mono " +
                (present
                  ? "bg-cyan-900/60 text-cyan-200"
                  : "bg-zinc-900/60 text-zinc-600")
              }
            >
              {VENDOR_ABBR[v]}
            </span>
          );
        })}
      </div>
    </Link>
  );
}
