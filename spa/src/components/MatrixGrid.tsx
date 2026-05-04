import { Link } from "react-router-dom";
import {
  MS_K8S_TACTICS,
  VENDORS,
  type MicrosoftK8sTactic,
  type TechniqueRecord,
  type Vendor,
} from "@/types/equilibrium";

// The matrix is grouped by the Microsoft K8s Threat Matrix tactic, since
// equilibrium is keyed on MS K8s technique IDs and that gives every record
// exactly one column. The MITRE tactic appears as enrichment on the card,
// not as the structural axis.
const MS_K8S_TACTIC_LABELS: Record<MicrosoftK8sTactic, string> = {
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege Esc",
  defense_evasion: "Defense Evasion",
  credential_access: "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  impact: "Impact",
};

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
  const byTactic = new Map<MicrosoftK8sTactic, TechniqueRecord[]>();
  for (const tactic of MS_K8S_TACTICS) byTactic.set(tactic, []);
  for (const t of techniques) {
    byTactic.get(t.microsoft_k8s_matrix.tactic)?.push(t);
  }

  const populated = MS_K8S_TACTICS.filter(
    (tac) => (byTactic.get(tac)?.length ?? 0) > 0,
  );

  return (
    <div className="overflow-x-auto">
      <div
        // Phone (default): one tactic per row stacked vertically.
        // Tablet+ (`sm:`): MS K8s matrix-style grid, horizontal scroll if
        // the columns exceed the viewport.
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
              {MS_K8S_TACTIC_LABELS[tactic]}
              <span className="ml-2 text-zinc-500">
                {byTactic.get(tactic)?.length ?? 0}
              </span>
            </div>
            {(byTactic.get(tactic) ?? []).map((t) => (
              <TechniqueCard key={t.id} t={t} />
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
  const dcCount = t.data_components.length;
  const isStub = dcCount === 0 && (t.vendor_detections ?? []).length === 0;

  return (
    <Link
      to={`/techniques/${t.id}`}
      className={
        "flex flex-col rounded border bg-zinc-900/60 p-3 text-sm hover:bg-zinc-900 " +
        (isStub
          ? "border-dashed border-zinc-700 hover:border-zinc-500"
          : "border-zinc-800 hover:border-cyan-500")
      }
    >
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <span className="font-mono">{t.microsoft_k8s_matrix.id ?? t.id}</span>
        {t.mitre_attack ? (
          <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-400">
            {t.mitre_attack.technique_id}
          </span>
        ) : (
          <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-[10px] text-amber-300">
            no MITRE map
          </span>
        )}
      </div>
      <div className="mt-1 font-medium">{t.title}</div>

      <div className="mt-2 flex flex-wrap gap-1">
        {t.data_components.slice(0, 3).map((dc) => (
          <span
            key={dc.name}
            className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-300"
          >
            {dc.name}
          </span>
        ))}
        {dcCount > 3 ? (
          <span className="text-[10px] text-zinc-500">+{dcCount - 3}</span>
        ) : null}
        {dcCount === 0 ? (
          <span className="text-[10px] italic text-zinc-600">
            no data components yet
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
