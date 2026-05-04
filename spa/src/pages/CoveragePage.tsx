import { Link } from "react-router-dom";
import { CheckCircle2, Circle, AlertCircle } from "lucide-react";
import { TECHNIQUES } from "@/lib/data";
import {
  MS_K8S_TACTICS,
  VENDORS,
  type MicrosoftK8sTactic,
} from "@/types/equilibrium";

const MS_K8S_TACTIC_LABELS: Record<MicrosoftK8sTactic, string> = {
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege Escalation",
  defense_evasion: "Defense Evasion",
  credential_access: "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  impact: "Impact",
};

export function CoveragePage() {
  const total = TECHNIQUES.length;
  const withDC = TECHNIQUES.filter((t) => t.data_components.length > 0).length;
  const withVD = TECHNIQUES.filter(
    (t) => (t.vendor_detections?.length ?? 0) > 0,
  ).length;
  const noMitre = TECHNIQUES.filter((t) => !t.mitre_attack).length;

  // Per-tactic completion: count records that have at least one data component.
  const perTactic = MS_K8S_TACTICS.map((tac) => {
    const inTactic = TECHNIQUES.filter((t) => t.microsoft_k8s_matrix.tactic === tac);
    const filled = inTactic.filter((t) => t.data_components.length > 0).length;
    return { tac, total: inTactic.length, filled };
  }).filter((r) => r.total > 0);

  // Per-vendor: how many techniques each vendor covers.
  const perVendor = VENDORS.map((vendor) => {
    const matched = TECHNIQUES.filter((t) =>
      (t.vendor_detections ?? []).some((vd) => vd.vendor === vendor),
    );
    return { vendor, count: matched.length };
  }).sort((a, b) => b.count - a.count);

  const stubs = TECHNIQUES.filter((t) => t.data_components.length === 0).sort(
    (a, b) =>
      a.microsoft_k8s_matrix.tactic.localeCompare(b.microsoft_k8s_matrix.tactic) ||
      a.title.localeCompare(b.title),
  );

  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-6 p-4 sm:p-6">
      <header>
        <h1 className="text-xl font-semibold sm:text-2xl">Coverage</h1>
        <p className="text-sm text-zinc-400">
          What is filled in across the {total}-technique corpus, by Microsoft K8s
          tactic and by vendor.
        </p>
      </header>

      <section className="grid gap-3 sm:grid-cols-4">
        <Stat label="Techniques" value={total} />
        <Stat
          label="With data components"
          value={`${withDC} / ${total}`}
          tone={withDC === total ? "ok" : "partial"}
        />
        <Stat
          label="With vendor detections"
          value={`${withVD} / ${total}`}
          tone={withVD === total ? "ok" : "partial"}
        />
        <Stat
          label="No MITRE map"
          value={noMitre}
          tone={noMitre > 0 ? "warn" : "ok"}
        />
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold">By tactic</h2>
        <ul className="flex flex-col gap-1 text-sm">
          {perTactic.map((r) => {
            const pct = Math.round((r.filled / r.total) * 100);
            return (
              <li
                key={r.tac}
                className="flex items-center gap-3 rounded border border-zinc-800 bg-zinc-900/60 p-2"
              >
                <span className="w-40 shrink-0 text-zinc-200">
                  {MS_K8S_TACTIC_LABELS[r.tac]}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded bg-zinc-800">
                  <div
                    className="h-full bg-cyan-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-16 shrink-0 text-right font-mono text-xs text-zinc-400">
                  {r.filled} / {r.total}
                </span>
              </li>
            );
          })}
        </ul>
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold">By vendor</h2>
        <ul className="flex flex-col gap-1 text-sm">
          {perVendor.map((r) => (
            <li
              key={r.vendor}
              className="flex items-center gap-3 rounded border border-zinc-800 bg-zinc-900/60 p-2"
            >
              <span className="w-40 shrink-0 font-mono text-zinc-200">
                {r.vendor}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded bg-zinc-800">
                <div
                  className="h-full bg-cyan-500"
                  style={{ width: `${(r.count / total) * 100}%` }}
                />
              </div>
              <span className="w-16 shrink-0 text-right font-mono text-xs text-zinc-400">
                {r.count} / {total}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold">
          Stubs awaiting authoring ({stubs.length})
        </h2>
        <p className="mb-2 text-sm text-zinc-400">
          Records with no Data Components yet. The next research-and-authoring
          batch should target these in tactic-grouped passes.
        </p>
        <ul className="grid gap-2 md:grid-cols-2">
          {stubs.map((t) => (
            <li
              key={t.id}
              className="rounded border border-dashed border-zinc-700 bg-zinc-900/40 p-2 hover:border-zinc-500"
            >
              <Link to={`/techniques/${t.id}`} className="block">
                <div className="flex items-center gap-2 text-xs text-zinc-500">
                  <span className="font-mono">{t.microsoft_k8s_matrix.id}</span>
                  <span>·</span>
                  <span>{MS_K8S_TACTIC_LABELS[t.microsoft_k8s_matrix.tactic]}</span>
                  {!t.mitre_attack ? (
                    <span className="ml-auto text-amber-400">no MITRE</span>
                  ) : (
                    <span className="ml-auto font-mono text-zinc-400">
                      {t.mitre_attack.technique_id}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 text-zinc-200">{t.title}</div>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "ok" | "warn" | "partial";
}) {
  const Icon =
    tone === "ok" ? CheckCircle2 : tone === "warn" ? AlertCircle : Circle;
  const iconClass =
    tone === "ok"
      ? "text-emerald-400"
      : tone === "warn"
      ? "text-amber-400"
      : tone === "partial"
      ? "text-cyan-400"
      : "text-zinc-500";
  return (
    <div className="rounded border border-zinc-800 bg-zinc-900/60 p-3">
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="mt-1 flex items-center gap-2">
        <Icon className={`h-5 w-5 ${iconClass}`} aria-hidden />
        <span className="text-xl font-semibold">{value}</span>
      </div>
    </div>
  );
}
