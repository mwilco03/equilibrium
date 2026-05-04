import { Link, useParams } from "react-router-dom";
import { ExternalLink, ArrowLeft } from "lucide-react";
import { getTechnique, getTechniquesByMitreId } from "@/lib/data";
import { DataComponentBadge } from "@/components/DataComponentBadge";
import { VendorDetectionBlock } from "@/components/VendorDetectionBlock";
import type { TechniqueRecord } from "@/types/equilibrium";

const REPO_DATA_PATH = "https://github.com/mwilco03/equilibrium/blob/main/data/techniques";

export function TechniquePage() {
  const { techniqueId } = useParams();
  const t = techniqueId ? getTechnique(techniqueId) : undefined;

  // Disambiguation: a MITRE ID like T1610 maps to multiple equilibrium
  // records (New Container, Privileged container, Sidecar Injection). Show
  // a list page in that case rather than a single record.
  if (!t && techniqueId) {
    const matches = getTechniquesByMitreId(techniqueId);
    if (matches.length > 1) {
      return <Disambiguation mitreId={techniqueId} matches={matches} />;
    }
  }

  if (!t) {
    return (
      <div className="p-6">
        <Link to="/" className="text-cyan-400 hover:underline">
          &larr; back to matrix
        </Link>
        <div className="mt-4 text-zinc-300">
          Technique <code className="font-mono">{techniqueId}</code> not found.
        </div>
      </div>
    );
  }

  const editUrl = `${REPO_DATA_PATH}/${t.microsoft_k8s_matrix.id ?? t.id}.json`;
  const isStub =
    t.data_components.length === 0 &&
    (t.vendor_detections ?? []).length === 0;

  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-6 p-4 sm:p-6">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <Link to="/" className="flex items-center gap-1 text-cyan-400 hover:underline">
          <ArrowLeft className="h-4 w-4" aria-hidden />
          matrix
        </Link>
        <span className="text-zinc-600">/</span>
        <span className="font-mono text-zinc-400">
          {t.microsoft_k8s_matrix.id ?? t.id}
        </span>
        {t.mitre_attack ? (
          <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-300">
            MITRE {t.mitre_attack.technique_id}
          </span>
        ) : (
          <span className="rounded bg-amber-900/40 px-2 py-0.5 text-xs text-amber-300">
            no MITRE mapping
          </span>
        )}
      </div>

      <header className="flex flex-col gap-2">
        <h1 className="text-xl font-semibold sm:text-2xl">{t.title}</h1>
        <p className="text-zinc-300">{t.description}</p>
        {isStub ? (
          <div className="rounded border border-amber-900/60 bg-amber-950/30 p-3 text-sm text-amber-200">
            <strong>Stub record.</strong> Data components, detection strategies,
            and vendor detections have not been authored yet. Open an issue to
            contribute the missing pieces.
          </div>
        ) : null}
        <div className="flex flex-wrap gap-3 pt-2 text-sm">
          {t.mitre_attack ? (
            <ExternalAnchor
              href={t.mitre_attack.url}
              label={`MITRE ATT&CK ${t.mitre_attack.technique_id}`}
            />
          ) : null}
          {t.microsoft_k8s_matrix.url ? (
            <ExternalAnchor
              href={t.microsoft_k8s_matrix.url}
              label={`MS K8s: ${t.microsoft_k8s_matrix.name}`}
            />
          ) : null}
          <a
            href={editUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-zinc-400 hover:text-zinc-100"
          >
            Edit on GitHub <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          </a>
        </div>
      </header>

      <section>
        <h2 className="mb-3 text-lg font-semibold">Data components</h2>
        {t.data_components.length === 0 ? (
          <div className="rounded border border-dashed border-zinc-800 p-4 text-zinc-500">
            None yet. Open a "Report mapping error" issue with proposed Data
            Components for this technique.
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {t.data_components.map((dc) => (
              <DataComponentBadge key={dc.name} dc={dc} />
            ))}
          </div>
        )}
      </section>

      {t.detection_strategies && t.detection_strategies.length > 0 ? (
        <section>
          <h2 className="mb-3 text-lg font-semibold">Detection strategies</h2>
          <ul className="flex flex-col gap-2">
            {t.detection_strategies.map((ds) => (
              <li
                key={ds.id}
                className="rounded border border-zinc-800 bg-zinc-900/60 p-3"
              >
                <div className="flex items-center gap-2">
                  {ds.url ? (
                    <a
                      href={ds.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 font-mono text-xs text-cyan-400 hover:underline"
                    >
                      {ds.id}
                      <ExternalLink className="h-3 w-3" aria-hidden />
                    </a>
                  ) : (
                    <span className="font-mono text-xs text-zinc-400">{ds.id}</span>
                  )}
                  <span className="font-medium">{ds.name}</span>
                </div>
                {ds.summary ? (
                  <div className="mt-1 text-sm text-zinc-300">{ds.summary}</div>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section>
        <h2 className="mb-3 text-lg font-semibold">Vendor detections</h2>
        <div className="flex flex-col gap-2">
          {(t.vendor_detections ?? []).map((vd, i) => (
            <VendorDetectionBlock key={`${vd.vendor}-${i}`} vd={vd} />
          ))}
          {!t.vendor_detections || t.vendor_detections.length === 0 ? (
            <div className="rounded border border-dashed border-zinc-800 p-4 text-zinc-500">
              No vendor detections yet. Open an "Add vendor detection" issue to contribute one.
            </div>
          ) : null}
        </div>
      </section>

      {t.references && t.references.length > 0 ? (
        <section>
          <h2 className="mb-3 text-lg font-semibold">References</h2>
          <ul className="flex flex-col gap-1 text-sm">
            {t.references.map((url) => (
              <li key={url}>
                <ExternalAnchor href={url} label={url} />
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function ExternalAnchor({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-1 break-all text-cyan-400 hover:underline"
    >
      {label}
      <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden />
    </a>
  );
}

function Disambiguation({
  mitreId,
  matches,
}: {
  mitreId: string;
  matches: TechniqueRecord[];
}) {
  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-4 p-4 sm:p-6">
      <Link to="/" className="text-cyan-400 hover:underline">
        &larr; back to matrix
      </Link>
      <h1 className="text-xl font-semibold sm:text-2xl">
        MITRE {mitreId} — {matches.length} equilibrium records
      </h1>
      <p className="text-zinc-400">
        The Microsoft K8s Threat Matrix has multiple distinct techniques that
        anchor on this MITRE ID. Pick the specific record:
      </p>
      <ul className="flex flex-col gap-2">
        {matches.map((m) => (
          <li key={m.id}>
            <Link
              to={`/techniques/${m.id}`}
              className="block rounded border border-zinc-800 bg-zinc-900/60 p-3 hover:border-cyan-500"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-zinc-500">
                  {m.microsoft_k8s_matrix.id ?? m.id}
                </span>
                <span className="font-medium">{m.title}</span>
              </div>
              <div className="mt-1 text-sm text-zinc-400">{m.description}</div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
