// Loads technique records at runtime via Vite's import.meta.glob so the build
// pulls every JSON under data/techniques/ into the bundle as statically
// discoverable imports. No runtime fetch, no GitHub API rate limits.
//
// Record IDs are now keyed on the Microsoft K8s Threat Matrix technique ID
// (EQ-MS-TA<num>) since multiple MS techniques can map to one MITRE technique
// (e.g., MS-TA9008 New Container, MS-TA9018 Privileged container, and
// MS-TA9011 Sidecar Injection all anchor on T1610). The lookup also accepts
// raw MS-TA ids (without the EQ- prefix) and unique MITRE technique ids for
// backward compatibility on URLs that pre-date the migration.

import type { TechniqueRecord } from "@/types/equilibrium";

const TECHNIQUE_GLOB = import.meta.glob<TechniqueRecord>(
  "../../../data/techniques/*.json",
  { eager: true, import: "default" },
);

export const TECHNIQUES: TechniqueRecord[] = Object.values(TECHNIQUE_GLOB);

const BY_KEY = new Map<string, TechniqueRecord>();
const MITRE_TO_RECORDS = new Map<string, TechniqueRecord[]>();

for (const t of TECHNIQUES) {
  BY_KEY.set(t.id, t);
  // Allow lookup by bare MS-TA id (without the EQ- prefix).
  if (t.microsoft_k8s_matrix.id) {
    BY_KEY.set(t.microsoft_k8s_matrix.id, t);
  }
  if (t.mitre_attack) {
    const mid = t.mitre_attack.technique_id;
    const list = MITRE_TO_RECORDS.get(mid) ?? [];
    list.push(t);
    MITRE_TO_RECORDS.set(mid, list);
    // Only set BY_KEY for unique MITRE ids; ambiguous MITRE keys route to
    // the disambiguation page handled in TechniquePage.
    if (list.length === 1) BY_KEY.set(mid, t);
    else BY_KEY.delete(mid);
  }
}

export function getTechnique(idOrTechniqueId: string): TechniqueRecord | undefined {
  return BY_KEY.get(idOrTechniqueId);
}

export function getTechniquesByMitreId(mitreId: string): TechniqueRecord[] {
  return MITRE_TO_RECORDS.get(mitreId) ?? [];
}
