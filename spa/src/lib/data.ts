// Loads technique records at runtime. We use Vite's import.meta.glob so the
// build pulls every JSON file under data/techniques/ into the bundle as
// statically discoverable imports. No runtime fetch, no GitHub API rate limits.
//
// The path is relative to this file (spa/src/lib/data.ts) so it crosses
// up to the repo root and into data/techniques/.

import type { TechniqueRecord } from "@/types/equilibrium";

const TECHNIQUE_GLOB = import.meta.glob<TechniqueRecord>(
  "../../../data/techniques/*.json",
  { eager: true, import: "default" },
);

export const TECHNIQUES: TechniqueRecord[] = Object.values(TECHNIQUE_GLOB);

const BY_ID = new Map<string, TechniqueRecord>();
for (const t of TECHNIQUES) {
  BY_ID.set(t.id, t);
  BY_ID.set(t.mitre_attack.technique_id, t);
}

export function getTechnique(idOrTechniqueId: string): TechniqueRecord | undefined {
  return BY_ID.get(idOrTechniqueId);
}
