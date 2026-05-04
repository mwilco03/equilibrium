#!/usr/bin/env node
// Builds a flat array of search documents from data/techniques/*.json and
// writes it to public/search-index.json. The SPA loads that file lazily,
// builds an Orama index in the browser, and runs all search client-side.
// (We could pre-build the Orama index too with @orama/plugin-data-persistence,
//  but the corpus is small enough that a JSON array of docs and a one-time
//  insertMultiple in the browser is simpler and faster to ship.)

import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TECHNIQUES_DIR = resolve(HERE, "..", "..", "data", "techniques");
const OUT_PATH = resolve(HERE, "..", "public", "search-index.json");

const files = (await readdir(TECHNIQUES_DIR)).filter((f) => f.endsWith(".json"));

const docs = [];
for (const f of files) {
  const r = JSON.parse(await readFile(join(TECHNIQUES_DIR, f), "utf8"));
  const queryBlob = (r.vendor_detections ?? [])
    .map((vd) => [vd.title, vd.intent, vd.query].filter(Boolean).join(" \n "))
    .join(" \n--- \n ");

  docs.push({
    id: r.id,
    technique_id: r.mitre_attack.technique_id,
    title: r.title,
    description: r.description,
    tactic: (r.mitre_attack.tactics ?? []).join(","),
    ms_tactic: r.microsoft_k8s_matrix?.tactic ?? "",
    ms_name: r.microsoft_k8s_matrix?.name ?? "",
    vendors: (r.vendor_detections ?? []).map((vd) => vd.vendor),
    data_components: (r.data_components ?? []).map((dc) => dc.name),
    query_blob: queryBlob,
  });
}

await mkdir(dirname(OUT_PATH), { recursive: true });
await writeFile(OUT_PATH, JSON.stringify(docs));
console.log(`Wrote ${OUT_PATH} with ${docs.length} documents.`);
