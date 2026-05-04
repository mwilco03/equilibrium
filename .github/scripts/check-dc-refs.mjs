#!/usr/bin/env node
// Cross-references vendor_detections[*].mapped_data_components and
// detection_strategies[*].data_component_refs against each record's
// declared data_components[*].name. Schema validation alone cannot enforce
// this, since JSON Schema does not express "value must appear in a sibling
// array of objects."
//
// Exits 0 if all references resolve; exits 1 with a per-file report otherwise.

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const TECHNIQUES_DIR = "data/techniques";

const files = (await readdir(TECHNIQUES_DIR)).filter((f) => f.endsWith(".json"));

let failures = 0;

for (const f of files) {
  const path = join(TECHNIQUES_DIR, f);
  const record = JSON.parse(await readFile(path, "utf8"));
  const declared = new Set((record.data_components ?? []).map((dc) => dc.name));

  const issues = [];

  for (const [i, vd] of (record.vendor_detections ?? []).entries()) {
    for (const ref of vd.mapped_data_components ?? []) {
      if (!declared.has(ref)) {
        issues.push(
          `vendor_detections[${i}] (${vd.vendor}) references unknown data component: "${ref}"`,
        );
      }
    }
  }

  for (const [i, ds] of (record.detection_strategies ?? []).entries()) {
    for (const ref of ds.data_component_refs ?? []) {
      if (!declared.has(ref)) {
        issues.push(
          `detection_strategies[${i}] (${ds.id}) references unknown data component: "${ref}"`,
        );
      }
    }
  }

  if (issues.length > 0) {
    failures += 1;
    console.error(`::error file=${path}::${path}: ${issues.length} unresolved data component reference(s)`);
    for (const msg of issues) console.error(`  - ${msg}`);
  } else {
    console.log(`ok ${path}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} file(s) failed cross-reference checks.`);
  process.exit(1);
}
