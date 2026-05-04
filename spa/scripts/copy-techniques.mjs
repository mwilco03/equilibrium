#!/usr/bin/env node
// Copies the schema and a manifest of technique files into spa/public/ so the
// deployed site can deep-link "Edit on GitHub" / "View raw" without a backend.
// Vite already bundles the JSON content via import.meta.glob in lib/data.ts,
// so this is metadata only, not the data path.

import { copyFile, mkdir, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SRC = resolve(HERE, "..", "..", "schema", "equilibrium.schema.json");
const TECHNIQUES_DIR = resolve(HERE, "..", "..", "data", "techniques");
const OUT_DIR = resolve(HERE, "..", "public", "data");

await mkdir(OUT_DIR, { recursive: true });
await copyFile(SCHEMA_SRC, join(OUT_DIR, "equilibrium.schema.json"));

const files = (await readdir(TECHNIQUES_DIR)).filter((f) => f.endsWith(".json"));
await writeFile(
  join(OUT_DIR, "manifest.json"),
  JSON.stringify({ techniques: files.sort() }, null, 2),
);

console.log(`Copied schema + manifest of ${files.length} techniques to ${OUT_DIR}`);
