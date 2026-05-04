#!/usr/bin/env node
// Parses a GitHub Issue Forms-rendered issue body into either a new
// data/techniques/T<id>.json file or a patch against an existing one.
//
// Issue Forms render each field as:
//
//   ### <Field Label>
//
//   <value>
//
// We split on "### " and key by label. Two submission flavors are handled,
// keyed off labels set by the issue templates:
//
//   submission:technique  -> create a new technique record
//   submission:detection  -> append a vendor_detections[] block to an existing record

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const TECHNIQUES_DIR = "data/techniques";
const ISO_TODAY = new Date().toISOString().slice(0, 10);

const labels = JSON.parse(process.env.ISSUE_LABELS ?? "[]").map((l) => l.name);
const body = process.env.ISSUE_BODY ?? "";

const fields = parseIssueBody(body);

if (labels.includes("submission:technique")) {
  writeNewTechnique(fields);
} else if (labels.includes("submission:detection")) {
  appendVendorDetection(fields);
} else {
  console.log("No actionable submission label; skipping.");
}

// ---------------------------------------------------------------------------

function parseIssueBody(text) {
  const out = {};
  const sections = text.split(/^### +/m).slice(1);
  for (const section of sections) {
    const newline = section.indexOf("\n");
    const label = section.slice(0, newline).trim();
    const value = section.slice(newline + 1).trim();
    out[label] = value === "_No response_" ? "" : value;
  }
  return out;
}

function lines(value) {
  return (value ?? "")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function dataComponentsFromLines(value) {
  return lines(value).map((line) => {
    const [ds_id, ds_name, dc_name] = line.split("|").map((s) => s.trim());
    return {
      id: null,
      name: dc_name,
      data_source_id: ds_id,
      data_source_name: ds_name,
      definition: "",
      url: ds_id ? `https://attack.mitre.org/datasources/${ds_id}/` : null,
      relevant_events: [],
    };
  });
}

function detectionStrategiesFromLines(value) {
  return lines(value).map((line) => {
    const [id, name] = line.split("|").map((s) => s.trim());
    return {
      id,
      name: name ?? "",
      summary: "",
      url: "https://attack.mitre.org/",
      data_component_refs: [],
    };
  });
}

function writeNewTechnique(f) {
  const techniqueId = (f["MITRE technique ID"] || "").trim();
  if (!/^T\d{4}(\.\d{3})?$/.test(techniqueId)) {
    fail(`Invalid MITRE technique ID: "${techniqueId}"`);
  }
  const baseId = techniqueId.split(".")[0];
  const path = join(TECHNIQUES_DIR, `${techniqueId}.json`);

  const record = {
    id: `EQ-${techniqueId}`,
    title: f["MITRE technique name"],
    description: f["Description"],
    tags: [],
    mitre_attack: {
      technique_id: techniqueId,
      name: f["MITRE technique name"],
      tactics: [f["MITRE tactic"]],
      sub_technique_of: techniqueId.includes(".") ? baseId : null,
      platforms: ["Containers"],
      url: `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`,
    },
    microsoft_k8s_matrix: {
      id: null,
      name: f["Microsoft Kubernetes Threat Matrix technique name"],
      tactic: f["Microsoft Kubernetes matrix tactic"],
      url: f["Microsoft Kubernetes matrix URL"],
      description: "",
    },
    data_components: dataComponentsFromLines(f["Data Components (one per line)"]),
    detection_strategies: detectionStrategiesFromLines(f["Detection Strategies (one per line, optional)"]),
    vendor_detections: [],
    references: lines(f["References"]),
    metadata: {
      version: "0.1.0",
      schema_version: "0.1.0",
      created: ISO_TODAY,
      updated: ISO_TODAY,
      contributors: [`issue-${process.env.ISSUE_NUMBER}`],
    },
  };

  mkdirSync(TECHNIQUES_DIR, { recursive: true });
  writeFileSync(path, JSON.stringify(record, null, 2) + "\n");
  console.log(`Wrote ${path}`);
}

function appendVendorDetection(f) {
  const targetRaw = (f["Target technique ID"] || "").trim();
  const techniqueId = targetRaw.startsWith("EQ-") ? targetRaw.slice(3) : targetRaw;
  const path = join(TECHNIQUES_DIR, `${techniqueId}.json`);

  if (!existsSync(path)) {
    fail(`No existing record at ${path}. File a "New technique mapping" first.`);
  }

  const record = JSON.parse(readFileSync(path, "utf8"));
  record.vendor_detections.push({
    vendor: f["Vendor"],
    language: f["Query language"],
    title: f["Detection title"],
    intent: f["Intent"],
    query: f["Query"],
    required_telemetry: lines(f["Required telemetry (one per line)"]),
    mapped_data_components: lines(f["Mapped Data Components (one per line)"]),
    confidence: f["Confidence"],
    false_positive_considerations: f["False-positive considerations"] || "",
    limitations: f["Limitations"] || "",
    references: lines(f["References (one URL per line)"]),
  });
  record.metadata.updated = ISO_TODAY;

  writeFileSync(path, JSON.stringify(record, null, 2) + "\n");
  console.log(`Appended vendor detection to ${path}`);
}

function fail(msg) {
  console.error(`::error::${msg}`);
  process.exit(1);
}
