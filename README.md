# equilibrium

A static, GitHub Pages-hosted SPA that joins three frameworks into one operational surface:

1. **MITRE ATT&CK** techniques, Detection Strategies, and Data Components.
2. **Microsoft Kubernetes Threat Matrix** techniques.
3. **Vendor detection logic** across CNAPP and runtime tools (Wiz, Upwind, Lacework, Sysdig, Snowflake/SQL, CrowdStrike, Prisma Cloud, Orca, Datadog Cloud SIEM).

The problem this project addresses: there is no standardized mapping that takes a Kubernetes-relevant technique from the MS matrix, anchors it on MITRE Data Components, and translates that into actionable, vendor-specific detection logic. Equilibrium models that mapping as data and renders it as a matrix UI.

> **Project name, not a GitHub user.** The repo lives at `github.com/mwilco03/equilibrium` (deploys to `https://mwilco03.github.io/equilibrium/`). The schema `$id` is a `urn:` placeholder until the repo is created.

## Core design principle: Data Components first

Every vendor detection in this repository is anchored to one or more MITRE Data Components, not to a tactic label or a vendor product category. A detection that does not declare which Data Components it satisfies cannot be merged.

The reason: tactic labels and product categories are how vendors organize marketing material. Data Components are the smallest unit of telemetry that an analyst can verify exists in their pipeline. Anchoring on them turns "do we cover Execution?" into "do we have at least one detection per relevant Data Component for every Execution technique we care about?" The matrix UI exposes those gaps directly.

## Repository layout

```
equilibrium/
  schema/
    equilibrium.schema.json     # canonical JSON Schema (Draft 2020-12)
  data/
    techniques/
      T1609.json                # one record per technique (canonical worked example)
    vendors/                    # reserved for vendor metadata files
  spa/                          # Vite + React + TS + Tailwind + Lucide + Orama (scaffold pending)
  docs/                         # design notes
  .github/
    ISSUE_TEMPLATE/             # YAML issue forms for structured submissions
    workflows/                  # CI: schema validation + issue-to-PR automation
    pull_request_template.md
```

## Schema overview

The schema is the single source of truth. It feeds:

- The SPA UI (matrix layout, filters, expandable cells).
- The GitHub Issue Forms (enums become dropdowns).
- The CI validator (every PR is rejected if its `data/techniques/*.json` fails schema validation).

A technique record carries:

| Top-level field | Purpose |
| --- | --- |
| `id` | `EQ-T<id>`, mirrors the anchored MITRE technique. |
| `mitre_attack` | MITRE technique ID, name, tactics, platforms, URL. |
| `microsoft_k8s_matrix` | MS matrix technique name and tactic. |
| `data_components` | First-class objects, the detection contract. |
| `detection_strategies` | MITRE DET#### / AN#### references. |
| `vendor_detections` | Normalized blocks; one per vendor query. Each block names which `data_components` it satisfies. |
| `references`, `tags`, `metadata` | Provenance and classification. |

See `schema/equilibrium.schema.json` for the full definition and `data/techniques/T1609.json` for a populated example.

## Contribution model

Submissions are structured. The more constrained the input form, the more we can absorb without a maintainer rewrite.

1. **Open a GitHub Issue** using one of the templates in `.github/ISSUE_TEMPLATE/`:
   - **New technique mapping** for adding a Microsoft K8s matrix technique that does not exist yet.
   - **Add vendor detection** for adding a query block to an existing technique.
   - **Report mapping error** for incorrect data-component mappings, broken references, or stale queries.
2. The form's typed fields produce a structured issue body. A GitHub Action (in `.github/workflows/`) parses that body and opens a **draft PR** that adds or modifies the appropriate `data/techniques/T<id>.json`.
3. CI validates the PR against the schema. The PR cannot merge until validation passes and a maintainer reviews.
4. On merge, GitHub Pages rebuilds the SPA and the search index automatically.

Direct PRs are welcome too. The same CI gates apply.

## Search

Client-side, build-time-indexed, JSON-native: **Orama** (TypeScript). At CI time, a small build step walks `data/techniques/*.json`, builds an Orama index, and serializes it to a static asset that the SPA fetches on first search. No daemon, no backend.

## Local development

The dev environment runs in a Debian LXC on the Proxmox node `chaos` (project policy: hosts stay pristine, runtimes live in LXCs). The LXC's only job is to run `pnpm dev` and to build the production bundle for verification. It never serves production traffic. Production is GitHub Pages.

Quickstart (after the LXC is provisioned):

```bash
cd spa
pnpm install
pnpm dev          # local dev server with HMR
pnpm build        # produces a static bundle in spa/dist/
pnpm validate     # runs ajv validate over data/techniques/*.json against the schema
```

## Deployment

GitHub Actions builds on every push to `main`:

1. Validate all `data/techniques/*.json` against `schema/equilibrium.schema.json`.
2. Build the Orama search index.
3. Build the SPA with `base: '/equilibrium/'`.
4. Publish to GitHub Pages.

Pretty URLs (e.g., `/equilibrium/techniques/T1609`) are supported via a `404.html` fallback that re-bootstraps the SPA, so deep-link refresh works.

## License

To be decided before the repo is published. Recommended: dual licensing of the data (CC BY 4.0, matching MITRE's licensing posture for ATT&CK derivative work) and the code (Apache-2.0 or MIT).
