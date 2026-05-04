# Sysdig

**Slug:** `sysdig`
**Category:** CNAPP / Runtime Security
**Pricing posture:** Subscription-based (SaaS and self-hosted). Free tier: Sysdig Secure has a limited free offering for small environments (Sysdig Open Source Falco is free). Enterprise tiers by workload count. No fully-featured free trial found in public docs.
**Last verified:** 2026-05-04

---

## Product Overview

Sysdig is built on Falco, the open-source CNCF runtime security engine that Sysdig created and donated to the CNCF (now a CNCF graduated project). Sysdig Secure extends Falco with a managed SaaS platform covering:
- Runtime threat detection (container, host, Kubernetes)
- Cloud security posture management (CSPM)
- Identity and access management analysis (CIEM)
- Supply chain security (image scanning, registry analysis, admission control)
- Compliance (PCI DSS, SOC 2, CIS, etc.)

The open-source Falco engine underpins the runtime detection tier. Sysdig ships a commercial managed Falco deployment with a Threat Research Library of pre-built rules plus a full API for custom rule management.

Sources: https://docs.sysdig.com/en/docs/sysdig-secure/ (fetched 2026-05-04), https://docs.sysdig.com/en/docs/sysdig-secure/policies/ (fetched 2026-05-04)

---

## Detection Model

**Falco YAML rules:**
All runtime threat detections are expressed as Falco rules. A Falco rule has:
- `condition`: a boolean expression over event fields (syscall fields, container metadata, process fields, K8s audit fields)
- `output`: a formatted string capturing relevant fields
- `priority`: severity (CRITICAL, WARNING, NOTICE, INFO)
- `source`: the event source (`syscall` or `k8s_audit` or cloud log source)
- `tags`: list including MITRE technique IDs (e.g., `[container, mitre_privilege_escalation, T1611]`)

Rule sources available in Sysdig Secure:
1. **`syscall`**: kernel-level events (process exec, file open/write, network connect, setns, mount, etc.) from the eBPF or kernel module sensor
2. **`k8s_audit`**: Kubernetes API server audit events forwarded via webhook or cloud-managed audit log
3. **AWS CloudTrail** / **Azure Platform Logs** / **GCP Audit Logs**: cloud provider log ingestion
4. **GitHub**, **Okta**: identity and SCM event sources

**SysQL:**
Sysdig introduced SysQL in 2025: a natural-language query interface that translates human queries into structured runtime data queries. This supplements (does not replace) Falco rules.

**Managed rule library:**
Sysdig ships a Falco Reference Library covering:
- Linux workloads (syscall-based)
- Kubernetes Audit (k8s_audit source)
- AWS CloudTrail
- Azure Platform Logs
- GCP Audit Logs
- GitHub, Okta

MITRE ATT\&CK tagging is consistent across all managed rules.

**QUERY_LANGUAGES mapping:**
- `falco_yaml`: the canonical equilibrium enum value for Sysdig rule authoring

Sources: https://docs.sysdig.com/en/docs/sysdig-secure/policies/ (fetched 2026-05-04), https://www.sysdig.com/blog/kubernetes-audit-log-falco (search result), Falco community rules (fetched via gh API 2026-05-04)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Kernel-level process, file, network, syscall events | Sysdig agent (eBPF CO-RE or kernel module) as DaemonSet | DS0009 Process, DS0022 File, DS0029 Network Traffic |
| Kubernetes API server audit logs | Webhook to Sysdig; or cloud-managed audit (EKS CloudWatch, GKE Cloud Audit) | DS0015 Application Log |
| AWS CloudTrail | API integration | DS0015 Application Log |
| Azure Platform Logs | Integration | DS0015 Application Log |
| GCP Audit Logs | Integration | DS0015 Application Log |
| Container image scanning | Registry integration and inline scanner | DS0007 Image |
| GitHub events | Integration | DS0015 Application Log |
| Okta events | Integration | DS0002 User Account |

---

## Container / Kubernetes Coverage Specifically

**Runtime agent:**
Sysdig agent deployed as a DaemonSet on each node. Supports:
- eBPF CO-RE (modern kernels, preferred)
- Kernel module (legacy kernels)
- No-driver mode (limited) for environments where kernel access is restricted

Agent captures every syscall from every container on the node. Container metadata (name, image, namespace, pod, labels) is automatically enriched.

**Kubernetes audit log:**
Falco `k8s_audit` source supports detecting:
- `kubectl exec` / `kubectl attach` (pods/exec subresource)
- Pod creation with privileged or hostPath spec
- Role and ClusterRole binding changes
- Service account token creation

The open-source `falco-incubating_rules.yaml` includes rules tagged T1610 (`Launch Privileged Container`, `Launch Excessively Capable Container`). The official `falco_rules.yaml` includes T1611-tagged rules (`Debugfs Launched in Privileged Container`, `Detect release_agent File Container Escapes`). Sysdig Secure ships these plus additional commercial rules.

**Admission controller:**
Sysdig Secure includes an admission controller for supply chain and vulnerability policy enforcement at deploy time.

Sources: https://docs.sysdig.com/en/docs/sysdig-secure/ (fetched), Falco rule files (fetched via gh API)

---

## Public API Surface

**Base URL pattern:** `https://<region>.app.sysdig.com/api/`
(Regions: `us2`, `us4`, `eu1`, `ap1`, `me1`, etc.)

**Auth model:** Bearer token authentication.
- Header: `Authorization: Bearer <API_TOKEN>`
- Token retrieved from Sysdig Secure UI (Settings > User Profile > API Token)
- Team-Based Service Accounts also supported (2025 addition)

**API capabilities (confirmed from docs and search results):**
- Policies management: CRUD for Falco-based threat detection policies
- Rules management: CRUD for custom Falco rules
- Events/alerts: query security events and signals
- Scanning results: vulnerability and image scan results
- SysQL API: natural-language to structured query (2025)

**Rate limits:** Not documented in public-facing search results.

Sources: https://docs.sysdig.com/en/developer-tools/sysdig-api/ (search result), https://docs.sysdig.com/en/docs/developer-tools/sysdig-rest-api-conventions/ (search result), Sysdig 2025 release notes (search result)

---

## Documentation References

- https://docs.sysdig.com/en/docs/sysdig-secure/ (root Sysdig Secure docs)
- https://docs.sysdig.com/en/docs/sysdig-secure/policies/ (policies overview, fetched)
- https://docs.sysdig.com/en/developer-tools/sysdig-api/ (API reference)
- https://docs.sysdig.com/en/docs/developer-tools/sysdig-rest-api-conventions/ (REST conventions)
- https://docs.sysdig.com/en/developer-tools/managing-access-keys/ (API key management)
- https://docs.sysdig.com/en/sysdig-secure/falco-reference-library/linux-workload/ (Linux workload Falco rules library)
- https://falco.org/docs/ (upstream Falco documentation)
- https://github.com/falcosecurity/rules (community Falco rules, fetched)
- https://www.sysdig.com/blog/kubernetes-audit-log-falco (K8s audit log + Falco tutorial)

---

## Confidence and Gaps

**Confirmed:**
- Detection model is Falco YAML rules
- Event sources: syscall, k8s_audit, cloud provider logs, GitHub, Okta
- eBPF CO-RE and kernel module sensor options
- T1610-tagged incubating Falco rules: `Launch Privileged Container`, `Launch Excessively Capable Container`
- T1611-tagged stable Falco rules: `Debugfs Launched in Privileged Container`, `Detect release_agent File Container Escapes`
- T1611-tagged incubating rules: setns/unshare/mount-based escape detection
- Bearer token auth for API access
- SysQL added in 2025

**Likely:**
- Sysdig Secure ships additional commercial Falco rules beyond the open-source community set, including T1609-specific k8s_audit rules (not found in open-source repo but described in product marketing)
- Policies API allows programmatic management of rules suitable for equilibrium integration

**Unknown / gaps in public docs:**
- Specific API endpoint paths for rules CRUD not confirmed (docs redirect or return empty content for fetched URLs)
- Rate limits not publicly documented
- Whether Sysdig Secure has a formal MITRE ATT\&CK coverage matrix in a machine-readable format is unconfirmed
