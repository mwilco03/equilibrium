# Upwind

**Slug:** `upwind`
**Category:** CNAPP (Cloud Native Application Protection Platform) -- runtime-first
**Pricing posture:** Enterprise-only; no public pricing or free tier. Demo required.
**Last verified:** 2026-05-04

---

## Product Overview

Upwind Security is a CNAPP vendor built around an "inside-out" philosophy: rather than scanning cloud configuration from the outside, Upwind deploys a lightweight eBPF sensor that observes actual runtime behavior and enriches that signal with cloud context. The platform covers Build, Run, and Protect phases.

Key differentiators per public marketing: eBPF sensor with claimed "95% noise reduction" via runtime-context filtering, and integration of runtime observations with cloud API data (IAM, network exposure, CVEs) in a graph-based query model called **Upwind Explorer**.

Sources: https://www.upwind.io/ (fetched 2026-05-04), https://docs.upwind.io/public/introduction/concepts/upwind-architecture/sensors (fetched 2026-05-04)

---

## Detection Model

Upwind's detection model is runtime-behavioral. The eBPF sensor captures kernel-level events (process spawns, syscalls, file I/O, network connections), then applies behavioral baselining to identify deviations. Custom policies can be scoped to specific workloads.

**Custom policy / query interface:**
The Upwind Explorer allows custom queries using either a visual query builder or **Rego** (the Open Policy Agent policy language). This is the publicly documented path for custom rule authoring. Rego policies operate over Upwind's dataset: CVE data, container behavior, process lineage, IAM bindings, network exposure.

**Detection categories:**
- Container escapes (runtime)
- Privilege escalation
- Anomalous network connections
- Drift (binary not in base image)
- API threat detection (runtime API traffic analysis)
- Zero-trust network enforcement at kernel level

The proprietary runtime detection rule language (for the sensor's built-in detection engine, not the Explorer) is not publicly specified. Equilibrium labels this `ebpf_dsl` as the closest approximation.

**QUERY_LANGUAGES mapping:**
- `ebpf_dsl`: for the sensor-level runtime detection rules
- Rego is the documented custom policy language (not currently in the equilibrium QUERY_LANGUAGES enum)

Sources: https://docs.upwind.io/public/introduction/concepts/upwind-architecture/sensors (fetched 2026-05-04), https://www.upwind.io/feed/from-query-to-policy-enforcing-real-time-cloud-compliance-with-upwind-explorer (search result), https://www.upwind.io/feed/enhance-your-threat-detection-capabilities-with-custom-policy-scope (search result)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Process execution (in containers and hosts) | Upwind Sensor (eBPF DaemonSet) | DS0009 Process |
| System calls | Upwind Sensor (eBPF) | DS0009 Process |
| File I/O (in containers) | Upwind Sensor (eBPF) | DS0022 File |
| Network connections (container and host) | Upwind Sensor (eBPF) | DS0029 Network Traffic |
| Kubernetes API server audit logs | Upwind K8s audit enrichment (when enabled) | DS0015 Application Log |
| Cloud provider APIs (IAM, resource inventory) | Cloud API integration | DS0002 User Account |
| Container image SBOMs / vulnerability data | Scanner component (sidecar or scan job) | DS0007 Image |

---

## Container / Kubernetes Coverage Specifically

**Sensor architecture in Kubernetes:**
- **Sensor DaemonSet**: runs on every node, collects kernel-level activity from all containers
- **Cluster Manager**: centralized proxy for cluster metadata, reduces API server load
- **Scanner**: generates SBOMs for vulnerability detection
- **Operator**: manages deployment and configuration

**Security properties of the sensor:**
- Runs as user-mode process (not kernel module)
- No privileged access to the Upwind SaaS plane
- Mutual certificate-based authentication; communication is unidirectional (sensor to Upwind SaaS only)

**Coverage:**
- Runtime process monitoring with container and Kubernetes workload identity enrichment
- Kubernetes audit log enrichment: when enabled, runtime process events carry the originating API principal (who initiated the kubectl exec that caused the process)
- Container escape detection (namespace transitions, host-mount writes)
- Admission-time visibility (via Kubernetes API integration)

Sources: https://docs.upwind.io/public/introduction/concepts/upwind-architecture/sensors (fetched 2026-05-04), https://www.upwind.io/glossary/what-is-ebpf-security (search result), https://www.upwind.io/feed/how-upwind-uses-ebpf-to-bring-real-time-security-to-cloud-native-environments (search result)

---

## Public API Surface

The Upwind Documentation Center requires login to access API documentation. From public search results:
- An Upwind Explorer query API exists (used to build custom queries and policies)
- API token or OAuth-based authentication is implied but not specified in public documentation

**Confirmed gap:** No public API reference documentation was accessible without authentication as of 2026-05-04. This is a documented limitation.

---

## Documentation References

- https://docs.upwind.io/public/introduction/concepts/upwind-architecture/sensors (sensor architecture, fetched)
- https://www.upwind.io/glossary/what-is-ebpf-security (eBPF overview)
- https://www.upwind.io/feed/how-upwind-uses-ebpf-to-bring-real-time-security-to-cloud-native-environments (eBPF runtime security blog)
- https://www.upwind.io/feed/automate-threat-detection-response-for-kubernetes-workloads (K8s threat detection)
- https://www.upwind.io/feed/from-query-to-policy-enforcing-real-time-cloud-compliance-with-upwind-explorer (Explorer/Rego)
- https://www.upwind.io/feed/enhance-your-threat-detection-capabilities-with-custom-policy-scope (custom policy scoping)
- https://www.upwind.io/glossary/kubernetes-api-security (K8s API security)

---

## Confidence and Gaps

**Confirmed:**
- eBPF sensor deployed as DaemonSet on Kubernetes nodes
- Sensor collects process, syscall, file I/O, and network events
- Cluster Manager, Scanner, and Operator are additional Kubernetes components
- Sensor uses mutual TLS; unidirectional communication to SaaS
- Custom policies can be authored in Rego via the Upwind Explorer

**Likely:**
- Kubernetes audit log ingestion exists and is used to enrich process events with API principal identity (described in equilibrium's vendor detection for T1609)
- Container escape detection and drift detection are built-in capabilities

**Unknown / gaps in public docs:**
- Exact eBPF rule/DSL format for built-in detections is not publicly specified
- Public API reference is login-gated; no endpoint list, auth model, or rate limits confirmed
- Pricing: enterprise-only, no public information
- Whether Upwind has out-of-the-box MITRE ATT\&CK coverage mapping is unconfirmed (no public MITRE coverage matrix found)
