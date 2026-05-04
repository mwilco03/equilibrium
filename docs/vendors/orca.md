# Orca Security

**Slug:** `orca`
**Category:** CNAPP (agentless-first)
**Pricing posture:** Enterprise-only; no public pricing or self-service free tier. Demo required.
**Last verified:** 2026-05-04

---

## Product Overview

Orca Security is a CNAPP built around **SideScanning**, a patented agentless technology that reads workload data from runtime block storage out-of-band without requiring agents on the workloads themselves. The platform provides CSPM, CWPP, vulnerability management, CIEM, and CDR (Cloud Detection and Response).

In 2023-2024, Orca introduced the **Orca Sensor**: an optional lightweight eBPF-based agent for Kubernetes clusters, VMs, and ECS that provides runtime behavioral visibility, complementing the agentless SideScanning base.

Orca covers AWS, Azure, GCP, OCI, AliCloud, and Kubernetes.

Sources: https://orca.security/platform/agentless-sidescanning/ (search result), https://orca.security/resources/blog/meet-orca-sensor/ (fetched 2026-05-04), https://orca.security/platform/container-and-kubernetes-security/ (fetched 2026-05-04)

---

## Detection Model

**Agentless SideScanning (posture + vulnerability):**
Reads block storage out-of-band to reconstruct the workload's file system state. Detects:
- Known CVEs in installed packages
- Malware (signature-based, file scanning)
- Misconfigurations in cloud resources and Kubernetes configurations
- IAM risks, sensitive data exposure
- Lateral movement paths (via Security Graph context)

SideScanning does NOT see live process execution, memory, or network connections.

**Orca Sensor (runtime behavioral detection):**
eBPF-based sensor deployed in Kubernetes, VMs, and ECS. Provides:
- Runtime process monitoring
- File activity monitoring
- DNS activity monitoring
- Network connection monitoring

Current built-in detection coverage: **30+ runtime detections** covering DNS, files, networks, and processes, including:
- Malware execution
- Malicious domain/IP connections
- Binary drift (executing binary not in base image)
- Webshell execution
- Fileless attacks (memory persistence and execution)
- Prevention capabilities (block specific threats)

Detection policies are described as "built-in and customizable." The specific rule language is not publicly documented (proprietary, not an open DSL).

**Query model:**
Orca provides a "Unified Data Model" for querying the entire environment. Public documentation references a GraphQL API and an AI-powered natural-language query interface. No formal SQL or DSL syntax is publicly specified.

**QUERY_LANGUAGES mapping:**
- `graphql`: for Orca's API-based query interface
- `json_rule`: possible if Orca's detection policies are JSON-based (unconfirmed)

Sources: https://orca.security/resources/blog/meet-orca-sensor/ (fetched 2026-05-04), https://orca.security/resources/blog/new-runtime-detections-in-orca-sensor/ (search result), https://orca.security/platform/container-and-kubernetes-security/ (fetched 2026-05-04)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Workload file system state (OS, apps, data) | SideScanning (out-of-band block storage read) | DS0007 Image, DS0022 File |
| Cloud resource configuration | Cloud provider APIs (agentless) | DS0015 Application Log |
| Runtime processes (in containers/VMs) | Orca Sensor (eBPF) | DS0009 Process |
| Runtime file activity | Orca Sensor (eBPF) | DS0022 File |
| Runtime DNS activity | Orca Sensor (eBPF) | DS0029 Network Traffic |
| Runtime network connections | Orca Sensor (eBPF) | DS0029 Network Traffic |
| Container image layers | SideScanning + registry integration | DS0007 Image |
| Kubernetes resource configuration | Cloud provider K8s API + SideScanning | DS0032 Container |

**Note:** Orca does NOT natively ingest Kubernetes API server audit logs as a distinct data source (unconfirmed; no reference found in public docs). Detection over audit-log-specific signals (e.g., T1609 exec events by principal) is likely not available without a separate audit log integration.

---

## Container / Kubernetes Coverage Specifically

**Agentless (SideScanning):**
- Full cluster asset discovery (deployments, pods, services, RBAC)
- Kubernetes misconfiguration detection (KSPM)
- Container image vulnerability scanning (in running clusters and registries)
- Identifies sensitive data in volumes

**Runtime (Orca Sensor, optional):**
- Deploys as DaemonSet in Kubernetes clusters, or as an agent on VMs/ECS
- eBPF-based: kernel-level visibility into process, file, DNS, and network activity
- Binary drift detection: alerts when a binary executes that was not in the container's base image
- 30+ built-in detection rules for runtime threats
- Local detection and decision-making (resilient to network loss)
- Automatic updates with minimal operator overhead

**Relationship between agentless and runtime:**
Orca describes the combination as "agentless-first + optional sensor." SideScanning provides the baseline posture and vulnerability signal. The Sensor adds live behavioral monitoring that SideScanning cannot provide (processes, memory, network connections at runtime).

Sources: https://orca.security/resources/blog/meet-orca-sensor/ (fetched), https://orca.security/platform/container-and-kubernetes-security/ (fetched), https://orca.security/platform/agentless-sidescanning/ (search result)

---

## Public API Surface

From search results and the apitracker.io entry:
- **API type:** REST and GraphQL (GraphQL Playground available)
- **Auth:** API key (documented at docs.orcasecurity.io, which redirected to region-selection during this session)
- **Rate limits:** Not confirmed from public sources
- **Capabilities:** Query findings, assets, alerts; manage rules; webhook configuration

GraphQL Playground is documented at docs.orcasecurity.io (access requires region selection).

Sources: https://apitracker.io/a/orca-security (search result), https://docs.orcasecurity.io/ (redirected to region-selection, content not accessible)

---

## Documentation References

- https://orca.security/platform/container-and-kubernetes-security/ (container/K8s coverage, fetched)
- https://orca.security/resources/blog/meet-orca-sensor/ (Orca Sensor announcement, fetched)
- https://orca.security/platform/agentless-sidescanning/ (SideScanning technology)
- https://orca.security/resources/blog/new-runtime-detections-in-orca-sensor/ (runtime detections)
- https://orca.security/resources/blog/orca-sensor-runtime-detections/ (additional runtime detection blog)
- https://innetworktech.com/wp-content/uploads/2024/09/ORCA-Side-Scanning-Technical-Brief-Digital.pdf (SideScanning technical brief)
- https://docs.orcasecurity.io/ (API docs portal, region-gated)

---

## Confidence and Gaps

**Confirmed:**
- SideScanning is agentless, reads block storage out-of-band
- Orca Sensor is eBPF-based, optional, deployed as DaemonSet in Kubernetes
- Sensor provides 30+ runtime detections covering processes, files, DNS, network
- Binary drift detection is a confirmed capability
- API is REST + GraphQL

**Likely:**
- Orca does NOT ingest Kubernetes API server audit logs natively (no reference found; SideScanning and Sensor focus on workload data, not audit plane). Audit-log-based detections (T1609, T1610 audit side) are likely not available without additional integration.

**Unknown / gaps in public docs:**
- Custom detection rule language for Orca Sensor is not publicly specified
- Whether Orca provides out-of-the-box MITRE ATT\&CK coverage mapping is not confirmed
- API endpoint list and rate limits: docs.orcasecurity.io redirected to region-selection during this session; content not accessible
- Pricing: enterprise-only, no public information
- QUERY_LANGUAGES enum for Orca is unclear; `graphql` is the closest match for the query API, but the rule authoring language is proprietary
