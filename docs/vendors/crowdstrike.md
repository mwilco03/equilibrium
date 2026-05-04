# CrowdStrike

**Slug:** `crowdstrike`
**Category:** CNAPP / EDR / NG-SIEM
**Pricing posture:** Enterprise-only; no public pricing or free tier. Module-based licensing (Falcon Prevent, Falcon Cloud Security, Falcon LogScale/NG-SIEM are separate modules).
**Last verified:** 2026-05-04

---

## Product Overview

CrowdStrike Falcon is a unified security platform. The cloud-native security components relevant to equilibrium are:

- **Falcon Cloud Security**: CNAPP covering CSPM, CWPP, CIEM, container/Kubernetes security
- **Falcon LogScale (Next-Gen SIEM)**: Petabyte-scale log management and threat detection platform (formerly Humio)
- **Falcon Sensor**: the endpoint agent, supporting both kernel module and eBPF modes, deployable as a DaemonSet in Kubernetes

CrowdStrike's approach to container security is described as full lifecycle: build (image scanning, registry security), deploy (admission control), and runtime (sensor-based behavioral detection).

Sources: https://www.crowdstrike.com/en-us/platform/cloud-security/container-kubernetes/ (fetched 2026-05-04), https://www.crowdstrike.com/en-us/blog/preventing-container-escape-attempts-falcon-cloud-runtime-security/ (fetched 2026-05-04)

---

## Detection Model

**Runtime detection (Falcon Sensor):**
The Falcon Sensor runs on each node (DaemonSet deployment on Kubernetes). It supports:
- Kernel module mode
- eBPF mode (for environments where kernel module cannot be loaded)

The sensor captures: process execution, file system changes, network behavior, container start/stop/image, and runtime events inside each container including Kubernetes namespace and pod metadata.

Detection is driven by adversary intelligence feeds plus behavioral ML. Alerts surface in the Falcon console with MITRE ATT\&CK mapping.

**Falcon NG-SIEM / LogScale (CQL):**
Falcon LogScale uses **CQL (CrowdStrike Query Language)**, also called the LogScale query language. CQL is a pipeline-based query language (not SQL) designed for log analysis. Features:
- Function composition via `|` pipe operator
- Functions: `filter()`, `groupBy()`, `count()`, `regex()`, `format()`, `timechart()`, etc.
- Event field access by name: `#source`, `verb`, `objectRef.resource`
- Case-insensitive matching functions

CQL is not SPL (Splunk Processing Language). The equilibrium schema currently uses `spl` as a possible enum value but CrowdStrike's native language is CQL. LogScale can ingest Kubernetes audit logs via the Fluent Bit integration and apply CQL-based detections.

**Agentless cloud detections:**
Falcon Cloud Security also integrates with the Kubernetes API Server for agentless control plane visibility (workload drift, unauthorized container deployment). This is separate from the sensor-based runtime detection.

**QUERY_LANGUAGES mapping:**
- LogScale/NG-SIEM: CQL. This maps to `spl` in the equilibrium QUERY_LANGUAGES enum only if treating CQL and SPL as equivalent (they are not). Equilibrium should consider adding `cql` as a distinct enum value, or use `spl` with a note that the actual syntax is CQL.

Sources: https://www.crowdstrike.com/en-us/platform/cloud-security/container-kubernetes/ (fetched 2026-05-04), https://www.crowdstrike.com/en-us/platform/next-gen-siem/falcon-logscale/ (search result), https://www.crowdstrike.com/tech-hub/ng-siem/top-logscale-query-functions-for-new-customers/ (search result), https://github.com/CrowdStrike/Kubernetes-FluentBit-Logging-Falcon-Logscale-Integration (search result)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Process events (inside containers) | Falcon Sensor (kernel module or eBPF) | DS0009 Process |
| File system events (inside containers) | Falcon Sensor | DS0022 File |
| Network events (container and host) | Falcon Sensor | DS0029 Network Traffic |
| Container start/stop/image metadata | Falcon Sensor | DS0032 Container |
| Kubernetes control plane events (agentless) | Kubernetes API Server integration | DS0015 Application Log |
| Kubernetes audit logs (via LogScale) | Fluent Bit DaemonSet -> LogScale ingestion | DS0015 Application Log |
| Registry and SBOM data | Falcon Cloud Security registry integration | DS0007 Image |
| Cloud provider logs | Falcon Cloud Security connectors (AWS, Azure, GCP) | DS0015 Application Log |

---

## Container / Kubernetes Coverage Specifically

**Runtime (Falcon Sensor as DaemonSet):**
- All process, file, and network events inside every container on the node
- Kubernetes metadata enrichment (namespace, pod, image, labels)
- Container escape detection: behavioral detection of chroot operations, namespace manipulation, host filesystem access from containers
- "Workload drift": detection of new binaries executing that were not part of the base image

**Agentless (Kubernetes API Server integration):**
- Control plane event monitoring: unauthorized container deployment, RBAC changes
- Workload configuration visibility (pod specs, service accounts)

**Kubernetes audit logs in LogScale:**
- Fluent Bit integration captures K8s cluster logging telemetry (API server logs, audit logs, application logs)
- CQL-based detection rules can query exec events, pod creation, and other audit fields
- Community content repository: https://github.com/CrowdStrike/logscale-community-content

**Kubernetes Helm deployment:**
Falcon Sensor is deployed via official Helm charts (https://github.com/CrowdStrike/falcon-helm) and managed by the Falcon Operator (https://github.com/CrowdStrike/falcon-operator).

Sources: https://www.crowdstrike.com/en-us/platform/cloud-security/container-kubernetes/ (fetched), https://github.com/CrowdStrike/Kubernetes-FluentBit-Logging-Falcon-Logscale-Integration (search result), https://github.com/CrowdStrike/falcon-helm (search result)

---

## Public API Surface

CrowdStrike exposes the **Falcon API**, a comprehensive REST API available to all Falcon subscribers.

- **Base URL:** `https://api.crowdstrike.com` (US-1); regional variants for EU, US-2, US-Gov
- **Auth:** OAuth 2.0 client credentials (client ID + secret -> Bearer token)
- **Rate limits:** Not publicly specified; vary by endpoint and subscription tier
- **Python SDK:** `falconpy` (open source, https://github.com/CrowdStrike/falconpy)

**Kubernetes Protection API** (Service Collection: `KubernetesProtection`):
Available at https://falconpy.io/Service-Collections/Kubernetes-Protection.html. Enables:
- Listing protected clusters
- Querying Kubernetes assets and events
- Managing cluster connectors

**LogScale API:** LogScale has a REST API for querying stored log data and managing saved queries/alerts programmatically.

**Relevance for equilibrium:** CQL-based hunt queries can be managed and executed via the LogScale API, enabling equilibrium to store CQL detection patterns and run them against a customer's LogScale instance.

Sources: https://falconpy.io/Service-Collections/Kubernetes-Protection.html (search result), https://www.crowdstrike.com/en-us/platform/cloud-security/container-kubernetes/ (fetched)

---

## Documentation References

- https://www.crowdstrike.com/en-us/platform/cloud-security/container-kubernetes/ (container/K8s overview, fetched)
- https://www.crowdstrike.com/en-us/blog/preventing-container-escape-attempts-falcon-cloud-runtime-security/ (container escape detection blog, fetched)
- https://www.crowdstrike.com/en-us/platform/next-gen-siem/falcon-logscale/ (LogScale overview)
- https://www.crowdstrike.com/tech-hub/ng-siem/top-logscale-query-functions-for-new-customers/ (CQL functions reference)
- https://github.com/CrowdStrike/falcon-helm (Helm chart deployment)
- https://github.com/CrowdStrike/falcon-operator (Kubernetes operator)
- https://github.com/CrowdStrike/Kubernetes-FluentBit-Logging-Falcon-Logscale-Integration (K8s logs -> LogScale pipeline)
- https://github.com/CrowdStrike/logscale-community-content (community CQL queries)
- https://falconpy.io/Service-Collections/Kubernetes-Protection.html (K8s Protection API)
- https://cql-hub.com/ (community CQL detection queries)

---

## Confidence and Gaps

**Confirmed:**
- Falcon Sensor supports both kernel module and eBPF modes
- DaemonSet deployment for Kubernetes is supported via official Helm chart and Operator
- Falcon captures process, file, network, and container events inside every container
- LogScale uses CQL (not SPL); CQL is pipeline-based with `|`-separated functions
- Kubernetes audit logs can be ingested into LogScale via Fluent Bit
- Kubernetes Protection API exists for programmatic K8s asset and event management
- Container escape detection is explicitly called out in product documentation

**Likely:**
- CQL community rules for K8s exec detection exist (CQL Hub has community queries)
- MITRE ATT\&CK mapping is available in Falcon console for runtime detections

**Unknown / gaps in public docs:**
- The internal detection rule format for the Falcon sensor's behavioral detection is not publicly specified (proprietary ML models + adversary intelligence, not a user-accessible rule DSL)
- Whether CQL detection rules can be pulled from the LogScale API in a format compatible with equilibrium is unconfirmed
- Pricing by module: not publicly available
- Specific API rate limits: not publicly documented
- **Note on equilibrium QUERY_LANGUAGES enum:** CQL is not SPL. If CrowdStrike LogScale detections are added to equilibrium, a `cql` enum entry should be considered.
