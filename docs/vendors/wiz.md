# Wiz

**Slug:** `wiz`
**Category:** CNAPP (Cloud Native Application Protection Platform)
**Pricing posture:** Enterprise-only; no free tier or self-service trial. Demo required.
**Last verified:** 2026-05-04

---

## Product Overview

Wiz is an agentless-first cloud and AI security platform. Its core value proposition is coverage without agents: it reads cloud configuration, workload runtime block storage, and cloud API telemetry without a running agent on each host. An optional **Wiz Runtime Sensor** (eBPF-based DaemonSet) extends coverage to live process, file, and network events within running workloads.

The platform organizes findings through the **Wiz Security Graph**, a graph database (deployed on Amazon Neptune per AWS partnership blog) that models every cloud resource as a node and every relationship (network exposure, IAM permission, vulnerability, container image, etc.) as an edge. Attack path analysis traverses this graph to surface toxic risk combinations.

Wiz categorizes itself across: CSPM, CWPP, CIEM, CNAPP, container security, AI security, and Code Security.

Sources: https://www.wiz.io/platform (fetched 2026-05-04), https://www.wiz.io/solutions/container-and-kubernetes-security (fetched 2026-05-04), https://aws.amazon.com/blogs/database/the-world-is-a-graph-how-wiz-reimagines-cloud-security-using-a-graph-in-amazon-neptune/ (search result 2026-05-04)

---

## Detection Model

Wiz detection operates across two planes:

**Agentless plane (CSPM / posture):**
Cloud configuration state is continuously scanned via cloud provider APIs. Detection rules fire on graph relationships (e.g., "container image with critical CVE AND exposed to internet via load balancer"). This plane does not see live process behavior.

**Runtime plane (Wiz Defend, via Wiz Runtime Sensor):**
The eBPF-based Runtime Sensor is deployed as a Kubernetes DaemonSet. It captures live process execution, network connections, file activity, and system calls. Detection rules are authored by the Wiz Research Team (thousands of built-in rules, continuously updated) plus customer custom rules. Detection signals from the runtime plane are combined with the Security Graph's risk context to produce enriched alerts.

**Threat Center / audit-log detections:**
Wiz ingests Kubernetes API server audit logs via a connector. Detections over audit logs use a query model referred to in Wiz documentation and integration guides as "Resource Graph" style (a proprietary graph query / KQL-adjacent syntax). The exact formal query language name is not publicly documented. Wiz also exposes a natural-language AI interface for investigation queries.

**Equilibrium QUERY_LANGUAGES mapping:**
- `wiz_resource_graph`: audit-log and configuration graph queries
- `ebpf_dsl` is a reasonable label for the runtime sensor's rule language (custom DSL, not publicly specified)

Sources: https://www.wiz.io/platform/wiz-defend (search result), https://softwareanalyst.substack.com/p/runtime-security-in-2025-how-wiz (search result), https://www.wiz.io/blog/overcoming-kubernetes-audit-log-challenges (search result), Cribl integration doc (https://docs.cribl.io/stream/4.5/usecase-wiz-api/ fetched 2026-05-04)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Cloud provider APIs (AWS, Azure, GCP) | Agentless API polling | DS0015 Application Log, DS0007 Image |
| Kubernetes API server audit logs | Wiz K8s audit connector (webhook or cloud-managed log forwarding) | DS0015 Application Log |
| Container image layers / SBOMs | Agentless registry scanning | DS0007 Image |
| Running process events (in container) | Wiz Runtime Sensor (eBPF DaemonSet) | DS0009 Process |
| File activity in containers | Wiz Runtime Sensor (eBPF DaemonSet) | DS0022 File |
| Network connections from containers | Wiz Runtime Sensor (eBPF DaemonSet) | DS0029 Network Traffic |
| Cloud SaaS logs (Okta, GitHub, etc.) | API-based integration connectors | DS0015 Application Log |

---

## Container / Kubernetes Coverage Specifically

**Agentless:**
- Continuous scanning of running container images for CVEs and malware signatures (via block storage read-out-of-band)
- Kubernetes KSPM: misconfiguration checks across cluster configuration, RBAC, network policies, Pod Security Standards
- Registry scanning for all registries the cluster pulls from (ECR, GCR, GHCR, ACR, Quay, Harbor)
- Admission controller integration to block non-compliant pods at deploy time

**Runtime (Wiz Runtime Sensor, optional):**
- eBPF DaemonSet collects: running processes, network connections, file activity, system calls
- Runtime file integrity monitoring
- Drift detection (binary not in base image)
- Threat monitoring against built-in + custom rules
- Kubernetes audit log ingestion via connector; detections over exec/attach/pod-create events

Sources: https://www.wiz.io/solutions/container-and-kubernetes-security (fetched 2026-05-04)

---

## Public API Surface

**Endpoint root:** Single GraphQL endpoint (exact URL is tenant-specific, typically `https://api.app.wiz.io/graphql` or equivalent regional URL)

**Auth model:** OAuth 2.0 client credentials flow. Requires:
- `clientId` (53-character string)
- `clientSecret` (64-character string)
- `authUrl` (e.g., `https://auth.app.wiz.io/oauth/token`)
Token exchanged for Bearer JWT, used in `Authorization: Bearer <token>` header.

**Data types accessible via API:**
- Audit Logs (platform activity: logins, mutation calls)
- Configuration Findings (CSPM issues)
- Issues (security problems with risk scores)
- Vulnerabilities
- Threats / Detections (runtime signals)

**Rate limit (Confirmed):** "Do not exceed three API requests per second"

**Result limits:** Audit Logs and Configuration Findings cap at 10,000 results per call. Issues and Vulnerabilities have no stated limit.

**Note for equilibrium:** Pulling back threat detections or audit-log queries programmatically requires the GraphQL API. The query structure for Threat Center data is not publicly documented beyond the Cribl integration example.

Sources: https://docs.cribl.io/stream/4.5/usecase-wiz-api/ (fetched 2026-05-04), https://docs.datadoghq.com/integrations/wiz/ (search result)

---

## Documentation References

- https://www.wiz.io/platform (product overview)
- https://www.wiz.io/platform/wiz-defend (runtime threat detection)
- https://www.wiz.io/solutions/container-and-kubernetes-security (K8s coverage)
- https://www.wiz.io/blog/overcoming-kubernetes-audit-log-challenges (K8s audit log challenges)
- https://docs.cribl.io/stream/4.5/usecase-wiz-api/ (API integration example with OAuth details)
- https://docs.datadoghq.com/integrations/wiz/ (Datadog integration, lists Wiz data types)
- https://aws.amazon.com/blogs/database/the-world-is-a-graph-how-wiz-reimagines-cloud-security-using-a-graph-in-amazon-neptuse/ (Security Graph architecture)
- https://softwareanalyst.substack.com/p/runtime-security-in-2025-how-wiz (independent analyst coverage of Wiz Defend 2025)
- https://security.googlecloudcommunity.com/community-blog-42/detect-and-respond-to-your-security-threats-with-wiz-and-google-cloud-5561 (cloud log integration)

---

## Confidence and Gaps

**Confirmed:**
- Wiz is agentless-first with an optional eBPF runtime sensor
- Kubernetes audit log ingestion is supported via a connector
- API is GraphQL with OAuth 2.0 client credentials auth
- Rate limit: 3 req/s
- Runtime sensor is a DaemonSet using eBPF

**Likely:**
- The "Resource Graph" query syntax used in equilibrium vendor_detections blocks is a reasonable characterization of Wiz's internal detection query model, but the exact formal language name is not publicly documented. Wiz docs reference it as a graph query/KQL-adjacent interface.
- Custom detection rules are supported in the Threat Center (confirmed by analyst sources and product marketing).

**Unknown / gaps in public docs:**
- Formal query language specification for custom rules is not publicly available (no open-source DSL spec found)
- Pricing: no public tier or pricing page. Enterprise sales only.
- Specific Falco-like rule format for Wiz Runtime Sensor rules is not public
- Whether Wiz exposes a bulk-download API for all custom detection rules (useful for pulling into equilibrium) is unconfirmed
