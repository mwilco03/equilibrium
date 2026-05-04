# Prisma Cloud

**Slug:** `prisma_cloud`
**Category:** CNAPP
**Pricing posture:** Enterprise-only (Palo Alto Networks). Module-based licensing. No public free tier or self-service trial.
**Last verified:** 2026-05-04

---

## Product Overview

Prisma Cloud is Palo Alto Networks' CNAPP offering. It combines:
- **CSPM** (Cloud Security Posture Management): multi-cloud configuration and compliance
- **CWPP** (Cloud Workload Protection): Defender-based runtime security for containers, hosts, and serverless
- **CIEM** (Cloud Infrastructure Entitlement Management): IAM risk
- **CNAPP integrations**: code security, supply chain, image scanning

Prisma Cloud has two deployment models:
- **Enterprise Edition** (SaaS): all capabilities in one platform; the main product
- **Compute Edition** (formerly Twistlock): self-hosted container security component; can run standalone

**MITRE ATT\&CK integration:** Palo Alto Networks released a cloud-native attack dashboard extending MITRE ATT\&CK with their own cloud threat matrix. Prisma Cloud surfaces MITRE technique mappings in its threat detection alerts.

Sources: https://docs.prismacloud.io/en (fetched 2026-05-04, returned navigation only), https://www.paloaltonetworks.com/blog/prisma-cloud/mitre-attck-for-cloud-improve-threat-detection/ (search result), https://docs.prismacloud.io/en/compute-edition/32/admin-guide/technology-overviews/defender-architecture (search result, page returned title-only)

---

## Detection Model

**Prisma Cloud Compute -- Defender (runtime):**
The **Defender** is Prisma Cloud's security agent. One Defender per node, deployed as a DaemonSet in Kubernetes. The Defender:
- Monitors container and host runtime activity
- Enforces runtime defense policies (behavioral profiles)
- Intercepts container API calls, process spawns, network connections, and file access
- Reports events to the Prisma Cloud console

**Runtime defense for containers:**
Prisma Cloud uses a **learned model / behavioral profile** approach for container runtime defense. The platform learns what "normal" looks like for each container image (processes, network connections, file system paths, system calls) and alerts or blocks deviations.

Policy types in runtime defense:
- Process policy: allowed/blocked processes
- Networking policy: allowed/blocked connections
- File system policy: allowed/blocked paths
- System call policy: allowed/blocked syscalls

**RQL (Resource Query Language) -- CSPM plane:**
RQL is the query language for cloud resource configuration queries. It queries the Prisma Cloud asset inventory, not live runtime events. Example:
```rql
config from cloud.resource where cloud.type = 'kubernetes' AND api.name = 'kubernetes-v1-pod'
AND json.rule = 'spec.containers[*].securityContext.privileged is true'
```

RQL does not query runtime events. Runtime events are queried through the Compute API or investigated via the Forensics timeline view.

**QUERY_LANGUAGES mapping:**
- CSPM configuration queries: `json_rule` (RQL-style JSON conditions) or no single enum match
- No formal QUERY_LANGUAGES enum match for runtime defense (behavioral profile, not a user-authored query language)

Sources: search results for Prisma Cloud Defender architecture and runtime defense docs (fetched pages returned title-only due to JS rendering); information drawn from available public sources and search result snippets.

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Container process events | Defender agent (DaemonSet) | DS0009 Process |
| Container file system events | Defender agent | DS0022 File |
| Container network connections | Defender agent | DS0029 Network Traffic |
| System calls (container runtime) | Defender agent | DS0009 Process |
| Kubernetes API server audit logs | Kubernetes audit log integration (where available) | DS0015 Application Log |
| Container image layers and SBOMs | Defender inline scanning + registry integration | DS0007 Image |
| Cloud provider configuration | API-based CSPM connectors | DS0015 Application Log |

---

## Container / Kubernetes Coverage Specifically

**Defender in Kubernetes:**
- DaemonSet deployment: one Defender pod per node
- Captures all process, network, and filesystem events from all containers on the node
- Container metadata enrichment (namespace, pod, image, deployment)
- Kubernetes audit log integration (optional; enables control-plane detection on top of runtime)

**Runtime defense model:**
- Behavioral profiles learned per container image (not per-instance)
- Profile includes: expected processes, network connections, file paths, capabilities
- Runtime alerts fire when container behavior deviates from the learned profile
- Separate policies for allowed/blocked items overlay the learned model

**Admission controller:**
Prisma Cloud includes an admission controller (webhook) for:
- Vulnerability-based admission gates
- Compliance policy enforcement at deploy time
- Image signature verification

**Supply chain:**
- Image scanning in CI pipelines and registries
- SBOM generation
- Known malware detection in image layers

Sources: https://docs.prismacloud.io/en/compute-edition/30/admin-guide/runtime-defense/runtime-defense-containers (search result, page JS-rendered), https://www.paloaltonetworks.com/blog/prisma-cloud/mitre-attck-for-cloud-improve-threat-detection/ (search result)

---

## Public API Surface

**Compute API:** `https://<compute-console-url>/api/v1/`
- REST API for Defender management, runtime events, scan results, policies
- Auth: JWT via username/password or service account token
- Python examples via `falconpy`-style SDK (not official; community examples exist)
- Endpoint reference: https://prisma.pan.dev/api/cloud/cwpp/

**Prisma Cloud Enterprise API:** separate REST API for CSPM findings, alerts, RQL queries
- Auth: JWT via service account
- Rate limits: not publicly documented

**Relevance for equilibrium:** The Compute API enables programmatic retrieval of runtime events and policy status, which could be used to pull detection results into equilibrium.

Sources: https://prisma.pan.dev/api/cloud/cwpp/defenders/ (search result), https://xsoar.pan.dev/docs/reference/integrations/palo-alto-networks-prisma-cloud-compute (search result)

---

## Documentation References

- https://docs.prismacloud.io/en (root documentation portal)
- https://docs.prismacloud.io/en/compute-edition/32/admin-guide/technology-overviews/defender-architecture (Defender architecture)
- https://docs.prismacloud.io/en/compute-edition/30/admin-guide/runtime-defense/runtime-defense-containers (container runtime defense)
- https://docs.prismacloud.io/en/enterprise-edition/content-collections/runtime-security/runtime-security (runtime security overview)
- https://prisma.pan.dev/api/cloud/cwpp/ (Compute API reference)
- https://prisma.pan.dev/api/cloud/cwpp/defenders/ (Defenders API)
- https://www.paloaltonetworks.com/blog/prisma-cloud/mitre-attck-for-cloud-improve-threat-detection/ (MITRE ATT\&CK integration blog)
- https://www.paloaltonetworks.com/blog/cloud-security/ebpf-cloud-security-real-time-protection/ (eBPF in Prisma Cloud blog)

---

## Confidence and Gaps

**Confirmed:**
- Defender is the runtime agent (DaemonSet deployment in Kubernetes)
- Behavioral profile (learned model) approach for container runtime defense
- RQL is the CSPM query language (configuration queries, not runtime events)
- Compute API exists at `prisma.pan.dev/api/cloud/cwpp/`
- MITRE ATT\&CK mapping is available in alerts

**Likely:**
- Defender uses a combination of kernel module and eBPF depending on kernel version (Palo Alto has a public blog on eBPF adoption; specific version thresholds not confirmed from fetched docs)
- Kubernetes audit log integration is available as an optional component

**Unknown / gaps in public docs:**
- Prisma Cloud documentation pages are heavily JS-rendered and returned only titles during fetches in this session. Most technical details above are from search result snippets and blog posts, not full documentation reads.
- Specific eBPF vs. kernel module threshold for Defender deployment: not confirmed
- Pricing: not publicly available
- API rate limits: not publicly documented
- Whether Prisma Cloud supports custom Falco-style rules (vs. only the behavioral profile model) is unclear from public docs
