# Lacework (FortiCNAPP)

**Slug:** `lacework`
**Category:** CNAPP
**Pricing posture:** Enterprise-only. Lacework was acquired by Fortinet in August 2024 and rebranded as **FortiCNAPP**. Pricing through Fortinet sales; no public free tier.
**Last verified:** 2026-05-04

---

## Product Overview

Lacework, now operating as **FortiCNAPP (formerly Lacework)** under Fortinet, is a CNAPP offering continuous security across cloud infrastructure, workloads, and container environments. Its distinguishing technology is the **Polygraph**: a behavioral graph that baselines normal cloud activity (API calls, process execution, network connections, file activity) and surfaces anomalous deviations without requiring a large library of hand-authored rules.

The platform won KuppingerCole 2025 CNAPP Leadership Compass (Overall, Market, and Innovation) and SC Awards 2025 Best Cloud Workload Protection Solution (per search result from appsecsanta.com, 2026-05-04).

Documentation now lives at: https://docs.fortinet.com/product/lacework-forticnapp (redirected from docs.lacework.net and docs.lacework.com as of 2026-05-04).

---

## Detection Model

**Polygraph (behavioral baselining):**
FortiCNAPP's primary detection mechanism is the Polygraph, which observes cloud and workload activity to build entity behavior graphs. Deviations from established baselines (e.g., a container making unusual network connections, a process spawning unexpected children) generate alerts. This anomaly-based approach requires less rule maintenance but produces different alert characteristics than signature-based detection.

**LQL (Lacework Query Language):**
LQL is a SQL-like query language for explicitly specifying selection, filtering, and manipulation of FortiCNAPP data. It enables security teams to:
- Query curated datasources (cloud provider logs, K8s audit, agent data, CloudTrail)
- Build custom policy rules
- Perform threat hunting

LQL structure:
```
{
  source { <datasource> }
  filter { <boolean expression> }
  return { <field list> }
}
```

LQL is case-insensitive for keywords, case-sensitive for identifiers. Max query size: 72,000 characters. Supports s-strings and double-quoted strings, single-line (`--`, `//`) and multi-line (`/* */`) comments.

**QUERY_LANGUAGES mapping:**
- `lql`: the canonical equilibrium enum value for LQL

Sources: https://docs.fortinet.com/document/lacework-forticnapp/latest/lql-reference/ (fetched 2026-05-04), https://docs.fortinet.com/document/lacework-forticnapp/25.2.0/cli-reference/295631/lql-queries (search result)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Kubernetes API server audit logs | K8s audit log integration (GKE native, EKS via CloudFormation/Terraform) | DS0015 Application Log |
| Cloud provider logs (AWS CloudTrail, GCP audit, Azure Monitor) | Cloud API integration | DS0015 Application Log |
| Agent-based host/container telemetry | Lacework agent (datacollector) running as DaemonSet | DS0009 Process, DS0022 File, DS0029 Network Traffic |
| Container image scanning | Inline scanner or registry integration | DS0007 Image |
| Kubernetes resource configuration | K8s API polling | DS0032 Container |

**Kubernetes audit log specifics:**
- Supported platforms: GKE, Amazon EKS (CloudFormation and Terraform deployment options)
- The platform processes audit logs to detect: unauthorized access attempts, privilege escalation, control plane manipulation
- Processing latency: under 15 minutes for near-real-time response (per search result from lacework.com blog)

Sources: https://docs.fortinet.com/document/lacework-forticnapp/latest/administration-guide/280544/kubernetes-audit-logs-for-gke (fetched 2026-05-04), https://www.lacework.com/blog/lacework-introduces-new-kubernetes-audit-logs-monitoring (search result)

---

## Container / Kubernetes Coverage Specifically

- Kubernetes audit log ingestion covering GKE and EKS (other providers: check Fortinet docs for current status)
- Agent-based workload monitoring: process execution, network connections, file activity within containers and hosts
- Container image scanning (vulnerability, malware)
- Kubernetes configuration compliance (KSPM)
- Polygraph builds behavioral baseline of workload activity within Kubernetes namespaces
- CDR (Cloud Detection and Response): processed Kubernetes audit logs combined with cloud provider logs for correlated detection

---

## Public API Surface

The Lacework API v2 previously documented at `docs.lacework.net/api/v2/docs` redirects to the Fortinet docs portal as of 2026-05-04. The Fortinet documentation portal lists an API Reference guide.

From the Fortinet docs portal (`docs.fortinet.com/product/lacework-forticnapp`):
- API Reference guide is listed as available
- LQL Reference Guide (PDF available: `fortinetweb.s3.amazonaws.com/docs.fortinet.com/...Lacework_FortiCNAPP-LQL_Reference_Guide.pdf`)

**Confirmed:** A REST API exists with API reference documentation in the Fortinet portal. Specific endpoint paths, auth model, and rate limits require accessing the gated Fortinet documentation.

A federated search integration exists (https://docs.query.ai/docs/lacework-fortinet-forticnapp), confirming the API supports querying for security events and findings.

---

## Documentation References

- https://docs.fortinet.com/product/lacework-forticnapp (root portal)
- https://docs.fortinet.com/document/lacework-forticnapp/latest/lql-reference/ (LQL reference, fetched)
- https://docs.fortinet.com/document/lacework-forticnapp/latest/administration-guide/280544/kubernetes-audit-logs-for-gke (K8s audit log docs, fetched)
- https://docs.fortinet.com/document/lacework-forticnapp/25.2.0/administration-guide/865261/eks-audit-log-integration-using-cloudformation (EKS audit log)
- https://www.lacework.com/blog/lacework-introduces-new-kubernetes-audit-logs-monitoring (feature announcement)
- https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e2dbb007-75dd-11ef-8355-fa163e15d75b/Lacework_FortiCNAPP-LQL_Reference_Guide.pdf (LQL reference PDF)
- https://docs.query.ai/docs/lacework-fortinet-forticnapp (federated search integration)

---

## Confidence and Gaps

**Confirmed:**
- Lacework rebranded as FortiCNAPP under Fortinet (August 2024 acquisition)
- Documentation lives at docs.fortinet.com as of 2026-05-04
- LQL is the query language; SQL-like with source/filter/return structure
- Kubernetes audit log integration exists for GKE and EKS
- API reference documentation exists in the Fortinet portal

**Likely:**
- The Polygraph behavioral baselining is retained in FortiCNAPP (no announcement of removal found)
- Agent-based telemetry (datacollector agent) continues to function as before the acquisition

**Unknown / gaps in public docs:**
- Specific API endpoint paths, auth model, and rate limits require accessing Fortinet's gated documentation
- Whether Azure AKS and on-premises K8s audit log integrations are supported (GKE and EKS confirmed; others unconfirmed)
- Post-acquisition feature roadmap: unclear which Lacework-specific features are being deprecated or modified under Fortinet ownership
