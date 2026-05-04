# Datadog Cloud SIEM

**Slug:** `datadog_cloud_siem`
**Category:** SIEM / CNAPP (runtime)
**Pricing posture:** Consumption-based (analyzed log GB). Free tier available (limited retention). Paid tiers by data volume. Enterprise contracts for production use.
**Last verified:** 2026-05-04

---

## Product Overview

Datadog is a unified observability and security platform. Its security-relevant products for equilibrium are:

1. **Cloud SIEM**: log-based threat detection and correlation against cloud and on-premises logs
2. **Workload Protection** (formerly Cloud Workload Security, CWS): eBPF-based runtime security for containers and hosts
3. **Cloud Security Misconfigurations** (formerly CSPM): cloud configuration compliance

All three are part of the Datadog Security product suite and share a unified data model. For equilibrium, Cloud SIEM covers the audit-log plane; Workload Protection covers the runtime/syscall plane.

Sources: https://docs.datadoghq.com/security/cloud_siem/ (fetched 2026-05-04), https://docs.datadoghq.com/security/detection_rules/ (fetched 2026-05-04), https://docs.datadoghq.com/security/workload_protection/ (fetched 2026-05-04)

---

## Detection Model

**Cloud SIEM -- log detection rules:**
Cloud SIEM uses detection rules that apply conditional logic against ingested logs. Rule types:
- **Log detection rules**: query syntax over normalized log data (uses Datadog log search syntax: field:value, boolean operators, `@field` for attributes)
- **Signal correlation rules**: correlate multiple signals into a higher-confidence finding

MITRE ATT\&CK mapping is available in Cloud SIEM, Workload Protection, and App and API Protection. Rules include tactic and technique tags.

**Workload Protection -- SECL (Security Expressions Condition Language):**
Workload Protection uses the **Datadog Agent Rule (SECL)** language for runtime detection. SECL is the kernel-level rule language:

Syntax: `<event-type>.<event-attribute> <operator> <value>`

Example: `open.file.path == "/etc/shadow" && process.file.path not in ["/usr/sbin/vipw"]`

Available event types (Linux):
- `exec`: process execution events
- `open`: file open events (read, write)
- `chmod`, `chown`, `link`, `rename`, `mkdir`, `rmdir`, `unlink`: file system operations
- `connect`, `bind`: network events
- `dns`: DNS resolution events
- `setuid`, `setgid`, `ptrace`: privilege/capability events
- Container metadata fields: `container.id`, `container.name`, `container.image.name`

SECL operators: `==`, `!=`, `>`, `>=`, `<`, `<=`, `&&`, `||`, `!`, `in`, `not in`, `=~` (pattern match), `r"regex"`

Time-based rules: use duration suffixes (s, m, h) for sliding window conditions.

**QUERY_LANGUAGES mapping:**
- Cloud SIEM log rules: Datadog log search syntax (not in current equilibrium enum; closest is `kql` if KQL-like, but it is distinct)
- Workload Protection runtime rules: SECL (custom Datadog DSL; not in current equilibrium enum; could map to `ebpf_dsl`)

Sources: https://docs.datadoghq.com/security/detection_rules/ (fetched 2026-05-04), https://docs.datadoghq.com/security/workload_protection/agent_expressions/ (fetched 2026-05-04), https://docs.datadoghq.com/security/workload_protection/ (fetched 2026-05-04)

---

## Telemetry Sources

| Telemetry | Ingestion Method | MITRE Data Source |
|---|---|---|
| Kubernetes API server audit logs | Datadog Agent Kubernetes integration (DaemonSet) | DS0015 Application Log |
| Container process events | Datadog Agent (eBPF DaemonSet) | DS0009 Process |
| File integrity monitoring (in containers/hosts) | Datadog Agent (SECL rules) | DS0022 File |
| Network connections (DNS, TCP) | Datadog Agent (eBPF) | DS0029 Network Traffic |
| AWS CloudTrail | Datadog AWS integration (API polling) | DS0015 Application Log |
| Azure Monitor logs | Datadog Azure integration | DS0015 Application Log |
| GCP Audit Logs | Datadog GCP integration | DS0015 Application Log |
| Okta events | Datadog Okta integration | DS0002 User Account |
| Container image vulnerability data | Datadog Container Image Scanning | DS0007 Image |

---

## Container / Kubernetes Coverage Specifically

**Workload Protection (eBPF runtime):**
- Datadog Agent deployed as DaemonSet on each node
- Monitors kernel-level activity: process execution, file opens/writes, network connections, DNS, privilege changes, container starts
- SECL rules fire on kernel events enriched with container and Kubernetes metadata
- 50+ out-of-the-box detection rules from Datadog security research team
- Custom rules via SECL (Assisted Rule Creator for simple FIM/process rules; Manual SECL for complex rules)
- **Active Protection** (Preview): automatic blocking of crypto mining threats

**Kubernetes audit log:**
- Kubernetes audit logs collected by the Datadog Agent's Kubernetes integration
- Used in Cloud SIEM for control-plane detection (exec events, RBAC changes, pod creation)
- MITRE ATT\&CK tagging in managed rules

**Coverage for specific techniques:**
- T1609 (Container Admin Command): K8s audit log detection in Cloud SIEM; process exec in container via Workload Protection
- T1610 (Deploy Container): K8s audit pod create detection in Cloud SIEM; container start in Workload Protection
- T1611 (Escape to Host): Workload Protection SECL rules for namespace transitions, privileged container process events, runtime socket writes
- T1525 (Implant Internal Image): Container Image Scanning for known malware; Cloud SIEM for registry push events (requires registry log ingestion)

---

## Public API Surface

**Base URL:** `https://api.datadoghq.com` (US); `https://api.datadoghq.eu` (EU); other regional variants

**Auth:**
- Header `DD-API-KEY: <api_key>` (required for all endpoints)
- Header `DD-APPLICATION-KEY: <app_key>` (required for most read/write operations)

**Security Monitoring API endpoints (v2):**

| Endpoint | Method | Description |
|---|---|---|
| `/api/v2/security_monitoring/rules` | `GET` | List detection rules (search, filter, paginate) |
| `/api/v2/security_monitoring/rules` | `POST` | Create custom detection rule |
| `/api/v2/security_monitoring/rules/{rule_id}` | `GET` | Get single rule |
| `/api/v2/security_monitoring/rules/{rule_id}` | `PUT` | Update rule |
| `/api/v2/security_monitoring/rules/{rule_id}` | `DELETE` | Delete rule |
| `/api/v2/security_monitoring/signals` | `GET` | List security signals |
| `/api/v2/security_monitoring/signals/{signal_id}/state` | `PATCH` | Update signal triage state |
| `/api/v2/posture_management/findings` | `GET` | List CSPM findings |

**Rate limits:** Not explicitly documented in the fetched content.

**Relevance for equilibrium:** The `/api/v2/security_monitoring/rules` GET endpoint allows programmatic export of all custom and managed detection rules, enabling equilibrium to pull Datadog rule definitions for cross-reference or synchronization.

Sources: https://docs.datadoghq.com/api/latest/security-monitoring/ (fetched 2026-05-04)

---

## Documentation References

- https://docs.datadoghq.com/security/cloud_siem/ (Cloud SIEM overview, fetched)
- https://docs.datadoghq.com/security/detection_rules/ (detection rules, fetched)
- https://docs.datadoghq.com/security/workload_protection/ (Workload Protection, fetched)
- https://docs.datadoghq.com/security/workload_protection/agent_expressions/ (SECL language reference, fetched)
- https://docs.datadoghq.com/security/workload_protection/workload_security_rules/custom_rules/ (custom rule creation, fetched)
- https://docs.datadoghq.com/api/latest/security-monitoring/ (Security Monitoring API, fetched)

---

## Confidence and Gaps

**Confirmed:**
- Cloud SIEM: log-based detection with Datadog log search syntax
- Workload Protection: eBPF-based runtime detection using SECL rule language
- SECL event types: exec, open, chmod, chown, link, connect, bind, dns, setuid, ptrace, plus container fields
- 50+ out-of-the-box Workload Protection rules
- Security Monitoring API: `/api/v2/security_monitoring/rules` for CRUD operations on rules
- Auth: DD-API-KEY + DD-APPLICATION-KEY headers
- MITRE ATT\&CK mapping in detection rules

**Likely:**
- Kubernetes audit logs are ingested via the standard Datadog Agent K8s integration and used in Cloud SIEM detections
- Container exec events (T1609) are detected via both K8s audit log rules in Cloud SIEM and runtime process rules in Workload Protection

**Unknown / gaps in public docs:**
- API rate limits: not found in fetched documentation
- Whether Cloud SIEM has out-of-the-box K8s exec (T1609) and privileged pod (T1610/T1611) managed rules: not confirmed from fetched docs (only general MITRE coverage mentioned)
- SECL syntax for container-escape-specific rules: the SECL page confirmed event types but specific K8s/container escape rule examples were not shown in fetched content
- Pricing details for specific Workload Protection tier: only general consumption model described
