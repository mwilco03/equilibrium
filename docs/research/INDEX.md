# Equilibrium Research Index

**Generated:** 2026-05-04
**Scope:** MITRE ATT\&CK techniques T1609, T1610, T1611, T1525 and nine vendor coverage reports

---

## Deliverables

| File | Description |
|---|---|
| [docs/research/technique-validation.md](technique-validation.md) | Upstream validation of four ATT\&CK techniques against MITRE CTI, Microsoft K8s Threat Matrix, Atomic Red Team, SigmaHQ, and Falco community rules |
| [docs/vendors/wiz.md](../vendors/wiz.md) | Wiz CNAPP coverage report |
| [docs/vendors/upwind.md](../vendors/upwind.md) | Upwind Security CNAPP coverage report |
| [docs/vendors/lacework.md](../vendors/lacework.md) | Lacework / FortiCNAPP coverage report |
| [docs/vendors/sysdig.md](../vendors/sysdig.md) | Sysdig Secure CNAPP/runtime coverage report |
| [docs/vendors/snowflake.md](../vendors/snowflake.md) | Snowflake as SQL-over-normalized-logs target |
| [docs/vendors/crowdstrike.md](../vendors/crowdstrike.md) | CrowdStrike Falcon Cloud Security + LogScale |
| [docs/vendors/prisma_cloud.md](../vendors/prisma_cloud.md) | Palo Alto Networks Prisma Cloud CNAPP |
| [docs/vendors/orca.md](../vendors/orca.md) | Orca Security agentless CNAPP |
| [docs/vendors/datadog_cloud_siem.md](../vendors/datadog_cloud_siem.md) | Datadog Cloud SIEM + Workload Protection |

---

## Highest-Confidence Findings

### ATT\&CK Upstream

**1. MITRE ATT\&CK v19 has empty data source mappings for all four techniques. (Confirmed)**

The `x_mitre_data_sources` field in the STIX objects for T1609, T1610, T1611, and T1525 is an empty array (`[]`). Verified by directly fetching the individual STIX JSON files from `github.com/mitre/cti` on 2026-05-04. The ATT\&CK v19 technique web pages corroborate this: no DS#### data source IDs are rendered for any of these four techniques.

This means the DS#### mappings in equilibrium's `data_components` records are community-inferred best practices, not MITRE-published relationships. This is not a defect in equilibrium; it is a gap in ATT\&CK that our records partially fill.

**2. T1611.json contains a data source ID mismatch. (Confirmed)**

`data_source_id: "DS0028"` with `data_source_name: "Logon Session"` is assigned to the "OS API Execution" data component in T1611.json. DS0028 is the canonical ATT\&CK Logon Session data source (authentication events). The described telemetry (syscalls: unshare, setns, keyctl, mount, pivot_root) belongs under DS0009 (Process). This is a concrete error that should be fixed.

**3. The `release_agent` cgroup escape vector is not covered in T1611.json. (Confirmed)**

The official Falco `falco_rules.yaml` (stable maturity) includes the rule "Detect release_agent File Container Escapes" tagged T1611. This specific file-write vector (write to `/sys/fs/cgroup/*/release_agent`) is not represented in T1611.json's `relevant_events` for DS0022 File Modification.

**4. Sidecar injection (kubectl patch on Deployments) is a T1609 execution vector not in equilibrium. (Confirmed)**

SigmaHQ has a rule `kubernetes_audit_sidecar_injection.yml` tagged T1609 that detects `verb=patch` on `apps/deployments`. equilibrium's T1609.json `relevant_events` only cover `verb=create` on `pods/exec`. The patch-based sidecar injection path is a distinct audit event not currently represented.

**5. No Sigma rule for T1610 exists in SigmaHQ. (Confirmed)**

GitHub API search of `SigmaHQ/sigma` for T1610 `.yml` files returned zero results. No community Sigma rule covers the pod-creation-via-API audit log for T1610.

**6. No Falco community rule exists for T1525. (Confirmed)**

Searched both `falco_rules.yaml` and `falco-incubating_rules.yaml` for T1525 references. Zero matches. Registry-push detection via Falco requires entirely custom rules.

**7. Microsoft's K8s Threat Matrix maps MS-TA9002 (Compromised Image in Registry) to both T1525 and T1195.002. (Confirmed)**

The Microsoft page explicitly lists two MITRE technique mappings. equilibrium's T1525.json only references T1525.

---

### Vendor Landscape

**8. CrowdStrike uses CQL, not SPL. (Confirmed)**

CrowdStrike Falcon LogScale / NG-SIEM uses CQL (CrowdStrike Query Language), a pipeline-based language using `|`-separated functions. It is architecturally different from SPL (Splunk). The equilibrium QUERY_LANGUAGES enum contains `spl` but not `cql`. Any CrowdStrike LogScale vendor_detections block should use a `cql` value; the enum may need updating.

**9. Sysdig's open-source Falco has three stable/incubating rules tagged T1611 and two tagged T1610 in the official rules repo. (Confirmed)**

Fetched and read the actual rule YAML files. T1611-tagged stable rules: "Debugfs Launched in Privileged Container", "Detect release_agent File Container Escapes". T1611-tagged incubating rules: setns, unshare, mount inside container. T1610-tagged incubating rules: "Launch Privileged Container", "Launch Excessively Capable Container". No Sigma rules for T1610; no Falco rules for T1525.

**10. Lacework was acquired by Fortinet (August 2024) and is now FortiCNAPP. All documentation redirects. (Confirmed)**

docs.lacework.com and docs.lacework.net both 301-redirect to docs.fortinet.com/product/lacework-forticnapp. The LQL Reference Guide (PDF) is available at the Fortinet S3 bucket URL. Kubernetes audit log integration (GKE, EKS) confirmed in post-acquisition Fortinet documentation.

**11. Orca Security's SideScanning does NOT observe live runtime processes or network connections. (Confirmed per Orca's own statement)**

Orca's blog on the Sensor explicitly states: "agentless technology doesn't see the processes or memory of your containers." The Orca Sensor (eBPF, optional) was introduced to close this gap and provides 30+ runtime detections. Any equilibrium Orca vendor_detection referencing runtime process data requires the Orca Sensor to be deployed.

**12. Datadog Workload Protection uses SECL as its runtime rule language. (Confirmed)**

SECL (Security Expressions Condition Language) is fully documented in Datadog's public docs with event types (exec, open, connect, dns, setuid, ptrace, etc.), operators, container metadata fields, and regex/glob support. The Security Monitoring API (`/api/v2/security_monitoring/rules`) provides full CRUD for detection rules, making Datadog the best-documented vendor API surface in this set.

---

## Action Items for equilibrium

### Immediate (confirmed errors)

1. Fix `DS0028` -> `DS0009` in `data/techniques/T1611.json` for the OS API Execution data component.

2. Add `release_agent` write to T1611.json `relevant_events` for DS0022 File Modification.

3. Add sidecar injection audit event (`verb=patch, resource=deployments`) to T1609.json as a new data_component entry (DS0032 Container Modification or DS0015 Application Log).

### Recommended (confirmed gaps from cross-reference)

4. Add T1195.002 cross-reference note to T1525.json `microsoft_k8s_matrix` description.

5. Add direct kubelet exec endpoint path to T1609.json DS0015 `relevant_events`.

6. Add `docker events` create event to T1610.json DS0032 Container Creation `relevant_events`.

7. Consider adding `cql` to the QUERY_LANGUAGES enum for CrowdStrike LogScale detections.

### Investigation needed (possible gaps, not yet confirmed)

8. CTID Sensor Mappings: Check whether CTID has formally linked DS objects to T1609/T1610/T1611/T1525 (GitHub API rate limit prevented this search).

9. Tetragon / Tracee community rules: Search these repos for T1609/T1610/T1611/T1525 tags when GitHub API rate limits reset.

---

## Research Methodology Notes

All technique STIX data verified by direct fetch of individual STIX JSON files from `github.com/mitre/cti` (not training data). All Sigma rule content verified by reading actual YAML files via GitHub API. All Falco rule content verified by reading actual YAML files via GitHub API. Vendor information was gathered from public documentation pages and web search results; any claims sourced only from search result snippets (not from fetched full-text pages) are labeled "Likely" or "Possible" per the project's epistemic discipline.
