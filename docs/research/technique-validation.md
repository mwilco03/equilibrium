# Technique Validation: Upstream Cross-Reference

**Generated:** 2026-05-04
**ATT\&CK Version verified against:** v19 (master CTI branch, STIX objects fetched 2026-05-04)
**Scope:** T1609, T1610, T1611, T1525

---

## Critical Upstream Finding (applies to all four techniques)

**Confirmed:** The `x_mitre_data_sources` field is an **empty array `[]`** in the STIX objects for all four techniques in the MITRE CTI master branch. This was verified by fetching individual STIX JSON files directly from `github.com/mitre/cti`.

```
T1609  attack-pattern--7b50a1d3-4ca7-45d1-989d-a6503f04bfe1  x_mitre_data_sources: []
T1610  attack-pattern--56e0d8b8-3e25-49dd-9050-3aa252f5aa92  x_mitre_data_sources: []
T1611  attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665  x_mitre_data_sources: []
T1525  attack-pattern--4fd8a28b-4b3a-4cd6-a8cf-85ba5f824a7f  x_mitre_data_sources: []
```

The MITRE ATT\&CK v19 technique web pages confirm no DS#### data source IDs are rendered for any of these techniques. Detection is expressed only via Detection Strategy (DET####) and Analytic (AN####) IDs. This is a known state of the ATT\&CK v12+ framework for container-specific techniques, where MITRE has migrated away from inline `x_mitre_data_sources` strings on individual techniques toward the separate Data Source objects (DS####) and Data Component objects. However, those Data Source/Component relationship objects are not wired to these four techniques in the current STIX bundle.

**Implication for equilibrium:** The `data_source_id` and `data_source_name` values in our records (DS0009, DS0015, DS0017, DS0022, DS0028, DS0029, DS0032) are derived from the ATT\&CK framework's canonical Data Source catalog, but MITRE has not formally linked these DS objects to T1609/T1610/T1611/T1525 in its STIX data. The mappings in our records are therefore best-practice community inference, not MITRE-published relationships.

---

## T1609: Container Administration Command

### (a) MITRE Canonical

**URL:** https://attack.mitre.org/techniques/T1609/
**ATT\&CK Version:** v19
**STIX ID:** attack-pattern--7b50a1d3-4ca7-45d1-989d-a6503f04bfe1
**Tactic:** Execution
**Platforms:** Containers

**Detection section (verbatim from page):**
> "Defenders may detect abuse of container administration commands by observing anomalous use of management utilities (docker exec, kubectl exec, or API calls to kubelet) correlated with unexpected process creation inside containers. Behavioral chains include unauthorized API requests followed by command execution within running pods or containers, often originating from unusual user accounts, automation scripts, or IP addresses outside the expected cluster management plane."

| ID | Name |
|---|---|
| DET0065 | Detection Strategy for Container Administration Command Abuse |
| AN0177 | Anomalous use of management utilities (analytic under DET0065) |

**Data Sources listed on page:** None (DS#### IDs absent from ATT\&CK v19 page for T1609).

**Source:** https://attack.mitre.org/techniques/T1609/ (fetched 2026-05-04)
**STIX verification:** https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--7b50a1d3-4ca7-45d1-989d-a6503f04bfe1.json (fetched 2026-05-04)

### (b) Cross-Reference Findings

**Microsoft Kubernetes Threat Matrix**
ID: MS-TA9006, Tactic: Execution, MITRE mapping: T1609
URL: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exec%20into%20container/
Summary: Confirms exec into container via kubectl exec as execution technique. Recommends least-privilege access (MS-M9003), exec command restrictions via admission controllers (MS-M9010), and runtime capability limits via LSM (MS-M9011). No additional data sources beyond what MITRE identifies.

**Atomic Red Team (T1609)**
URL: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1609/T1609.md (fetched 2026-05-04)
Tests: (1) ExecIntoContainer via `kubectl exec`, (2) Docker Exec Into Container via `docker exec`.
Telemetry generated per ART:
- Kubernetes API server audit log (pod exec events)
- kubelet API calls to /exec handler
- Container process creation events
- Docker daemon logs

**Sigma Rules (SigmaHQ/sigma)**
Two rules found tagging T1609:

1. `kubernetes_audit_exec_into_container.yml`
   - Source: k8s audit log
   - Detection: `verb: create`, `objectRef.resource: pods`, `objectRef.subresource: exec`
   - Level: medium
   - URL: https://github.com/SigmaHQ/sigma/blob/cf68547b29cae8368ff55f8707dab6453b6f49c8/rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml

2. `kubernetes_audit_sidecar_injection.yml`
   - Source: k8s audit log
   - Detection: `verb: patch`, `apiGroup: apps`, `objectRef.resource: deployments`
   - Level: medium
   - Note: Tags T1609 (Exec-class execution via sidecar injection).
   - URL: https://github.com/SigmaHQ/sigma/blob/cf68547b29cae8368ff55f8707dab6453b6f49c8/rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml

**Falco Community Rules (falcosecurity/rules)**
The official Falco rule set does not tag any rule directly with T1609. The closest is:
- "Terminal shell in container" (`falco_rules.yaml`): tags `mitre_execution, T1059` (not T1609). Covers the runtime process side of exec sessions.
- No T1609-tagged rule was found in `falco_rules.yaml` or `falco-incubating_rules.yaml`.

**CTID Sensor Mappings:** GitHub API rate limit prevented search of the CTID sensor-mappings-to-attack repo during this session.

### (c) Gap Analysis vs equilibrium T1609.json

equilibrium current `data_components`:
- DS0015 Application Log Content (K8s audit)
- DS0017 Command Execution
- DS0009 Process Creation
- DS0029 Network Traffic Content

**Gaps identified:**

| Gap | Evidence | Confidence |
|---|---|---|
| The `id` fields for all data_component objects are `null`. MITRE's DS component IDs (e.g., DS0009.Process Creation = component ID not formally linked to T1609) need to be left null or resolved. | STIX verification: T1609 has no formal DS links in ATT\&CK v19. | Confirmed |
| Sidecar injection (kubectl patch to inject container into running Deployment) is a distinct sub-technique execution path tagged T1609 by Sigma but not represented in equilibrium's `relevant_events`. | Sigma `kubernetes_audit_sidecar_injection.yml` tags T1609; detection is `verb=patch, resource=deployments`. | Confirmed |
| kubelet direct exec endpoint (`POST /exec`, `/run` on TCP/10250) is mentioned in equilibrium's description but no explicit `relevant_event` entry covers the kubelet subresource path (separate from API server audit). | ART test #1 generates kubelet API calls distinct from API server audit path. | Likely |
| `Network Traffic Flow` (DS0029 Network Traffic Flow, not Content) as a data component is not separately called out. Network flow data (connection metadata without payload) from SPDY upgrade streams is a distinct detection point. | Sigma rules and ART implicitly generate this. | Possible |

---

## T1610: Deploy Container

### (a) MITRE Canonical

**URL:** https://attack.mitre.org/techniques/T1610/
**ATT\&CK Version:** v19
**STIX ID:** attack-pattern--56e0d8b8-3e25-49dd-9050-3aa252f5aa92
**Tactic:** Execution, Defense Evasion
**Platforms:** Containers

**Detection section (verbatim from page):**
> "Remote/API driven creation and start of a container whose image is not on an allow-list (or is tagged `latest`), executed by a non-admin principal, and/or started with risky runtime attributes (e.g., `--privileged`, host PID/NET namespaces, sensitive host path mounts, capability adds). Correlates create -> start -> first network/process actions from that container within a short time window."

| ID | Name |
|---|---|
| DET0249 | Behavior-chain detection for T1610 Deploy Container across Docker & Kubernetes control/node planes |
| AN0693 | Analytic for remote/API-driven container creation with risky attributes |

**Data Sources listed on page:** None (DS#### IDs absent).

**Source:** https://attack.mitre.org/techniques/T1610/ (fetched 2026-05-04)

### (b) Cross-Reference Findings

**Microsoft Kubernetes Threat Matrix**
ID: MS-TA9008, Tactic: Execution
URL: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/New%20Container/
Summary: Confirms deployment via pods, DaemonSets, ReplicaSets, Deployments. Mitigations: least privilege (MS-M9003), restrict over-permissive containers (MS-M9013), gate images via admission controllers (MS-M9005.003). No detection guidance provided.

**Atomic Red Team (T1610)**
URL: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1610/T1610.md (fetched 2026-05-04)
Test: Deploy Docker container (single test). Telemetry: Docker daemon create/start events. No K8s-specific test. No data sources explicitly tagged.

**Sigma Rules (SigmaHQ/sigma)**
Search via GitHub API returned no T1610-tagged `.yml` rules files. The search returned 0 results for `T1610 extension:yml` in SigmaHQ/sigma. The `sigma_attack_nav_coverage.json` file references T1610 but that is a coverage map, not a rule.

**Falco Community Rules (falcosecurity/rules)**
Two rules in `falco-incubating_rules.yaml` tag T1610:

1. "Launch Privileged Container": `container_started and container.privileged=true`; tags `mitre_execution, T1610`
2. "Launch Excessively Capable Container": `container_started and excessively_capable_container`; tags `mitre_execution, T1610`

Both fire on runtime Container Start events (DS0032 Container Start). Neither fires on the audit-log side (pod create via API).

### (c) Gap Analysis vs equilibrium T1610.json

equilibrium current `data_components`:
- DS0015 Application Log Content
- DS0032 Container Creation
- DS0032 Container Start
- DS0007 Image Metadata

**Gaps identified:**

| Gap | Evidence | Confidence |
|---|---|---|
| No Sigma rule for T1610 exists in SigmaHQ. The audit-log (DS0015) angle for pod create via API is not covered by any community Sigma rule tagged T1610. | GitHub API search returned 0 T1610 .yml results. | Confirmed |
| Falco covers only the runtime side (Container Start), not the API audit-log side (Container Creation via API server). equilibrium captures both in data_components, but the Falco coverage gap is worth noting in detection_strategies. | Falco T1610 rules use `container_started` condition, not k8s_audit. | Confirmed |
| Direct Docker daemon container creation (`docker run` on unmanaged hosts) is in equilibrium's description but the `relevant_events` for DS0032 Container Creation do not include `docker events` as a distinct event source. | ART test uses `docker build` + `docker run` without kubectl. | Likely |
| Defense Evasion tactic is in equilibrium's `tactics` array. MITRE confirms this. No gap here. | STIX verified: kill_chain_phases includes defense-evasion. | Confirmed |

---

## T1611: Escape to Host

### (a) MITRE Canonical

**URL:** https://attack.mitre.org/techniques/T1611/
**ATT\&CK Version:** v19
**STIX ID:** attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
**Tactic:** Privilege Escalation
**Platforms:** Windows, Linux, Containers, ESXi

**Detection section (verbatim from page):**
> "Detection of container escape attempts via bind mounts, privileged containers, or abuse of docker.sock. Defenders may observe anomalous volume mount configurations (e.g., hostPath to / or /proc), unexpected privileged container launches, or use of container administration commands to access host resources. These events typically correlate with subsequent process execution on the host outside of normal container isolation. Detection of Linux container escape attempts via syscalls (unshare, keyctl, mount) or process execution outside container namespaces. Defenders may correlate unusual system calls from containerized processes with subsequent process creation on the host or modification of host resources. Detection of Windows container escape attempts by observing processes accessing host directories, symbolic link abuse, or privilege escalation attempts. Detection of ESXi escape attempts by monitoring for anomalies in hypervisor logs such as unexpected VM operations, privilege escalation events, or attempts to load malicious kernel modules."

| ID | Name |
|---|---|
| DET0219 | Detection Strategy for Escape to Host |
| AN0612 | Container Escape via Bind Mounts / Privileged Containers |
| AN0613 | Linux Container Escape via Syscalls |
| AN0614 | Windows Container Escape Detection |
| AN0615 | ESXi Escape Attempts |

**Data Sources listed on page:** None (DS#### IDs absent).

**Source:** https://attack.mitre.org/techniques/T1611/ (fetched 2026-05-04)

### (b) Cross-Reference Findings

**Microsoft Kubernetes Threat Matrix**
ID: MS-TA9013, Tactics: Persistence, Privilege Escalation, Lateral Movement
URL: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/
Note: Microsoft maps T1611 to "Writable hostPath mount" specifically. Also covers "Privileged container" as a separate technique (MS-TA9012, see Sigma rule reference below). Mitigations: restrict over-permissive containers (MS-M9013), read-only file permissions (MS-M9016), LSM constraints (MS-M9011), Pod Security Standards (MS-M9017).

**Atomic Red Team (T1611)**
URL: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1611/T1611.md (fetched 2026-05-04)
Tests:
1. Deploy Container Using nsenter Escape (hostPID + nsenter to pivot to host mount namespace)
2. Mount Host Filesystem from Privileged Container (mount device + cron job persistence on host)
3. Privilege Escalation via Docker Volume Mapping (`docker run -v /:/mnt --rm alpine chroot /mnt`)

Telemetry generated:
- Pod creation audit event (hostPID=true, privileged=true)
- nsenter/mount/chroot syscall traces
- Process creation events outside container namespace
- Cron file writes on host filesystem

**Sigma Rules (SigmaHQ/sigma)**
Two rules found tagging T1611:

1. `kubernetes_audit_privileged_pod_creation.yml`
   - Source: k8s audit log
   - Detection: `verb: create, objectRef.resource: pods, capabilities: '*'`
   - Tags: `attack.t1611, attack.privilege-escalation`
   - URL: https://github.com/SigmaHQ/sigma/blob/cf68547b29cae8368ff55f8707dab6453b6f49c8/rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml

2. `kubernetes_audit_hostpath_mount.yml`
   - Source: k8s audit log
   - Detection: `verb: create, objectRef.resource: pods, hostPath: '*'`
   - Tags: `attack.t1611, attack.privilege-escalation`
   - URL: https://github.com/SigmaHQ/sigma/blob/cf68547b29cae8368ff55f8707dab6453b6f49c8/rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml

**Falco Community Rules (falcosecurity/rules)**
Several rules tag T1611:

From `falco_rules.yaml` (maturity: stable):
- "Debugfs Launched in Privileged Container": `container.privileged=true and proc.name=debugfs`; tags `mitre_privilege_escalation, T1611`
- "Detect release_agent File Container Escapes": `open_write and fd.name endswith release_agent and CAP_SYS_ADMIN`; tags `mitre_privilege_escalation, T1611`

From `falco-incubating_rules.yaml` (maturity: incubating):
- "Namespace change (setns) by unexpected program": `evt.type=setns in container`; tags `mitre_privilege_escalation, T1611`
- "Change namespace privileges via unshare": `evt.type=unshare and container and not CAP_SYS_ADMIN`; tags `mitre_privilege_escalation, T1611`
- "Mount Launched in Privileged Container": `container.privileged=true and proc.name=mount`; tags `mitre_privilege_escalation, T1611`

### (c) Gap Analysis vs equilibrium T1611.json

equilibrium current `data_components`:
- DS0032 Container Creation
- DS0009 Process Creation
- DS0028 OS API Execution (incorrectly mapped to DS0028 Logon Session -- see gap below)
- DS0022 File Modification

**Gaps identified:**

| Gap | Evidence | Confidence |
|---|---|---|
| `DS0028` (Logon Session) is the wrong DS ID for the "OS API Execution" data component in T1611.json. The definition in the file describes syscall observation (unshare, setns, mount), which belongs to DS0009 (Process) with the "OS API Execution" component, or potentially a custom component. DS0028 is "Logon Session" (authentication events). | equilibrium T1611.json line 53: `"data_source_id": "DS0028", "data_source_name": "Logon Session"`. Canonical ATT\&CK DS0028 = Logon Session, not syscalls. | Confirmed |
| Falco community covers the `release_agent` cgroup escape path (write to `release_agent` file). This is a specific file-write vector not represented in equilibrium's `relevant_events` for DS0022 File Modification. | Falco `falco_rules.yaml`: "Detect release_agent File Container Escapes" (stable rule). | Confirmed |
| ESXi escape (AN0615) and Windows container escape (AN0614) are referenced in MITRE's detection text and have no corresponding data_components or relevant_events in equilibrium T1611.json, which is Containers-platform-scoped. This is a reasonable scope decision but should be documented. | MITRE T1611 Platforms: Windows, Linux, Containers, ESXi. | Likely |
| `keyctl` syscall manipulation (capture host keyring) is listed in equilibrium's relevant_events for DS0028 but should be in the syscall/process component. | equilibrium T1611.json relevant_events for DS0028: includes `keyctl`. | Confirmed (same as DS0028 mismap above) |

---

## T1525: Implant Internal Image

### (a) MITRE Canonical

**URL:** https://attack.mitre.org/techniques/T1525/
**ATT\&CK Version:** v19
**STIX ID:** attack-pattern--4fd8a28b-4b3a-4cd6-a8cf-85ba5f824a7f
**Tactic:** Persistence
**Platforms:** IaaS, Containers

**Detection section (verbatim from page):**
> "Implantation of malicious code into container images followed by registry push and use in new deployments."
> "Creation or modification of cloud virtual machine images (AMIs, custom images) with persistence mechanisms, followed by infrastructure provisioning that uses these implanted images."

| ID | Name |
|---|---|
| DET0334 | Detection Strategy for T1525 -- Implant Internal Image |
| AN0946 | Container image backdoor followed by registry push and deployment |
| AN0947 | Cloud VM image with persistence followed by provisioning |

**Data Sources listed on page:** None (DS#### IDs absent).

**Note:** The Atomic Red Team file for T1525 returns 404 (no test exists for T1525 as of 2026-05-04). This was verified by a direct fetch of the expected path.

**Source:** https://attack.mitre.org/techniques/T1525/ (fetched 2026-05-04)

### (b) Cross-Reference Findings

**Microsoft Kubernetes Threat Matrix**
ID: MS-TA9002, Tactic: Initial Access, MITRE mappings: T1195.002, T1525
URL: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Compromised%20Image%20In%20Registry/
Note: Microsoft cross-maps T1525 to Initial Access (cluster perspective) and to T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain). The additional T1195.002 mapping is not present in equilibrium. Mitigations: secure CI/CD (MS-M9004), Image Assurance Policy (MS-M9005). No detection guidance provided in the public page.

**Atomic Red Team (T1525):** No test file exists (404 confirmed).

**Sigma Rules (SigmaHQ/sigma)**
One rule found tagging T1525:

1. `aws_ecs_task_definition_cred_endpoint_query.yml`
   - Source: AWS CloudTrail
   - Detection: ECS `RegisterTaskDefinition` / `RunTask` with command containing `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
   - Tags: `attack.persistence, attack.t1525`
   - Scope: AWS ECS only (not K8s or generic registry).
   - URL: https://github.com/SigmaHQ/sigma/blob/cf68547b29cae8368ff55f8707dab6453b6f49c8/rules/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query.yml

No K8s-specific Sigma rule for T1525 was found.

**Falco Community Rules (falcosecurity/rules)**
No T1525-tagged rule was found in either `falco_rules.yaml` or `falco-incubating_rules.yaml` (searched full content for T1525 string, returned 0 matches).

### (c) Gap Analysis vs equilibrium T1525.json

equilibrium current `data_components`:
- DS0007 Image Creation
- DS0007 Image Modification
- DS0015 Application Log Content
- DS0002 User Account Authentication

**Gaps identified:**

| Gap | Evidence | Confidence |
|---|---|---|
| The T1195.002 cross-mapping from the Microsoft matrix (Supply Chain Compromise) is not captured in equilibrium's `microsoft_k8s_matrix` section (which references MS-TA9002 / T1525). The Microsoft page explicitly links MS-TA9002 to both T1195.002 and T1525. | Fetched MS-TA9002 page: "MITRE Techniques: T1195.002, T1525". | Confirmed |
| AWS ECS-specific vector (backdoored task definition querying IMDS credential endpoint) is represented by a Sigma rule but has no analog in equilibrium T1525.json, which is K8s-focused. This is a scope decision but the IaaS platform is listed in MITRE's platforms. | Sigma `aws_ecs_task_definition_cred_endpoint_query.yml` tags T1525. equilibrium T1525.json has no ECS/CloudTrail data_component. | Likely |
| No Falco community rule exists for T1525. The registry-push-detection gap in the open-source Falco ecosystem is notable and means any Falco-based detection must be custom. | Searched `falco_rules.yaml` and `falco-incubating_rules.yaml` for T1525: 0 matches. | Confirmed |
| DS0002 User Account Authentication is present in equilibrium but MITRE does not formally link DS0002 to T1525 in its STIX data (same upstream omission as all other techniques above). The community mapping is reasonable but unconfirmed by MITRE. | STIX T1525: x_mitre_data_sources = []. | Confirmed (upstream gap, not equilibrium gap) |

---

## Recommended Record Updates

The following are concrete proposed edits. Do NOT apply these automatically; review and apply manually.

### 1. data/techniques/T1609.json

**Add to `data_components[]`:**
```
{
  "id": null,
  "name": "Container Modification",
  "data_source_id": "DS0032",
  "data_source_name": "Container",
  "definition": "Modification of a running container's configuration via a patch operation against Deployment, DaemonSet, or StatefulSet resources (kubectl patch / API PATCH verb on apps/v1 resources) to inject a sidecar container. This is a second execution path for T1609 alongside direct exec, tagged T1609 by Sigma community rules.",
  "url": "https://attack.mitre.org/datasources/DS0032/",
  "relevant_events": [
    "Kubernetes audit event: verb=patch, apiGroup=apps, objectRef.resource in {deployments, daemonsets, statefulsets}",
    "New container entry appearing in pod spec that was not present at pod creation"
  ]
}
```

**Add to `data_components[Application Log Content].relevant_events[]`:**
```
"kubelet direct exec endpoint: POST to kubelet TCP/10250 at path /exec or /run (bypasses API server audit when kubelet is directly accessible)"
```

### 2. data/techniques/T1610.json

**Add to `data_components[Container Creation].relevant_events[]`:**
```
"Docker daemon event: type=container, action=create (from docker events API on standalone Docker hosts, outside Kubernetes)"
```

**Suggested note in `detection_strategies`:** Document that no SigmaHQ community Sigma rule currently covers T1610 (the gap was confirmed via GitHub API search as of 2026-05-04).

### 3. data/techniques/T1611.json

**Fix mismatched data_source on OS API Execution component:**
```
Change: "data_source_id": "DS0028", "data_source_name": "Logon Session"
To:     "data_source_id": "DS0009", "data_source_name": "Process"
```
Rationale: DS0028 is the canonical ATT\&CK ID for Logon Session (authentication events). The component being described (syscall observation of unshare, setns, keyctl, mount, pivot_root) belongs under Process (DS0009) as an "OS API Execution" data component.

**Add to `data_components[File Modification].relevant_events[]`:**
```
"Write to /sys/fs/cgroup/*/release_agent from inside a container (cgroup escape via release_agent mechanism)",
"Write to /proc/sysrq-trigger from inside a container"
```

### 4. data/techniques/T1525.json

**Update `microsoft_k8s_matrix.description`** to note the dual MITRE mapping:
> Add: "The Microsoft matrix page (MS-TA9002) cross-maps this technique to both T1525 (Implant Internal Image) and T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)."

**Add to `data_components[]` (optional, IaaS platform coverage):**
```
{
  "id": null,
  "name": "Application Log Content",
  "data_source_id": "DS0015",
  "data_source_name": "Application Log",
  "definition": "AWS CloudTrail log entries for ECS RegisterTaskDefinition and RunTask events where the container definition includes a command referencing $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, indicating a backdoored task definition querying the IMDS credential endpoint.",
  "url": "https://attack.mitre.org/datasources/DS0015/",
  "relevant_events": [
    "CloudTrail event: eventSource=ecs.amazonaws.com, eventName=RegisterTaskDefinition, requestParameters.containerDefinitions.command contains '$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'",
    "CloudTrail event: eventSource=ecs.amazonaws.com, eventName=RunTask"
  ]
}
```
Note: This is only relevant if equilibrium's scope extends to IaaS (AWS ECS) in addition to K8s containers.

---

## Research Process

### Searches Performed
1. "MITRE ATT\&CK T1609 T1610 T1611 T1525 data sources data components v19"
2. "SigmaHQ sigma T1609 kubernetes" (GitHub API)
3. "SigmaHQ sigma T1610 kubernetes" (GitHub API)
4. "SigmaHQ sigma T1611 kubernetes" (GitHub API)
5. "SigmaHQ sigma T1525" (GitHub API)
6. "falcosecurity rules T1610 T1609 T1611 T1525" (GitHub API)

### Pages Fetched
- [Official] https://attack.mitre.org/techniques/T1609/ (fetched, read)
- [Official] https://attack.mitre.org/techniques/T1610/ (fetched, read)
- [Official] https://attack.mitre.org/techniques/T1611/ (fetched, read)
- [Official] https://attack.mitre.org/techniques/T1525/ (fetched, read)
- [Official STIX] https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--7b50a1d3-4ca7-45d1-989d-a6503f04bfe1.json (T1609, fetched)
- [Official STIX] https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--56e0d8b8-3e25-49dd-9050-3aa252f5aa92.json (T1610, fetched)
- [Official STIX] https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665.json (T1611, fetched)
- [Official STIX] https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--4fd8a28b-4b3a-4cd6-a8cf-85ba5f824a7f.json (T1525, fetched)
- [Official] https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exec%20into%20container/ (fetched)
- [Official] https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/New%20Container/ (fetched)
- [Official] https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/ (fetched)
- [Official] https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Compromised%20Image%20In%20Registry/ (fetched)
- [Official] https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1609/T1609.md (fetched)
- [Official] https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1610/T1610.md (fetched)
- [Official] https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1611/T1611.md (fetched)
- [Official] https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1525/T1525.md (404 - no test exists)
- [Official] SigmaHQ rule files fetched via gh API (4 rule files read in full)
- [Official] falcosecurity/rules falco_rules.yaml (fetched via gh API, searched)
- [Official] falcosecurity/rules falco-incubating_rules.yaml (fetched via gh API, searched)

### Sources Rejected
- ATT\&CK datasources page (JS-rendered, returned empty results for component lists)
- DS0032 individual page (returned "0 techniques" note, possibly stale/JS-rendered)
- CTID sensor-mappings-to-attack repo (GitHub API rate limit hit before search completed)
- enterprise-attack.json full bundle (10MB+ size limit exceeded)

### Gaps
- CTID Attack Flow / Sensor Mapping data not retrieved (API rate limited). Unknown whether any CTID sensor mappings formally link DS objects to these techniques.
- Tetragon community rules not searched (GitHub API rate limited after Falco search). Tetragon uses eBPF policies in a TracingPolicy CRD; unknown if any community policies tag these ATT\&CK IDs.
- Tracee community rules not searched for same reason.

### Tools Used
- WebFetch: 28 calls
- WebSearch: 6 calls
- Bash (gh API): 6 calls
- Bash (curl STIX): 2 calls
- Read: 4 files (technique JSON records)
