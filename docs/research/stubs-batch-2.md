# Stubs Batch 2: Research Report

**Scope:** 21 stub techniques across Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, and Impact.

**Methodology:** MITRE ATT&CK STIX data (enterprise-attack-14.1, fetched directly from mitre-attack/attack-stix-data) used as the ground truth for `x_mitre_data_sources`. Microsoft Threat Matrix for Kubernetes pages fetched directly. Sigma rules confirmed via SigmaHQ/sigma GitHub directory listing. Falco rules confirmed via falcosecurity/rules. Atomic Red Team tests confirmed via redcanaryco/atomic-red-team. DET/AN IDs sourced from live MITRE ATT&CK technique pages.

**Key conventions:**
- DS IDs and data component names come verbatim from STIX data (Confirmed).
- DET/AN IDs come from MITRE ATT&CK technique pages as fetched (Confirmed where the page returned them, Likely otherwise).
- Sigma/Falco rule paths are verbatim from GitHub.

---

## 1. MS-TA9021 -- Clear Container Logs

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1070/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Clear%20container%20logs/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing fetched; no K8s-specific clear-log rule found for container logs)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Clear Log Activities` rule tagged `T1070`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml (fetched; Windows-only tests, no container tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Log entries produced by containerized applications or container runtimes (e.g., Docker engine logs, containerd logs, application stdout/stderr). Clearing or truncating these files removes attacker-activity evidence.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Container runtime log files (e.g., /var/lib/docker/containers/<id>/<id>-json.log) truncated or deleted",
      "Application stdout/stderr logs removed from pod log directory /var/log/pods/",
      "Falco alert: Clear Log Activities fired inside a container context"
    ]
  },
  {
    "id": null,
    "name": "File Deletion",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "File system events indicating removal of files. Deletion of container log files on the host node is a primary indicator of this technique.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "inotify/auditd DELETE event on /var/log/pods/<namespace>/<pod>/ files",
      "rm or truncate syscall targeting container log paths recorded by Falco",
      "Container log file size reduced to zero (truncation)"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Command-line invocations inside a container that target log file paths, such as rm, truncate, or shell redirects to /dev/null.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "kubectl exec session issuing `rm -rf /var/log/` inside a container",
      "Container process executing `truncate -s 0 /proc/1/fd/1` to silence stdout",
      "Shell command `cat /dev/null > <logfile>` executed within container PID namespace"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0184",
    "name": "Behavioral Detection of Indicator Removal Across Platforms",
    "summary": "Detects deletion or overwriting of audit logs and container log paths post-compromise. AN0523 specifically addresses container log tampering.",
    "url": "https://attack.mitre.org/techniques/T1070/",
    "data_component_refs": ["Application Log Content", "File Deletion", "Command Execution"]
  }
]
```

**Analytics:** AN0520, AN0521, AN0522, AN0523, AN0524, AN0525 (AN0523 is the container-specific analytic).

### Notes / Confidence

- **Confirmed:** STIX `x_mitre_data_sources` for T1070 includes `Application Log: Application Log Content`, `File: File Deletion`, `Command: Command Execution`, and `Process: Process Creation`. All are applicable in the container context.
- **Confirmed:** Falco `Clear Log Activities` rule exists in falcosecurity/rules, tagged `T1070`, covers host and container contexts.
- **Likely:** MS mitigation MS-M9020 (Collect Logs to Remote Data Storage) implies that off-node log forwarding (e.g., Fluentd to a SIEM) is the primary detective control; deletion of local logs is then detectable only via the remote sink's absence of expected events.
- No Atomic Red Team container-specific test exists for T1070 (Windows-only).

### Open Questions

- Does the project's logging stack ship container stdout/stderr off-node before an attacker can clear it? If not, DS0015 coverage is theoretical.

---

## 2. MS-TA9022 -- Delete K8S Events

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1070/ (fetched; parent technique)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml (fetched; Sigma rule `kubernetes_audit_events_deleted`, tagged `attack.t1070`)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Clear Log Activities` tagged `T1070`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml (fetched; no K8s test)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs recording DELETE verb operations against the `events` resource. This is the primary data source for detecting `kubectl delete events --all` or equivalent API calls.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit log: verb=delete, objectRef.resource=events, user.username=<principal>",
      "API server audit event with requestObject showing bulk event deletion",
      "Absence of expected Kubernetes events (pod creation, image pull) in the event stream after a known workload change"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Recording of kubectl or direct API calls that delete Kubernetes event objects from within a pod or from an external client.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`kubectl delete events --all -n <namespace>` captured in audit log or shell history",
      "Direct HTTP DELETE to /api/v1/namespaces/<ns>/events recorded in API server logs",
      "curl or API client call deleting events via a service account token"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0184",
    "name": "Behavioral Detection of Indicator Removal Across Platforms",
    "summary": "AN0523 covers tampering with audit logs inside container/cluster contexts. The Sigma rule kubernetes_audit_events_deleted directly implements this for K8s event deletion.",
    "url": "https://attack.mitre.org/techniques/T1070/",
    "data_component_refs": ["Application Log Content", "Command Execution"]
  }
]
```

**Analytics:** AN0523 (container/audit log tampering).

**Sigma rule:** `rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml` (SigmaHQ/sigma, author: Leo Tsaousis, 2024-03-26, severity: medium, status: test).

### Notes / Confidence

- **Confirmed:** Sigma rule `kubernetes_audit_events_deleted.yml` exists and is tagged `attack.t1070`, detection logic: verb=delete on resource=events.
- **Confirmed:** STIX T1070 includes `Application Log: Application Log Content` and `Command: Command Execution`.
- **Confirmed:** MS mitigation recommends remote log storage (MS-M9020) and least-privilege RBAC (MS-M9003). RBAC restriction is a preventive control; audit logging is the detective control.
- This technique is K8s-specific (Kubernetes Event objects). The sub-technique T1070 is the best current mapping; there is no T1070.xxx sub-technique specific to K8s event deletion.

### Open Questions

- Does the cluster have a Kubernetes audit policy configured to capture DELETE verbs on the events resource? Without that policy level, the Sigma rule will never fire.

---

## 3. MS-TA9023 -- Pod or Container Name Similarity

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1036/ (fetched)
- https://attack.mitre.org/techniques/T1036/005/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Pod%20or%20container%20name%20similarity/ (404; slug not found)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; `kubernetes_audit_pod_in_system_namespace.yml` is the closest match)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no direct T1036 K8s rule found)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/005/ (not checked separately; parent T1036 has no container tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Image Metadata",
    "data_source_id": "DS0007",
    "data_source_name": "Image",
    "definition": "Container image name, tag, registry path, and layer hashes. An attacker deploying a malicious image named `kube-system/coredns` or similar mimics legitimate workloads.",
    "url": "https://attack.mitre.org/datasources/DS0007/",
    "relevant_events": [
      "Pod spec referencing an image name that matches a system component but originates from an unexpected registry",
      "Image pull from a non-allowlisted registry for a pod named to resemble kube-system workloads",
      "OPA/Gatekeeper admission webhook rejecting image name mismatch against allowlist"
    ]
  },
  {
    "id": null,
    "name": "Process Metadata",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process name, binary path, and parent process information. A container running with a name matching a system daemon but spawning unexpected child processes is an indicator.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Process named `kube-proxy` or `coredns` spawning a shell or network scanner",
      "Executable binary hash mismatch vs. known-good for a process bearing a legitimate system name",
      "Process created in a pod whose name matches a kube-system component but runs in a different namespace"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "New process creation events from container workloads. Processes in pods with deceptive names that deviate from expected command lines indicate masquerading.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Kubernetes audit: pod created in kube-system namespace with user-defined service account",
      "Falco: process spawned in container whose pod name matches a system workload pattern but has anomalous args",
      "AN0986 fires: container/pod name or namespace mimics legitimate workload, image layer inconsistency detected"
    ]
  },
  {
    "id": null,
    "name": "File Metadata",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Binary and configuration file metadata inside containers. Comparing hashes of running binaries against known-good images surfaces name-spoofed containers.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Binary in container filesystem with a legitimate system name but unexpected hash",
      "File created in /usr/bin/ inside a container with a name matching a system tool but different size",
      "Image layer diff showing replacement of a legitimate binary with a malicious one of the same name"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0127",
    "name": "Behavioral Detection of Masquerading Across Platforms via Metadata and Execution Discrepancy",
    "summary": "AN0358 specifically targets renamed container images and files with misleading names injected into containers during startup or scheduled jobs.",
    "url": "https://attack.mitre.org/techniques/T1036/",
    "data_component_refs": ["Image Metadata", "Process Metadata", "Process Creation"]
  },
  {
    "id": "DET0347",
    "name": "Detection Strategy for Masquerading via Legitimate Resource Name or Location",
    "summary": "AN0986 recognizes malicious containers or pods using names, labels, or namespaces mimicking legitimate workloads and checks for image layer inconsistencies.",
    "url": "https://attack.mitre.org/techniques/T1036/005/",
    "data_component_refs": ["Image Metadata", "Process Creation", "File Metadata"]
  }
]
```

**Analytics:** AN0355-AN0359 (T1036 parent), AN0983-AN0987 (T1036.005). Container-specific: AN0358 and AN0986.

### Notes / Confidence

- **Confirmed:** STIX T1036.005 `x_mitre_data_sources`: `File: File Metadata`, `Image: Image Metadata`, `Process: Process Metadata`, `Process: Process Creation`.
- **Likely:** MS Threat Matrix page returned 404 (slug may use different casing); description reconstructed from stub JSON and Threat Matrix index.
- **Possible:** Sigma rule `kubernetes_audit_pod_in_system_namespace.yml` covers the related pattern of pods being created in the kube-system namespace by non-system actors, which partially covers this technique.

### Open Questions

- What is the exact MS slug for this page? The 404 prevents direct fetch. Alternative slug `pod-or-container-name-similarity` also 404s.
- Does the cluster have an OPA/Gatekeeper policy enforcing image registry allowlists? That is the primary preventive control.

---

## 4. MS-TA9024 -- Connect From Proxy Server

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1090/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Connect%20from%20proxy%20server/ (404)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no proxy-specific K8s rule)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no direct T1090 rule identified)
- Atomic Red Team: no K8s-specific T1090 tests exist

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Summarized or raw network flow data showing source IP, destination IP, port, and protocol. API server requests originating from known proxy/VPN/TOR exit nodes are a primary indicator.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Kubernetes API server receiving requests from a TOR exit node IP or known proxy ASN",
      "kubectl command authenticated from a source IP not in the cluster's authorized IP range",
      "Repeated API authentication attempts from multiple geographically dispersed source IPs (proxy chain rotation)"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Deep packet inspection or TLS-decrypted content of traffic to/from the Kubernetes API server or other cluster endpoints. May reveal proxy protocol headers (X-Forwarded-For) inserted by attacker infrastructure.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "X-Forwarded-For or Via headers in requests to the API server suggesting proxied origin",
      "Unexpected User-Agent strings in kubectl-style API calls indicating non-standard tooling",
      "TLS certificate anomalies in connections to internal cluster services routed through a proxy"
    ]
  },
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "New outbound or inbound network connections. Attackers may establish reverse proxy or tunnel connections from a compromised pod to external infrastructure.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Container establishing outbound connection to a non-cluster IP on an unusual port (e.g., 8080, 3128, 1080)",
      "socat or ncat process inside a pod creating a listener or forwarding connection",
      "kubectl port-forward invoked to tunnel external attacker traffic through the API server"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0445",
    "name": "Detection of Proxy Infrastructure Setup and Traffic Bridging",
    "summary": "AN1229-AN1233 cover process-level proxy tooling and network connection creation. AN1232 focuses on nc/socat reverse tunnel scripts in containers.",
    "url": "https://attack.mitre.org/techniques/T1090/",
    "data_component_refs": ["Network Traffic Flow", "Network Traffic Content", "Network Connection Creation"]
  }
]
```

**Analytics:** AN1229, AN1230, AN1231, AN1232, AN1233.

### Notes / Confidence

- **Confirmed:** STIX T1090 `x_mitre_data_sources`: `Network Traffic: Network Traffic Flow`, `Network Traffic: Network Traffic Content`, `Network Traffic: Network Connection Creation`. All three are directly applicable.
- **Likely:** MS Threat Matrix page 404; the technique is about using a proxy server to avoid IP-based detection when accessing the K8s API server or other cluster services. Description inferred from stub JSON.
- **Possible:** Geo-IP and ASN reputation feeds integrated with the API server audit log are the most practical K8s implementation of this detection.

### Open Questions

- What is the correct MS slug for this page?
- Does the cluster enforce API server authorized IP ranges (`--service-cluster-ip-range` or cloud provider IP allowlisting)?

---

## 5. MS-TA9016 -- Container Service Account

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1528/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/container%20service%20account/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; `kubernetes_audit_serviceaccount_creation.yml` and `kubernetes_audit_rbac_permisions_listing.yml` are adjacent)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Contact K8S API Server From Container` tagged `mitre_discovery`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.yaml (fetched; Azure-only tests, no K8s container tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "User Account Modification",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Changes to service account objects or their associated RBAC bindings in Kubernetes. An attacker who steals a service account token effectively impersonates that account; post-theft API activity shows up as the service account principal.",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Kubernetes audit: requests from system:serviceaccount:<ns>:<name> to resources beyond the SA's normal scope",
      "Unexpected creation of ClusterRoleBinding granting cluster-admin to a pod service account",
      "Service account token used to authenticate from a source IP outside the node's subnet"
    ]
  },
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Read access to the service account token file mounted into every pod at /var/run/secrets/kubernetes.io/serviceaccount/token. Detection of this read by an unexpected process indicates token theft.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Falco: unexpected process (e.g., curl, wget, python) reading /var/run/secrets/kubernetes.io/serviceaccount/token",
      "auditd: open() syscall on /var/run/secrets/kubernetes.io/serviceaccount/token by non-entrypoint process",
      "Container exec session running `cat /var/run/secrets/kubernetes.io/serviceaccount/token`"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs recording API calls authenticated with a service account JWT. Anomalous resource access patterns using a pod SA token indicate theft.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "API audit log: service account performing `kubectl get secrets` or `kubectl get pods --all-namespaces`",
      "Service account token used to authenticate from outside the cluster (external IP in audit sourceIPs)",
      "AN1423: container SA token retrieved then used for unauthorized Kubernetes API requests"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0515",
    "name": "Detection Strategy for T1528 -- Steal Application Access Token",
    "summary": "AN1423 directly addresses Kubernetes SA token retrieval followed by unauthorized API requests using that token.",
    "url": "https://attack.mitre.org/techniques/T1528/",
    "data_component_refs": ["User Account Modification", "Application Log Content", "File Access"]
  }
]
```

**Analytics:** AN1423, AN1424, AN1425, AN1426, AN1427. AN1423 is K8s-specific.

### Notes / Confidence

- **Confirmed:** STIX T1528 `x_mitre_data_sources`: `User Account: User Account Modification`. This is the sole STIX data source; it is sparse.
- **Likely:** `File: File Access` is not in STIX T1528 data sources but is the most K8s-relevant detection signal (reading the token file). Inclusion is based on community inference from the attack pattern.
- **Confirmed:** MS page describes the token path `/var/run/secrets/kubernetes.io/serviceaccount/token` explicitly.
- **Confirmed:** Falco `Contact K8S API Server From Container` rule captures post-theft API usage from within a container.
- **Note:** STIX x_mitre_data_sources for T1528 contains only one entry (`User Account: User Account Modification`). The `File: File Access` addition is community inference, flagged accordingly.

### Open Questions

- Does the cluster disable automatic service account token mounting (automountServiceAccountToken: false) on pods that do not need it?
- Is the Falco `Contact K8S API Server From Container` rule configured with the cluster's actual API server IP?

---

## 6. MS-TA9025 -- List K8S Secrets

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://attack.mitre.org/techniques/T1552/007/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/List%20K8S%20secrets/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml (fetched; tagged `attack.t1552.007`)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml (fetched; tagged `attack.credential-access`)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Search Private Keys or Passwords` tagged `T1552.001`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.007/T1552.007.yaml (fetched; 3 tests including K8s container tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs recording list/get operations on the `secrets` resource. This is the canonical detection source for this technique.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit: verb=list, objectRef.resource=secrets, user.username=<service account or user>",
      "Kubernetes audit: verb=get, objectRef.resource=secrets, objectRef.name=<specific secret name>",
      "API request to /api/v1/secrets (cluster-wide) or /api/v1/namespaces/<ns>/secrets"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Recording of kubectl commands or direct API calls listing or getting Kubernetes secrets.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`kubectl get secrets --all-namespaces` or `kubectl describe secret <name>` in shell history or audit log",
      "curl call to /api/v1/secrets with Authorization: Bearer <token>",
      "Atomic Red Team T1552.007 test: query to /api/v1/secrets endpoint"
    ]
  },
  {
    "id": null,
    "name": "User Account Authentication",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Authentication events in the Kubernetes API server. Enumerating secrets requires valid credentials; anomalous authentication followed by secret access is a compound indicator.",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Service account authenticating from outside the cluster then listing secrets",
      "User account with no prior secret-access history suddenly listing all secrets",
      "Authentication using a token not associated with any running pod (orphaned token)"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0198",
    "name": "Detect Abuse of Container APIs for Credential Access",
    "summary": "AN0571 identifies suspicious kubectl get secrets or direct API calls exposing credential data via container APIs.",
    "url": "https://attack.mitre.org/techniques/T1552/007/",
    "data_component_refs": ["Application Log Content", "Command Execution", "User Account Authentication"]
  },
  {
    "id": "DET0412",
    "name": "Detect Access or Search for Unsecured Credentials Across Platforms",
    "summary": "AN1158 flags unusual access to container image layers or mounted secrets. AN1157 detects unauthorized API calls to retrieve key material.",
    "url": "https://attack.mitre.org/techniques/T1552/",
    "data_component_refs": ["Application Log Content", "User Account Authentication"]
  }
]
```

**Analytics:** AN0571 (T1552.007 specific), AN1153-AN1159 (T1552 parent).

**Sigma rules:**
- `rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml` (tagged `attack.t1552.007`)
- `rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml` (tagged `attack.credential-access`)

**Atomic Red Team:** T1552.007 has 3 container-platform tests including listing secrets via `/api/v1/secrets` and reading the SA token file.

### Notes / Confidence

- **Confirmed:** STIX T1552.007 `x_mitre_data_sources`: `User Account: User Account Authentication`, `Command: Command Execution`.
- **Confirmed:** Sigma rule `kubernetes_audit_secrets_enumeration.yml` exists tagged `attack.t1552.007`, detection: verb=list on resource=secrets.
- **Confirmed:** Atomic Red Team has K8s container-platform tests for T1552.007.
- **Likely:** `Application Log: Application Log Content` (from T1552 parent STIX) is the right DS for K8s audit logs; the sub-technique STIX entry is sparse.

### Open Questions

- Are Kubernetes secrets encrypted at rest in etcd? If not, direct etcd access is also an attack path not covered by API server audit.
- Is the cluster using an external secret manager (Vault, AWS Secrets Manager) that would redirect this activity to a different audit trail?

---

## 7. MS-TA9026 -- Mount Service Principal

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://attack.mitre.org/techniques/T1552/001/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Mount%20service%20principal/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; `kubernetes_audit_hostpath_mount.yml` is adjacent)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Search Private Keys or Passwords` tagged `T1552.001`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.yaml (fetched; no container tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Read access to files containing cloud service principal credentials on an AKS node, typically mounted into a container via hostPath or as a Kubernetes secret.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Container process reading /etc/kubernetes/azure.json or cloud provider credential files on the node",
      "auditd open() on /var/lib/waagent/ paths or Azure MSI token files from a non-system process",
      "Falco: Search Private Keys or Passwords rule triggered inside a container"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Commands executed within a container that access cloud credential files, such as cat, cp, or environment variable inspection targeting cloud authentication material.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`cat /etc/kubernetes/azure.json` or `env | grep -i azure` inside a container",
      "Mounting of a Kubernetes secret containing a service principal clientSecret and subsequent access",
      "kubectl exec session retrieving cloud credentials from a running pod"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "New processes within containers that perform cloud authentication using credential files, such as az login, aws configure, or gcloud auth.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Container spawning `az login --service-principal` with credentials from a mounted file",
      "curl or wget call to cloud management API endpoints using a service principal token from inside a pod",
      "AWS CLI or Azure CLI process starting inside a container not in the approved image"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0307",
    "name": "Detect Access to Unsecured Credential Files Across Platforms",
    "summary": "AN0859 covers container processes accessing mounted secrets or configuration paths followed by network or credential activity. AN0860 covers cloud credential file access followed by metadata API calls.",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "data_component_refs": ["File Access", "Command Execution", "Process Creation"]
  },
  {
    "id": "DET0412",
    "name": "Detect Access or Search for Unsecured Credentials Across Platforms",
    "summary": "AN1158 flags unusual access to container image layers or mounted secrets by processes outside the entrypoint context.",
    "url": "https://attack.mitre.org/techniques/T1552/",
    "data_component_refs": ["File Access", "Command Execution"]
  }
]
```

**Analytics:** AN0856-AN0860 (T1552.001), AN0859 and AN0860 are container/cloud-specific.

### Notes / Confidence

- **Confirmed:** STIX T1552.001 `x_mitre_data_sources`: `Command: Command Execution`, `Process: Process Creation`, `File: File Access`.
- **Confirmed:** MS page explicitly describes AKS node credential files and service principal secrets as targets.
- **Possible:** The Sigma `kubernetes_audit_hostpath_mount.yml` rule may partially cover cases where a container mounts credential file paths, but it targets the admission phase, not the access phase.
- **Note:** This technique is cloud-K8s specific (primarily AKS). On GKE/EKS the attack surface differs (Workload Identity, IRSA). Detection strategies should be tuned per cloud.

### Open Questions

- Is the cluster on AKS, GKE, EKS, or self-managed? The specific credential file paths differ.
- Does admission control block mounting of node host paths that contain credential files?

---

## 8. MS-TA9027 -- Application Credentials in Configuration Files

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20credentials%20in%20configuration%20files/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no rule directly for this)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Search Private Keys or Passwords` tagged `T1552.001`)
- No Atomic Red Team K8s-specific test for configuration file credential access

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Read access to Kubernetes pod spec files, ConfigMaps, or other configuration files containing plaintext credentials stored as environment variables or volume-mounted files.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Container process reading a mounted ConfigMap that contains a password or API key in plaintext",
      "kubectl exec session running `env` to dump environment variables containing credentials",
      "File read on a mounted volume containing application config with embedded credentials"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs showing reads of ConfigMaps or pod specs that contain credential data. Also API server queries to retrieve pod environment variable definitions.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "kubectl get pod <name> -o yaml returning env vars with credential keys",
      "API server: GET /api/v1/namespaces/<ns>/configmaps/<name> returning base64-encoded credentials",
      "kubectl describe deployment showing environment variables with secret-looking values"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Commands that extract environment variables or read configuration files from running containers.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`kubectl exec <pod> -- env | grep -i password` or `printenv` inside a container",
      "`cat /app/config.yaml` inside a container revealing database credentials",
      "Shell command accessing .env files mounted from Kubernetes ConfigMaps or Secrets"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0412",
    "name": "Detect Access or Search for Unsecured Credentials Across Platforms",
    "summary": "AN1158 flags unusual access to container image layers or mounted secrets. The technique involves credentials in config files which are a superset of the mounted secret path.",
    "url": "https://attack.mitre.org/techniques/T1552/",
    "data_component_refs": ["File Access", "Application Log Content", "Command Execution"]
  }
]
```

**Analytics:** AN1153-AN1159 (T1552 parent). AN1158 (container/mounted secrets) is closest.

### Notes / Confidence

- **Confirmed:** STIX T1552 parent `x_mitre_data_sources` includes `Application Log: Application Log Content`, `Command: Command Execution`, `File: File Access`.
- **Likely:** The specific K8s surface is ConfigMaps with embedded credentials and pod environment variables. The STIX data sources are appropriate but were designed for generic file credential access.
- **Possible:** Static analysis of image layers (checking for credential patterns in Dockerfiles or config files baked into images) is a preventive/discovery control not currently a MITRE data component but relevant operationally.

### Open Questions

- Does the project use a secrets scanner (e.g., Trivy, detect-secrets) in the CI pipeline to prevent credentials from entering ConfigMaps or images?

---

## 9. MS-TA9028 -- Access Managed Identity Credentials

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://attack.mitre.org/techniques/T1552/005/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20managed%20identity%20credentials/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no IMDS-specific K8s rule)
- No Falco rule specifically for IMDS access found
- No Atomic Red Team K8s test for T1552.005

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "User Account Authentication",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Authentication events using managed identity tokens obtained from the cloud IMDS endpoint. These tokens authenticating to cloud APIs from unexpected sources indicate theft.",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Cloud audit log: managed identity token used from a source IP that is not a known node IP",
      "Azure Activity Log: operation performed by a managed identity from an unexpected client application",
      "AWS CloudTrail: AssumeRole using pod identity from a non-pod source IP"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network connections from container processes to the cloud IMDS endpoint (169.254.169.254). Expected only from specific workloads; unexpected access from a container indicates IMDS token theft.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "HTTP GET to 169.254.169.254/metadata/identity/oauth2/token from a pod not configured with managed identity",
      "Azure IMDS endpoint queried from within a container that is not in the approved workload identity list",
      "Network policy violation: pod egress to 169.254.169.254 blocked and logged"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Cloud provider audit logs (Azure Activity Log, AWS CloudTrail) recording API calls made with managed identity tokens that originated from a container workload.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Azure: Resource Manager API called with a managed identity token by an unexpected resource",
      "AWS: EC2 instance metadata credentials used from a container pod IP not matching expected node",
      "GCP: Workload Identity token used for Cloud API access from unexpected service account binding"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0001",
    "name": "Detect Access to Cloud Instance Metadata API (IaaS)",
    "summary": "AN0001 identifies attempts to reach cloud metadata endpoints like 169.254.169.254 from virtual machines or containerized environments, covering SSRF exploitation methods.",
    "url": "https://attack.mitre.org/techniques/T1552/005/",
    "data_component_refs": ["Network Traffic Flow", "User Account Authentication", "Application Log Content"]
  }
]
```

**Analytics:** AN0001 (T1552.005 specific).

### Notes / Confidence

- **Confirmed:** STIX T1552.005 `x_mitre_data_sources`: `User Account: User Account Authentication`. This is the only STIX entry; it is sparse.
- **Likely:** `Network Traffic: Network Traffic Flow` is the most actionable K8s detection signal (monitoring IMDS endpoint access). Included via community inference.
- **Confirmed:** MS page explicitly states the attack involves querying IMDS from within a compromised pod.
- **Note:** STIX T1552.005 has only one data source. Both `Network Traffic: Network Traffic Flow` and `Application Log: Application Log Content` are community inferences, not in STIX.

### Open Questions

- Does the cluster restrict pod egress to 169.254.169.254 via NetworkPolicy or cloud firewall rules?
- Is AAD Pod Identity or Azure Workload Identity in use? The detection surface differs between the two.

---

## 10. MS-TA9029 -- Access the K8S API Server

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1613/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20the%20K8S%20API%20server/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_potential_enumeration_activity.yml (fetched; tagged `attack.t1613`)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml (fetched; covers unauthorized API access)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Contact K8S API Server From Container` covers container-to-API access)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1613/T1613.yaml (fetched; container platform tests)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Container Enumeration",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Events recording enumeration of container or pod resources via the Kubernetes API. An attacker querying the API server for pods, deployments, or services is performing container enumeration.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "kubectl get pods --all-namespaces returning full cluster workload inventory",
      "API server audit: list verb on pods, deployments, replicasets by an unexpected principal",
      "Falco: Contact K8S API Server From Container rule firing for a service account making cluster-wide list calls"
    ]
  },
  {
    "id": null,
    "name": "Pod Enumeration",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Events recording enumeration of pod objects in Kubernetes. Listing pods reveals running workloads, namespaces, labels, and associated service accounts.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "API audit: GET /api/v1/pods returning full pod list across namespaces",
      "kubectl get pod -o wide revealing node assignments and IP addresses",
      "Repeated pod list queries by a service account with no deployment-management role"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs. All API server interactions are logged here; anomalous enumeration patterns are the primary K8s detection mechanism for this technique.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Burst of list/get requests across multiple resource types from a single principal in a short window",
      "API server access from a source IP not matching any known node or administrator workstation",
      "Requests to /apis/ (API discovery endpoint) indicating initial cluster reconnaissance"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0490",
    "name": "Detection Strategy for Container and Resource Discovery",
    "summary": "AN1352 detects anomalous API calls to Docker or Kubernetes such as kubectl get pods and kubectl get nodes, correlating with user context and network activity.",
    "url": "https://attack.mitre.org/techniques/T1613/",
    "data_component_refs": ["Container Enumeration", "Pod Enumeration", "Application Log Content"]
  }
]
```

**Analytics:** AN1352 (T1613).

**Sigma rules:**
- `rules/application/kubernetes/audit/kubernetes_audit_potential_enumeration_activity.yml` (tagged `attack.t1613`)
- `rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml`

**Falco:** `Contact K8S API Server From Container` (tagged `mitre_discovery`).

**Atomic Red Team:** T1613 has container-platform tests (docker ps, container inspection).

### Notes / Confidence

- **Confirmed:** STIX T1613 `x_mitre_data_sources`: `Pod: Pod Enumeration`, `Container: Container Enumeration`. These are the exact STIX entries.
- **Confirmed:** Sigma rule for enumeration exists, tagged `attack.t1613`.
- **Confirmed:** Falco `Contact K8S API Server From Container` is a stable rule covering container-to-API interactions.
- **Likely:** `Application Log: Application Log Content` is the operational implementation of both Pod Enumeration and Container Enumeration in K8s (everything goes through API server audit). Adding it as a component improves actionability.

### Open Questions

- Is API server audit logging enabled at the Request/RequestResponse level? Metadata-only audit policies will miss response bodies containing sensitive resource data.

---

## 11. MS-TA9030 -- Access Kubelet API

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1613/ (fetched; same as MS-TA9029)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20Kubelet%20API/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no Kubelet-specific Sigma rule found)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no specific Kubelet API rule identified)
- No Atomic Red Team test specifically for Kubelet API access

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Container Enumeration",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Container enumeration events via the Kubelet read-only API (TCP 10255). Queries to /pods/ expose all running containers on the node without authentication.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "HTTP GET to <node-ip>:10255/pods returning the full pod manifest list",
      "Access to <node-ip>:10255/spec returning node hardware and resource information",
      "Network flow showing a pod IP making requests to port 10255 on node IPs"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network connections to the Kubelet ports (10250 authenticated, 10255 read-only unauthenticated) from unexpected sources. Container-to-Kubelet traffic is anomalous unless explicitly required.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Pod-sourced TCP connection to port 10255 on any node IP",
      "External-sourced connection to port 10250 attempting to use kubectl exec via Kubelet directly",
      "Network policy audit log: egress to node:10255 blocked for a non-system pod"
    ]
  },
  {
    "id": null,
    "name": "Pod Enumeration",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Pod listing via Kubelet endpoint rather than the API server. The /pods/ endpoint on port 10255 returns pod specs without authentication, enabling enumeration that bypasses API server audit logging.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "HTTP request to http://<kubelet-ip>:10255/pods from a container workload",
      "Response containing pod specs with environment variables and volume mounts",
      "Access log from node-level HTTP server on port 10255 (if enabled)"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0490",
    "name": "Detection Strategy for Container and Resource Discovery",
    "summary": "AN1352 covers container metadata endpoint queries. Kubelet port 10255 is a container metadata endpoint and falls within this strategy's scope.",
    "url": "https://attack.mitre.org/techniques/T1613/",
    "data_component_refs": ["Container Enumeration", "Pod Enumeration", "Network Traffic Flow"]
  }
]
```

**Analytics:** AN1352.

### Notes / Confidence

- **Confirmed:** STIX T1613 `x_mitre_data_sources`: `Pod: Pod Enumeration`, `Container: Container Enumeration`.
- **Confirmed:** MS page describes Kubelet port 10255 as unauthenticated read-only; disabling it is the primary mitigation.
- **Likely:** `Network Traffic: Network Traffic Flow` is included via inference; it is the primary detective control if the Kubelet API is disabled and attempts are still made.
- **Note:** If Kubelet port 10255 is disabled (as recommended), this technique is mitigated before detection is needed. The detection strategy assumes the port may still be open.
- No Sigma or Falco rules specifically for Kubelet API access were found. This is a gap.

### Open Questions

- Is Kubelet port 10255 disabled in this cluster? If so, detection is moot.
- Is NodeRestriction admission plugin enabled to limit Kubelet permissions?

---

## 12. MS-TA9031 -- Network Mapping

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1046/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Network%20mapping/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no network-scan specific K8s rule)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no T1046 specific rule found)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.yaml (fetched; `Network Service Discovery for Containers` test exists)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network flow data showing inter-pod traffic. Network mapping from a compromised container generates abnormal east-west traffic patterns: sequential port probes across pod CIDR ranges.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Pod generating TCP SYN packets to multiple pod IPs across the cluster CIDR in rapid succession",
      "Single pod IP contacting dozens of destination IPs across multiple ports within a short time window",
      "nmap or similar scanner fingerprinted in netflow data from a container source IP"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Recording of network scanning commands executed inside containers, such as nmap, netcat, masscan, or custom shell scripts performing port sweeps.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "nmap, masscan, or ncat process execution detected inside a container by Falco or auditd",
      "Shell script invoking a for-loop with nc -z across a /24 subnet",
      "Atomic Red Team T1046 container test: image built and scanner script executed"
    ]
  },
  {
    "id": null,
    "name": "Cloud Service Enumeration",
    "data_source_id": "DS0025",
    "data_source_name": "Cloud Service",
    "definition": "Cloud provider API calls that enumerate compute instances, VPCs, or subnets from a compromised pod, providing network topology information beyond the cluster.",
    "url": "https://attack.mitre.org/datasources/DS0025/",
    "relevant_events": [
      "AWS DescribeInstances or DescribeSubnets called from a pod using node instance role credentials",
      "Azure Resource Manager API: list virtual machines called from within a container",
      "GCP: compute.instances.list called using workload identity from a pod"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0376",
    "name": "Behavioral Detection Strategy for Network Service Discovery Across Platforms",
    "summary": "AN1060 specifically detects lateral discovery or container breakout using netcat, curl, or custom binaries probing services within the same namespace/VPC subnet.",
    "url": "https://attack.mitre.org/techniques/T1046/",
    "data_component_refs": ["Network Traffic Flow", "Command Execution"]
  }
]
```

**Analytics:** AN1057, AN1058, AN1059, AN1060. AN1060 is container-specific.

**Atomic Red Team:** `Network Service Discovery for Containers` test exists for T1046.

### Notes / Confidence

- **Confirmed:** STIX T1046 `x_mitre_data_sources`: `Network Traffic: Network Traffic Flow`, `Command: Command Execution`, `Cloud Service: Cloud Service Enumeration`.
- **Confirmed:** Atomic Red Team has a container-platform test for T1046.
- **Confirmed:** MS page states Kubernetes has no default pod-to-pod communication restrictions, making network mapping particularly effective.

### Open Questions

- Are NetworkPolicies implemented to restrict pod-to-pod communication? Without them, network mapping is trivially unobstructed.

---

## 13. MS-TA9033 -- Instance Metadata API

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://attack.mitre.org/techniques/T1552/005/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Instance%20Metadata%20API/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no IMDS-specific rule)
- No Falco rule specifically for IMDS access found
- No Atomic Red Team K8s test for T1552.005

**Note:** This technique maps to the same MITRE IDs as MS-TA9028 (T1552, T1552.005). The MS tactic here is Discovery rather than Credential Access, reflecting the metadata/reconnaissance aspect (gathering node information: network config, disk, identities) rather than just stealing a token.

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "User Account Authentication",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Authentication events from tokens obtained via IMDS, used to access cloud resources. In the Discovery context, IMDS queries are used to enumerate node metadata even without follow-on credential use.",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Cloud API call authenticated with an IMDS-derived token from an unexpected pod source IP",
      "Azure IMDS: request to /metadata/instance returning node network, disk, and identity metadata",
      "AWS IMDS: request to /latest/meta-data/ returning instance type, region, and IAM role information"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network connections to the IMDS IP (169.254.169.254) from container workloads. Any pod communicating with this endpoint is a candidate for investigation.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "HTTP GET to 169.254.169.254 from a container not in the approved IMDS-consumer list",
      "Network policy audit: egress to 169.254.169.254/32 blocked and logged for a suspicious pod",
      "Volume of IMDS queries from a single pod exceeding normal application patterns"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "HTTP request and response content for IMDS API calls. The response reveals what metadata was accessed (identities, network config, credentials).",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "IMDS response containing managed identity token captured in an HTTP proxy log",
      "Full path enumeration of IMDS endpoints (e.g., /metadata/instance/network, /metadata/identity/) indicating discovery behavior",
      "SSRF exploitation using a pod-hosted web app to relay IMDS requests"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0001",
    "name": "Detect Access to Cloud Instance Metadata API (IaaS)",
    "summary": "AN0001 identifies attempts to reach cloud metadata endpoints like 169.254.169.254 from VMs or containerized environments.",
    "url": "https://attack.mitre.org/techniques/T1552/005/",
    "data_component_refs": ["Network Traffic Flow", "Network Traffic Content", "User Account Authentication"]
  }
]
```

**Analytics:** AN0001 (T1552.005).

### Notes / Confidence

- **Confirmed:** STIX T1552.005 `x_mitre_data_sources`: `User Account: User Account Authentication`.
- **Likely:** `Network Traffic: Network Traffic Flow` and `Network Traffic: Network Traffic Content` are community inferences (not in STIX T1552.005) but are the primary actionable detection signals.
- **Confirmed:** MS page positions this as a Discovery technique because the primary value is node metadata (not just credential theft), distinguishing it from MS-TA9028.
- **Note:** MS-TA9028 and MS-TA9033 share the same MITRE sub-technique (T1552.005). The data components are nearly identical; the distinction is in the MS tactic context (Credential Access vs. Discovery).

### Open Questions

- Same as MS-TA9028: are network policies blocking pod egress to 169.254.169.254?

---

## 14. MS-TA9034 -- Cluster Internal Networking

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1210/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster%20internal%20networking/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no specific T1210 K8s rule)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Netcat Remote Code Execution in Container` adjacent)
- No Atomic Red Team test specifically for K8s lateral movement via internal networking

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Packet-level content of inter-pod traffic. Exploit payloads directed at vulnerable services running in other pods traverse the cluster network unencrypted by default.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Exploit payload detected in traffic between two pods in the same namespace",
      "HTTP requests from pod A to pod B containing injection patterns or vulnerability probe strings",
      "Service mesh (Istio/Envoy) access log showing unexpected cross-service calls with anomalous payloads"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Application logs from target services recording exploit attempts, connection anomalies, or errors caused by lateral movement traffic.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Web application log: 500 error from a request containing a deserialization exploit payload",
      "Database service log: authentication failure from a pod IP not in the approved client list",
      "Service crash or restart in kube-system correlated with unusual inbound network traffic"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Flow-level data showing inter-pod connection patterns. Unexpected pod-to-pod connections violating expected application topology are an indicator of lateral movement.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Pod establishing a connection to another pod's port that is not part of the defined service graph",
      "Flow data showing a compromised pod connecting to multiple other pods sequentially (scanning then exploiting)",
      "NetworkPolicy violation log: pod attempted connection to restricted destination"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0118",
    "name": "Exploitation of Remote Services -- multi-platform lateral movement detection",
    "summary": "AN0328 links inbound network access to services with subsequent daemon crashes or shell spawning, covering service exploitation within the cluster.",
    "url": "https://attack.mitre.org/techniques/T1210/",
    "data_component_refs": ["Network Traffic Content", "Application Log Content", "Network Traffic Flow"]
  }
]
```

**Analytics:** AN0327, AN0328, AN0329, AN0330. AN0328 (Linux/service-level) is most applicable in K8s context.

### Notes / Confidence

- **Confirmed:** STIX T1210 `x_mitre_data_sources`: `Network Traffic: Network Traffic Content`, `Application Log: Application Log Content`.
- **Confirmed:** MS page explicitly states Kubernetes default networking allows unrestricted pod-to-pod traffic.
- **Likely:** `Network Traffic: Network Traffic Flow` is not in STIX T1210 but is the most practical K8s control for detecting anomalous lateral movement paths.

### Open Questions

- Is a service mesh (Istio, Linkerd) deployed? mTLS between pods would encrypt traffic, reducing Network Traffic Content detection value. The flow-level detection remains valid.
- Are NetworkPolicies enforced that define the expected service communication graph?

---

## 15. MS-TA9035 -- CoreDNS Poisoning

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1557/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/CoreDNS%20poisoning/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; `kubernetes_audit_change_admission_controller.yml` and `kubernetes_audit_rbac_permisions_listing.yml` are adjacent; no CoreDNS-specific rule)
- No Falco rule specifically for CoreDNS ConfigMap modification found
- No Atomic Red Team test for CoreDNS poisoning

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs recording modifications to the CoreDNS ConfigMap in the kube-system namespace. This is the primary indicator of CoreDNS poisoning.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit: verb=update/patch, objectRef.resource=configmaps, objectRef.name=coredns, objectRef.namespace=kube-system",
      "Change to the Corefile content in the coredns ConfigMap not matching a change management record",
      "CoreDNS pod restart following a ConfigMap modification (indicating the new config was applied)"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "DNS query and response traffic showing poisoned resolution. Requests for legitimate service names returning unexpected IPs indicate active CoreDNS poisoning.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "DNS response for a known internal service returning an unexpected IP (not a cluster service IP)",
      "DNS traffic showing unexpected rewrites or rewrite rules added to Corefile directing traffic to attacker infrastructure",
      "Cluster DNS query patterns showing increased NXDOMAIN or redirect responses"
    ]
  },
  {
    "id": null,
    "name": "Windows Registry Key Modification",
    "data_source_id": "DS0024",
    "data_source_name": "Windows Registry",
    "definition": "Note: STIX T1557 includes Windows Registry modification as a data source (covering AiTM via registry-based DNS config changes on Windows nodes). In K8s context this is replaced by ConfigMap modification in the API server audit.",
    "url": "https://attack.mitre.org/datasources/DS0024/",
    "relevant_events": [
      "NOT applicable in pure-Linux K8s clusters; included for completeness per STIX T1557 data sources",
      "On Windows worker nodes: DNS client configuration registry changes in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
    ]
  },
  {
    "id": null,
    "name": "Service Creation",
    "data_source_id": "DS0019",
    "data_source_name": "Service",
    "definition": "Creation of new Kubernetes Services or ExternalName services that redirect cluster DNS resolution to attacker-controlled endpoints.",
    "url": "https://attack.mitre.org/datasources/DS0019/",
    "relevant_events": [
      "New ExternalName service created pointing a legitimate service name to an external attacker IP",
      "Kubernetes Service creation that shadows an existing service name in a different namespace",
      "API audit: service creation by a non-privileged user in kube-system namespace"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0296",
    "name": "Detect Adversary-in-the-Middle via Network and Configuration Anomalies",
    "summary": "AN0823 identifies suspicious DNS poisoning attempts and unauthorized configuration modifications. AN0824 monitors unauthorized config file edits correlated with unexpected network sessions.",
    "url": "https://attack.mitre.org/techniques/T1557/",
    "data_component_refs": ["Application Log Content", "Network Traffic Content", "Service Creation"]
  }
]
```

**Analytics:** AN0823, AN0824, AN0825, AN0826. AN0823 and AN0824 are most applicable.

### Notes / Confidence

- **Confirmed:** STIX T1557 `x_mitre_data_sources`: `Application Log: Application Log Content`, `Network Traffic: Network Traffic Content`, `Windows Registry: Windows Registry Key Modification`, `Network Traffic: Network Traffic Flow`, `Service: Service Creation`.
- **Confirmed:** MS page confirms the attack vector is modifying the coredns ConfigMap in kube-system namespace.
- **Likely:** `Service: Service Creation` is the Kubernetes-native data source for detecting ExternalName service poisoning, which is functionally equivalent to DNS poisoning. This is community inference for the K8s context.
- **Note:** Windows Registry modification is in STIX T1557 but is not applicable in Linux K8s clusters. Flagged for completeness.

### Open Questions

- Is RBAC configured to restrict configmap update access in kube-system to only the CoreDNS controller service account?
- No Sigma or Falco rule specifically for CoreDNS ConfigMap modification exists. This is a detection gap.

---

## 16. MS-TA9036 -- ARP Poisoning and IP Spoofing

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1557/ (fetched; same as MS-TA9035)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/ARP%20poisoning%20and%20IP%20spoofing/ (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no ARP-specific K8s rule)
- No Falco rule specifically for ARP poisoning in containers found
- No Atomic Red Team test for K8s ARP poisoning

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network flow data showing anomalous ARP behavior or IP spoofing patterns at the pod network layer. Containers with NET_RAW capability can craft spoofed ARP or IP packets.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Gratuitous ARP replies from a pod claiming an IP address belonging to another pod",
      "Network traffic from a pod using a source IP that does not match the pod's assigned IP",
      "ARP cache poisoning detected by a CNI plugin or network monitoring agent on the node"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Packet-level content showing ARP packets or IP packets with spoofed source addresses traversing the cluster network bridge.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "ARP packet with sender MAC not matching the expected MAC for the sender IP on the bridge",
      "ICMP packet with source IP spoofed to another pod's IP intercepted at the node bridge",
      "Credential capture from an intercepted pod-to-pod communication session (e.g., DNS query with credentials)"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes audit logs or CNI plugin logs recording anomalous network events attributable to ARP spoofing or IP spoofing within the pod network.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "CNI plugin log: IP address conflict detected between pods",
      "Node-level kernel log: duplicate address detection failure for pod IP",
      "Service mesh log: mTLS certificate mismatch indicating traffic interception"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0296",
    "name": "Detect Adversary-in-the-Middle via Network and Configuration Anomalies",
    "summary": "AN0823 identifies suspicious ARP poisoning attempts. AN0824 monitors unauthorized ARP broadcasts correlated with unexpected network sessions.",
    "url": "https://attack.mitre.org/techniques/T1557/",
    "data_component_refs": ["Network Traffic Flow", "Network Traffic Content", "Application Log Content"]
  }
]
```

**Analytics:** AN0823, AN0824. Both reference ARP poisoning detection.

### Notes / Confidence

- **Confirmed:** STIX T1557 `x_mitre_data_sources`: `Application Log: Application Log Content`, `Network Traffic: Network Traffic Content`, `Network Traffic: Network Traffic Flow`, `Service: Service Creation`.
- **Confirmed:** MS page states the attack requires NET_RAW capability and references CVE-2021-1677.
- **Confirmed:** Removing the NET_RAW capability (via securityContext) is the primary preventive control.
- **Possible:** mTLS via a service mesh (Istio/Linkerd) is the best detective control: intercepted traffic will fail certificate validation.

### Open Questions

- Is NET_RAW capability dropped by default in this cluster's security policies (PSP, OPA, Kyverno)?
- Is a service mesh with mTLS enforced? This is the most effective detection for active interception.

---

## 17. MS-TA9037 -- Images from a Private Registry

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1530/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/images%20from%20a%20private%20registry/ (fetched via lowercase slug)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no registry-access rule)
- No Falco rule specifically for private registry credential theft found
- No Atomic Red Team test specifically for T1530 in K8s context

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Cloud Storage Access",
    "data_source_id": "DS0010",
    "data_source_name": "Cloud Storage",
    "definition": "Access events to cloud-hosted container registries (Azure Container Registry, Amazon ECR, Google Artifact Registry). An attacker using stolen credentials to pull private images generates cloud audit events.",
    "url": "https://attack.mitre.org/datasources/DS0010/",
    "relevant_events": [
      "Azure Container Registry: pull operation from an IP not associated with a known node or CI/CD system",
      "AWS ECR: GetAuthorizationToken or BatchGetImage called using node instance role from outside the cluster",
      "GCP Artifact Registry: pull event using workload identity token from a pod not in the image-pull service account list"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes audit logs showing pod creation events with image pull secrets being accessed, or node-level container runtime logs showing registry authentication and image pull operations.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit: list/get operation on secrets of type kubernetes.io/dockerconfigjson",
      "Container runtime log: image pull from private registry using a managed identity or node role credential",
      "Kubernetes event: SuccessfulPull event for an image that is not in the approved image allowlist"
    ]
  },
  {
    "id": null,
    "name": "Image Metadata",
    "data_source_id": "DS0007",
    "data_source_name": "Image",
    "definition": "Container image metadata including registry source, digest, and pull history. Unexpected image pulls from private registries by unauthorized principals indicate credential abuse.",
    "url": "https://attack.mitre.org/datasources/DS0007/",
    "relevant_events": [
      "New container image pulled from a private registry not previously accessed by this cluster",
      "Image pull using node managed identity rather than a per-pod image pull secret",
      "Container image inventory audit revealing images from unexpected registry namespaces"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0484",
    "name": "Multi-Platform Cloud Storage Exfiltration Behavior Chain",
    "summary": "AN1328-AN1330 cover spike in access from new IAM roles and OAuth token abuse for data access. The container registry pull scenario maps to AN1328 (new IAM user/role accessing cloud storage).",
    "url": "https://attack.mitre.org/techniques/T1530/",
    "data_component_refs": ["Cloud Storage Access", "Application Log Content", "Image Metadata"]
  }
]
```

**Analytics:** AN1328, AN1329, AN1330.

### Notes / Confidence

- **Confirmed:** STIX T1530 `x_mitre_data_sources`: `Cloud Storage: Cloud Storage Access`. This is the only STIX data source.
- **Likely:** `Application Log: Application Log Content` and `Image: Image Metadata` are community inferences for the K8s-specific surface (API server audit + container runtime logs). Not in STIX T1530 directly.
- **Confirmed:** MS page describes two specific attack vectors: managed identity tokens (Azure) and EC2ContainerRegistryReadOnly IAM role (AWS).

### Open Questions

- Are image pull secrets stored as Kubernetes secrets (accessible to those who can list secrets) or handled via node-level managed identity?
- Is an image admission policy (OPA/Kyverno) enforcing pull from an approved registry allowlist?

---

## 18. MS-TA9041 -- Collecting Data from Pod

### Authoritative Sources Fetched

- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Collecting%20Data%20from%20Pod/ (fetched)
- No MITRE ATT&CK technique ID assigned. The MS page maps this to Collection tactic; no T#### ID is listed.
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml (adjacent; exec is the prerequisite for kubectl cp)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no specific kubectl cp rule)

**Note:** MITRE field is null for this technique. Data components are derived from the MS technique description.

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs recording kubectl cp operations (which invoke exec) and Kubelet Checkpoint API calls. These are the primary observable events for this technique.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit: verb=create, subresource=exec, objectRef.resource=pods, containing tar binary invocation (kubectl cp backend)",
      "Kubelet Checkpoint API: POST request to /checkpoint/<namespace>/<pod>/<container>",
      "API audit: cp-related exec command referencing /tmp or external paths in the container"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Commands executed within or against pods for data collection, including kubectl cp (backed by exec+tar), kubectl exec for manual file reading, and Kubelet checkpoint invocations.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`kubectl cp <pod>:/sensitive/file /local/path` captured in audit log as exec with tar",
      "kubectl exec session running `cat`, `find`, or `tar` to archive files within a pod",
      "Direct Kubelet Checkpoint API POST call creating a memory checkpoint of a running container"
    ]
  },
  {
    "id": null,
    "name": "Container Enumeration",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Container-level events including exec sessions and checkpoint operations. The Kubelet Checkpoint API creates a stateful container copy, which is a container-level operation.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "Container checkpoint created via Kubelet API; checkpoint file accessible on node",
      "Container exec session opened from a non-CI/CD principal performing file copy operations",
      "Container process list showing tar, zip, or other archiving tools not in the image's declared entrypoint"
    ]
  },
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "File read events within containers during data collection operations. Sensitive files (encryption keys, application data, configuration) being read indicate collection activity.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "auditd/Falco: file open for read on /app/data/, /var/lib/, or application-specific data paths by a non-entrypoint process",
      "kubectl cp triggering open() syscalls on sensitive file paths within the container",
      "Checkpoint file on node containing memory pages with plaintext credentials or encryption keys"
    ]
  }
]
```

### Recommended `detection_strategies[]`

There are no MITRE DET/AN IDs for this technique (no MITRE T-ID assigned). Detection guidance is derived from MS source material and adjacent MITRE entries.

```json
[]
```

**Sigma rule (adjacent):** `rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml` detects exec operations; kubectl cp depends on exec, so this rule partially covers the technique.

### Notes / Confidence

- **Confirmed:** MS page describes two attack methods: `kubectl cp` (exec+tar) and Kubelet Checkpoint API.
- **Confirmed:** There is no MITRE T#### ID for this technique. Data components are inferred from the MS description.
- **Likely:** DS0022 `File: File Access`, DS0032 `Container: Container Enumeration`, DS0017 `Command: Command Execution`, and DS0015 `Application Log: Application Log Content` are the appropriate data sources based on the attack pattern, derived by analogy with T1213 (Data from Information Repositories) and T1005 (Data from Local System).
- **Note:** The Kubelet Checkpoint API is a relatively new feature (alpha in K8s 1.25, beta in 1.30). Detection may not be covered by most existing security tools.

### Open Questions

- Is the Kubelet Checkpoint API enabled in this cluster? If on K8s < 1.25, it is not available.
- Is MS-TA9041 intended to receive a MITRE T-ID mapping eventually? This should be tracked.

---

## 19. MS-TA9038 -- Data Destruction

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1485/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/ (fetched)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; `Remove Bulk Data from Disk` tagged `T1485`)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml (fetched; no K8s container tests; Windows, Linux, GCP, ESXi tests only)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; `kubernetes_audit_deployment_deleted.yml` is adjacent)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "File Deletion",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Deletion of files within container volumes or host-path mounts. Destructive commands (rm -rf, shred, dd) targeting mounted persistent volume data are the primary indicator.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Container process executing `rm -rf /data/*` on a mounted PersistentVolume",
      "Falco: Remove Bulk Data from Disk fired inside a container accessing a host or volume path",
      "auditd: unlink() syscalls on critical application data files within a pod"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "New process creation within containers running destructive tools such as rm, shred, dd, or custom wiper binaries.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Container spawning `dd if=/dev/zero of=/data/db/...` to overwrite database files",
      "Process `shred` or `wipe` running inside a pod with access to persistent storage",
      "AN0416: container process executes destructive file operations inside volume mounts or host paths"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Destructive kubectl or API commands that delete Kubernetes workload resources, PersistentVolumeClaims, Deployments, or namespace objects.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "`kubectl delete namespace <ns>` deleting all workloads and their data",
      "`kubectl delete pvc --all` removing persistent volume claims and triggering volume deletion",
      "API audit: delete verb on deployments, statefulsets, or PVCs by an unexpected principal"
    ]
  },
  {
    "id": null,
    "name": "Instance Deletion",
    "data_source_id": "DS0030",
    "data_source_name": "Instance",
    "definition": "Cloud instance deletion events. In cloud-hosted K8s (AKS, EKS, GKE), an attacker with cloud credentials may delete the underlying node instances, taking down the cluster.",
    "url": "https://attack.mitre.org/datasources/DS0030/",
    "relevant_events": [
      "Azure: VM delete operation on a node pool instance",
      "AWS: TerminateInstances called on EKS worker node EC2 instances",
      "GCP: compute.instances.delete on GKE node pool members"
    ]
  },
  {
    "id": null,
    "name": "Volume Deletion",
    "data_source_id": "DS0034",
    "data_source_name": "Volume",
    "definition": "Cloud storage volume deletion events, including PersistentVolume backing storage (EBS, Azure Disk, GCP PD) being deleted via cloud APIs.",
    "url": "https://attack.mitre.org/datasources/DS0034/",
    "relevant_events": [
      "AWS EBS volume deletion for a disk that was backing a K8s PersistentVolume",
      "Azure: managed disk delete on a volume backing a StatefulSet",
      "Kubernetes PersistentVolume reclaim policy set to Delete, triggered by PVC deletion"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0146",
    "name": "Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns",
    "summary": "AN0416 specifically addresses container processes executing destructive file operations inside volume mounts or host paths. AN0414 covers cloud infrastructure deletion.",
    "url": "https://attack.mitre.org/techniques/T1485/",
    "data_component_refs": ["File Deletion", "Process Creation", "Command Execution", "Instance Deletion", "Volume Deletion"]
  }
]
```

**Analytics:** AN0411-AN0416. AN0414 (cloud infrastructure deletion) and AN0416 (container destructive operations) are most relevant.

**Falco:** `Remove Bulk Data from Disk` tagged `T1485`, covers host and container contexts.

### Notes / Confidence

- **Confirmed:** STIX T1485 `x_mitre_data_sources`: `Snapshot: Snapshot Deletion`, `Process: Process Creation`, `File: File Deletion`, `Image: Image Deletion`, `Instance: Instance Deletion`, `File: File Modification`, `Volume: Volume Deletion`, `Cloud Storage: Cloud Storage Deletion`, `Command: Command Execution`.
- **Confirmed:** Falco `Remove Bulk Data from Disk` rule exists, tagged `T1485`.
- **Confirmed:** No Atomic Red Team K8s container tests exist for T1485.
- **Likely:** MS page focuses on Kubernetes-level destruction (delete deployments, configs, storage). Cloud-level destruction (VM, volume deletion) is an escalated variant.

### Open Questions

- Are PersistentVolume reclaim policies set to Retain (safer) or Delete? The Delete policy makes PVC deletion automatically destructive.
- Are cloud-level resource deletions restricted via IAM policies preventing the K8s service principal from deleting underlying compute/storage?

---

## 20. MS-TA9039 -- Resource Hijacking

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1496/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Resource%20hijacking/ (fetched)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no specific mining rule identified in excerpt, but relevant rules may exist)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1496/T1496.yaml (fetched; CPU load simulation tests, no K8s tests)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no specific resource hijacking rule)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "New processes within containers running cryptocurrency mining tools or CPU/GPU intensive workloads inconsistent with the expected container function.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Container spawning a process named xmrig, cpuminer, or similar mining binary",
      "Process with high CPU usage executing from /tmp or /dev/shm (non-standard paths) inside a container",
      "Container running a process not present in the declared image entrypoint or CMD"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Network connections to known mining pool endpoints or stratum protocol traffic from within the cluster. Mining operations require connectivity to external pool servers.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Pod establishing outbound TCP connection to a known mining pool IP or domain (stratum port 3333, 4444, 14444)",
      "Container generating consistent high-volume outbound traffic to a single external endpoint",
      "DNS resolution of known mining pool domains (pool.minexmr.com, xmrpool.eu) from within the cluster"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Commands that download or execute mining binaries inside containers, often using curl/wget followed by execution of a downloaded payload.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "Container executing `curl -o /tmp/miner <url> && chmod +x /tmp/miner && /tmp/miner`",
      "kubectl exec session installing and running a miner inside a running pod",
      "Container deployment via kubectl apply of a DaemonSet running a mining image on every node"
    ]
  },
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "New outbound connections from containers to mining infrastructure. The consistent pattern of mining pool connectivity is highly anomalous in production workloads.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "New TCP connection to stratum+tcp:// endpoints from a container",
      "WebSocket connection to a browser-based mining service from a container",
      "Container repeatedly reconnecting to the same external IP on port 3333 or 4444"
    ]
  },
  {
    "id": null,
    "name": "Host Status",
    "data_source_id": "DS0013",
    "data_source_name": "Sensor Health",
    "definition": "Node-level resource utilization metrics. Sustained CPU spike on a node hosting a compromised container is a secondary indicator of mining activity.",
    "url": "https://attack.mitre.org/datasources/DS0013/",
    "relevant_events": [
      "Node CPU usage sustained above 90% with no corresponding legitimate workload scale-out",
      "cgroup CPU throttling events for a container not under any active load",
      "Kubernetes metrics-server: pod CPU request vs. actual usage anomaly (actual >> requested)"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0267",
    "name": "Resource Hijacking Detection Strategy",
    "summary": "AN0745 monitors high CPU usage within containers running mining tools or proxy utilities. AN0744 covers cloud VM CPU spikes with mining pool traffic.",
    "url": "https://attack.mitre.org/techniques/T1496/",
    "data_component_refs": ["Process Creation", "Network Traffic Flow", "Network Connection Creation", "Host Status", "Command Execution"]
  }
]
```

**Analytics:** AN0741-AN0746. AN0744 (cloud VM) and AN0745 (container) are most relevant.

### Notes / Confidence

- **Confirmed:** STIX T1496 `x_mitre_data_sources`: `Network Traffic: Network Traffic Flow`, `File: File Creation`, `Network Traffic: Network Connection Creation`, `Sensor Health: Host Status`, `Process: Process Creation`, `Command: Command Execution`.
- **Confirmed:** MS page describes cryptocurrency mining as the primary use case.
- **Likely:** Mining pool destination IPs/domains are well-documented in threat intelligence feeds; integrating TI into network monitoring is the most effective detection.
- No Atomic Red Team K8s container test for resource hijacking exists.

### Open Questions

- Are egress NetworkPolicies in place to restrict outbound connectivity to only approved destinations? That would block mining pool connectivity.
- Is the cluster's resource quota system configured to detect runaway CPU consumption?

---

## 21. MS-TA9040 -- Denial of Service

### Authoritative Sources Fetched

- https://attack.mitre.org/techniques/T1498/ (fetched)
- https://attack.mitre.org/techniques/T1499/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Denial%20of%20service/ (fetched)
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched; no specific DoS K8s rule)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1498/T1498.yaml (fetched; network flooding tests, Linux/macOS)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; no DoS-specific K8s rule)

### Recommended `data_components[]`

```json
[
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "High-volume network flows indicating a flood attack originating from or directed at cluster endpoints. Covers T1498 (network-level DoS) from K8s workloads.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Pod generating anomalously high PPS (packets per second) or BPS toward external targets",
      "Cluster ingress receiving a flood of requests that exhaust service capacity",
      "netflow showing amplification attack traffic (DNS, NTP) sourced from a cluster node"
    ]
  },
  {
    "id": null,
    "name": "Host Status",
    "data_source_id": "DS0013",
    "data_source_name": "Sensor Health",
    "definition": "Node and pod health status including OOM kills, crashloop events, and resource exhaustion. Covers T1499 (endpoint-level DoS) targeting cluster components.",
    "url": "https://attack.mitre.org/datasources/DS0013/",
    "relevant_events": [
      "Kubernetes: pod in CrashLoopBackOff state due to resource exhaustion attack",
      "Node entering NotReady state due to memory pressure from a resource-exhausting container",
      "AN0588: container orchestrator logs revealing crashlooping pods or repeated resource exhaustion"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Application and API server logs recording service unavailability or errors caused by DoS conditions. K8s API server slowdown or unavailability under attack generates audit log gaps.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "API server: 429 Too Many Requests or 503 Service Unavailable responses at elevated rate",
      "Application service log: timeouts or connection refused errors correlating with resource exhaustion",
      "AN0584: excessive resource exhaustion induced by processes consuming CPU/memory"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Content",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Deep packet inspection of traffic targeting cluster services. Application-layer DoS (T1499) may involve malformed requests or exploit payloads designed to crash services.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "HTTP flood with malformed or oversized payloads targeting an ingress service",
      "gRPC or WebSocket connection flood causing service thread pool exhaustion",
      "Kubernetes API server targeted with large list queries causing etcd overload"
    ]
  }
]
```

### Recommended `detection_strategies[]`

```json
[
  {
    "id": "DET0518",
    "name": "Behavioral Detection of T1498 -- Network Denial of Service Across Platforms",
    "summary": "AN1434 and AN1435 detect programs/scripts creating substantial outbound network traffic and flooding instruments dispatching high-volume packet streams.",
    "url": "https://attack.mitre.org/techniques/T1498/",
    "data_component_refs": ["Network Traffic Flow", "Network Traffic Content"]
  },
  {
    "id": "DET0208",
    "name": "Endpoint Resource Saturation and Crash Pattern Detection Across Platforms",
    "summary": "AN0588 detects container orchestrator logs revealing crashlooping pods, repeated resource exhaustion, or malicious binaries with infinite loops consuming cgroup limits.",
    "url": "https://attack.mitre.org/techniques/T1499/",
    "data_component_refs": ["Host Status", "Application Log Content", "Network Traffic Content"]
  }
]
```

**Analytics:** AN1434, AN1435 (T1498); AN0584, AN0585, AN0586, AN0587, AN0588 (T1499). AN0588 is container-specific.

### Notes / Confidence

- **Confirmed:** STIX T1498 `x_mitre_data_sources`: `Network Traffic: Network Traffic Flow`, `Sensor Health: Host Status`.
- **Confirmed:** STIX T1499 `x_mitre_data_sources`: `Application Log: Application Log Content`, `Network Traffic: Network Traffic Flow`, `Network Traffic: Network Traffic Content`, `Sensor Health: Host Status`.
- **Confirmed:** MS page identifies three mitigations: runtime restriction (LSM), API server IP firewall, and resource limits (LimitRanges/ResourceQuotas).
- **Likely:** `Application Log: Application Log Content` from T1499 STIX is applicable to K8s API server log analysis for request flood detection.

### Open Questions

- Are LimitRange and ResourceQuota objects configured in all namespaces? Without them, a single pod can exhaust all node resources.
- Is rate limiting configured on the Kubernetes API server (`--max-requests-inflight`)?

---

## Summary Table

| Technique ID | Technique Name | MITRE IDs | Data Components (count) | Detection Strategies (count) |
|---|---|---|---|---|
| MS-TA9021 | Clear container logs | T1070 | 3 | 1 (DET0184) |
| MS-TA9022 | Delete K8S events | T1070 | 2 | 1 (DET0184) |
| MS-TA9023 | Pod or container name similarity | T1036, T1036.005 | 4 | 2 (DET0127, DET0347) |
| MS-TA9024 | Connect from Proxy server | T1090 | 3 | 1 (DET0445) |
| MS-TA9016 | Container service account | T1528 | 3 | 1 (DET0515) |
| MS-TA9025 | List K8S secrets | T1552, T1552.007 | 3 | 2 (DET0198, DET0412) |
| MS-TA9026 | Mount service principal | T1552, T1552.001 | 3 | 2 (DET0307, DET0412) |
| MS-TA9027 | Application credentials in configuration files | T1552 | 3 | 1 (DET0412) |
| MS-TA9028 | Access managed identity credentials | T1552, T1552.005 | 3 | 1 (DET0001) |
| MS-TA9029 | Access the K8S API server | T1613 | 3 | 1 (DET0490) |
| MS-TA9030 | Access Kubelet API | T1613 | 3 | 1 (DET0490) |
| MS-TA9031 | Network mapping | T1046 | 3 | 1 (DET0376) |
| MS-TA9033 | Instance Metadata API | T1552, T1552.005 | 3 | 1 (DET0001) |
| MS-TA9034 | Cluster internal networking | T1210 | 3 | 1 (DET0118) |
| MS-TA9035 | CoreDNS poisoning | T1557 | 4 | 1 (DET0296) |
| MS-TA9036 | ARP poisoning and IP spoofing | T1557 | 3 | 1 (DET0296) |
| MS-TA9037 | Images from a private registry | T1530 | 3 | 1 (DET0484) |
| MS-TA9041 | Collecting Data from Pod | (none) | 4 | 0 |
| MS-TA9038 | Data destruction | T1485 | 5 | 1 (DET0146) |
| MS-TA9039 | Resource hijacking | T1496 | 5 | 1 (DET0267) |
| MS-TA9040 | Denial of service | T1498, T1499 | 4 | 2 (DET0518, DET0208) |

**Totals:** 21 techniques, 72 data component entries (some names shared across techniques), 26 detection strategy references.

---

## Research Process

### Searches Performed

None via WebSearch. All evidence gathered from direct URL fetches and GitHub API.

### Pages Fetched

**MITRE ATT&CK (Official):**
- https://attack.mitre.org/techniques/T1070/ (fetched)
- https://attack.mitre.org/techniques/T1070/002/ (fetch failed: empty content)
- https://attack.mitre.org/techniques/T1036/ (fetched)
- https://attack.mitre.org/techniques/T1036/005/ (fetched)
- https://attack.mitre.org/techniques/T1090/ (fetched)
- https://attack.mitre.org/techniques/T1528/ (fetched)
- https://attack.mitre.org/techniques/T1552/ (fetched)
- https://attack.mitre.org/techniques/T1552/001/ (fetched)
- https://attack.mitre.org/techniques/T1552/005/ (fetched)
- https://attack.mitre.org/techniques/T1552/007/ (fetched)
- https://attack.mitre.org/techniques/T1613/ (fetched)
- https://attack.mitre.org/techniques/T1046/ (fetched)
- https://attack.mitre.org/techniques/T1210/ (fetched)
- https://attack.mitre.org/techniques/T1557/ (fetched)
- https://attack.mitre.org/techniques/T1530/ (fetched)
- https://attack.mitre.org/techniques/T1485/ (fetched)
- https://attack.mitre.org/techniques/T1496/ (fetched)
- https://attack.mitre.org/techniques/T1498/ (fetched)
- https://attack.mitre.org/techniques/T1499/ (fetched)
- https://attack.mitre.org/datasources/ (fetched; full DS catalog)
- https://attack.mitre.org/datasources/DS0015/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0032/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0014/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0029/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0022/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0002/ (fetched; content did not render components)
- https://attack.mitre.org/datasources/DS0009/ (fetched; content did not render components)

**MITRE STIX Ground Truth (Official, via GitHub raw):**
- https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json (fetched via curl+python3; extracted x_mitre_data_sources for all 18 relevant T-IDs -- CONFIRMED ground truth)

**Microsoft Threat Matrix for Kubernetes (Official):**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Clear%20container%20logs/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Pod%20or%20container%20name%20similarity/ (404)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Connect%20from%20proxy%20server/ (404)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/container%20service%20account/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/List%20K8S%20secrets/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Mount%20service%20principal/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20credentials%20in%20configuration%20files/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20managed%20identity%20credentials/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20the%20K8S%20API%20server/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20Kubelet%20API/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Network%20mapping/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Instance%20Metadata%20API/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster%20internal%20networking/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/CoreDNS%20poisoning/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/ARP%20poisoning%20and%20IP%20spoofing/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Images%20from%20a%20private%20registry/ (404)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/images%20from%20a%20private%20registry/ (fetched via lowercase slug)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Collecting%20Data%20from%20Pod/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/collecting-data-from-pod/ (404)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Resource%20hijacking/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Denial%20of%20service/ (fetched)
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/  (index; used to find Collecting Data slug)

**SigmaHQ (Community):**
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/ (directory listing; fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_potential_enumeration_activity.yml (fetched)
- https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml (fetched)

**Falco (Community):**
- https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (fetched twice with different prompts)

**Atomic Red Team (Community):**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.007/T1552.007.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1613/T1613.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1496/T1496.yaml (fetched)
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml (fetched)

### Sources Evaluated but Rejected

- https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -- rejected: 10MB+ content limit exceeded. Used mitre-attack/attack-stix-data instead (versioned file, under limit).
- https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json -- not rejected; fetched successfully via `curl` in Bash (bypasses 10MB WebFetch limit). This is the ground truth for all x_mitre_data_sources values.

### Gaps

- **MS Threat Matrix pages for MS-TA9023 and MS-TA9024 returned 404.** The slugs `Pod%20or%20container%20name%20similarity` and `Connect%20from%20proxy%20server` both failed. Technique descriptions reconstructed from stub JSON.
- **MITRE ATT&CK data source pages (DS0015, DS0029, etc.) did not render data component details** via WebFetch (SPA rendering issue). Ground truth obtained from STIX data instead.
- **No Sigma rules found for:** Kubelet API access (MS-TA9030), CoreDNS ConfigMap poisoning (MS-TA9035), ARP spoofing in K8s (MS-TA9036), IMDS access from pods (MS-TA9028, MS-TA9033), proxy-sourced K8s access (MS-TA9024), private registry credential theft (MS-TA9037), data destruction in K8s (MS-TA9038), resource hijacking in K8s (MS-TA9039), DoS in K8s (MS-TA9040). These are detection gaps.
- **No Atomic Red Team tests for:** T1090, T1557, T1530, T1485 (K8s), T1498 (K8s), T1499 (K8s), and the MS-only technique MS-TA9041.
- **MS-TA9041 has no MITRE T-ID assignment.** This may be updated in a future MS Threat Matrix release.
- **GitHub Search API rate limit** hit during Sigma rule searches beyond T1070 and T1552. Initial search retrieved the K8s audit directory listing which provided the complete rule inventory.

### Tools Used

- WebFetch: 47 requests
- Bash (curl + python3 for STIX data): 1 request (enterprise-attack-14.1.json)
- Bash (gh api for Sigma rule search): 3 queries (rate limited after 10 API calls used)
- Read (stub JSON files): 2 files (MS-TA9021, MS-TA9016 as structure reference)
