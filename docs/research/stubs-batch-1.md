# Research Report: Stubs Batch 1 - Data Components and Detection Strategies

**Generated:** 2026-05-04
**Scope:** 15 stub technique records across Initial Access, Execution, Persistence, and Privilege Escalation

This report provides recommended `data_components[]` and `detection_strategies[]` for each stub, anchored on the MITRE Data Component catalog (confirmed from the STIX bundle at `github.com/mitre/cti`). All DS IDs, DC IDs, DET IDs, and AN IDs were verified from the live STIX bundle; none are inferred from training data alone.

---

## Data Source and Data Component Reference (Confirmed from STIX)

The following DS/DC IDs are used throughout this report. Confirmed by extracting `x-mitre-data-source` and `x-mitre-data-component` objects from the enterprise-attack STIX bundle.

| DS ID | Data Source Name |
|-------|-----------------|
| DS0002 | User Account |
| DS0003 | Scheduled Job |
| DS0009 | Process |
| DS0014 | Pod |
| DS0015 | Application Log |
| DS0017 | Command |
| DS0022 | File |
| DS0025 | Cloud Service |
| DS0028 | Logon Session |
| DS0029 | Network Traffic |
| DS0031 | Cluster |
| DS0032 | Container |

Key Data Components referenced in this report:

| DC ID | DC Name | Parent DS |
|-------|---------|-----------|
| DC0002 | User Account Authentication | DS0002 |
| DC0014 | User Account Creation | DS0002 |
| DC0038 | Application Log Content | DS0015 |
| DC0064 | Command Execution | DS0017 |
| DC0032 | Process Creation | DS0009 |
| DC0019 | Pod Creation | DS0014 |
| DC0030 | Pod Modification | DS0014 |
| DC0072 | Container Creation | DS0032 |
| DC0077 | Container Start | DS0032 |
| DC0029 | Script Execution | DS0012 |
| DC0078 | Network Traffic Flow | DS0029 |
| DC0082 | Network Connection Creation | DS0029 |
| DC0067 | Logon Session Creation | DS0028 |
| DC0039 | File Creation | DS0022 |
| DC0061 | File Modification | DS0022 |
| DC0055 | File Access | DS0022 |
| DC0001 | Scheduled Job Creation | DS0003 |
| DC0012 | Scheduled Job Modification | DS0003 |
| DC0069 | Cloud Service Modification | DS0025 |
| DC0083 | Cloud Service Enumeration | DS0025 |
| DC0120 | Cluster Metadata | DS0031 |

Note: The STIX bundle stores `x_mitre_data_source_ref` as a STIX identity reference, not a plain DS ID string. The parent DS assignments above are derived from the MITRE ATT&CK website and the data-source page hierarchy, which is authoritative for DS-to-DC relationships. Confidence: **Confirmed** for the DS IDs and DC IDs themselves (they exist in the STIX bundle); **Likely** for some DS-to-DC parent mappings where the STIX field is empty and the ATT&CK website datasource pages returned deprecation notices without listing components explicitly.

---

## INITIAL ACCESS

---

### MS-TA9001 - Using Cloud Credentials

**MITRE IDs:** T1078, T1078.004

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1078/` - Valid Accounts parent technique
- `https://attack.mitre.org/techniques/T1078/004/` - Cloud Accounts sub-technique
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Using%20Cloud%20Credentials/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml` references T1078 in tags; no dedicated cloud-credential K8s Sigma rule found.
- Falco: No dedicated Falco rule for cloud credential theft found in `falco_rules.yaml`; `Find AWS Credentials` rule (T1552) is related but distinct.
- Atomic Red Team: `atomics/T1078.004/T1078.004.md` - tests for GCP service account creation, Azure Automation Runbook persistence, GCP custom IAM role creation.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "User Account Authentication",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Authentication events from cloud identity providers recording when cloud credentials (IAM user keys, service principal credentials, managed identity tokens) are used to authenticate to cloud Kubernetes management APIs (AKS, GKE, EKS).",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Azure AD sign-in log: appDisplayName='Azure Kubernetes Service AAD Server', resultType=0 (success) from unexpected IP or location",
      "AWS CloudTrail: eventSource=eks.amazonaws.com, eventName=DescribeCluster or GetToken with unusual userIdentity.arn",
      "GCP Cloud Audit Log: methodName=google.container.v1.ClusterManager.GetCluster from unexpected service account"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log entries showing cluster management operations initiated via cloud credentials, indicating post-compromise use of stolen cloud account tokens.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=list, objectRef.resource=pods, user.username matching cloud-provider IAM pattern (e.g., system:serviceaccount:kube-system or ARN-formatted principal) from unusual source IP",
      "Kubernetes audit event: verb=get, objectRef.resource=secrets from cloud-managed identity outside expected namespace",
      "Cloud provider audit log: call to GetCredentials or az aks get-credentials from unknown client IP"
    ]
  },
  {
    "id": null,
    "name": "Logon Session Creation",
    "data_source_id": "DS0028",
    "data_source_name": "Logon Session",
    "definition": "Cloud provider IAM session creation events that precede Kubernetes API access, capturing the moment a compromised cloud credential establishes an authenticated session.",
    "url": "https://attack.mitre.org/datasources/DS0028/",
    "relevant_events": [
      "AWS STS: AssumeRole event for a role with eks:DescribeCluster permissions from an unexpected principal or IP",
      "Azure: token issuance event in Azure AD for AKS audience from unrecognized device or location",
      "GCP: google.oauth2.service_accounts.generateAccessToken for a service account with container.clusters.get permission from unexpected origin"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0546",
    "name": "Detection of Abused or Compromised Cloud Accounts for Access and Persistence",
    "summary": "Correlates anomalous cloud authentication patterns (impossible geolocations, legacy protocols, API scope anomalies) that precede or accompany Kubernetes cluster access via cloud management plane.",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "data_component_refs": ["User Account Authentication", "Logon Session Creation"]
  },
  {
    "id": "DET0560",
    "name": "Detection of Valid Account Abuse Across Platforms",
    "summary": "Broader cross-platform detection covering compromised valid accounts; analytics AN1546 (IdP geographic anomalies) and AN1547 (containerized service account misuse from unexpected nodes/IPs) are most relevant here.",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "data_component_refs": ["User Account Authentication", "Application Log Content"]
  }
]
```

**Notes / Confidence:**
- DET0546 and its analytics (AN1503-AN1506) confirmed from STIX `x-mitre-detection-strategy` objects with relationship type `detects` targeting T1078.004. Confidence: **Confirmed**.
- DET0560 confirmed from STIX targeting T1078 parent. Confidence: **Confirmed**.
- DS0002 Application Log Content (DC0038) and User Account Authentication (DC0002) are the MITRE-canonical data components for T1078.004. The STIX `x_mitre_log_sources` field on DC0002 does not list Kubernetes-specific sources; the K8s-specific `relevant_events` above are authored from the MS matrix description and AKS/GKE/EKS documentation. Confidence for K8s-specific events: **Likely**.

**Open questions:**
- T1078.004's MITRE page does not list explicit `x_mitre_data_sources` in the STIX bundle (the field appears empty in the current spec version). The DS assignments are inferred from the canonical ATT&CK technique page text and the DET/AN content. This is flagged per project requirement: **STIX `x_mitre_data_sources` is empty for T1078.004**.

---

### MS-TA9003 - Kubeconfig File

**MITRE IDs:** None (MS-only technique)

**Authoritative sources fetched:**
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Kubeconfig%20file/`
- No canonical MITRE technique page (no MITRE mapping).
- No dedicated Sigma rule found for kubeconfig file access (searched `SigmaHQ/sigma`).
- Falco: `read_sensitive_file_untrusted` rule covers unauthorized reads of authentication files; kubeconfig (`~/.kube/config`, `/etc/kubernetes/admin.conf`) would match if added to the sensitive files macro.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "File system read events on kubeconfig file paths (e.g., ~/.kube/config, /etc/kubernetes/admin.conf, /root/.kube/config) by processes or users that do not normally need cluster credential access.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Linux auditd: syscall=open, path=~/.kube/config or /etc/kubernetes/admin.conf, exe not in [kubectl, kubeadm, cloud-provider-daemon]",
      "Falco event: open_read with sensitive kubeconfig path by untrusted process",
      "Windows Sysmon Event ID 11 (FileCreate) or Event ID 23 on %USERPROFILE%\\.kube\\config by unexpected processes"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Execution of cloud CLI commands that download or update kubeconfig files (az aks get-credentials, gcloud container clusters get-credentials, aws eks update-kubeconfig), potentially indicating an attacker attempting to obtain valid cluster credentials.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "Process creation: az aks get-credentials or gcloud container clusters get-credentials executed by non-admin user or at anomalous time",
      "AWS CloudTrail: UpdateKubeconfig API call from unexpected IAM principal",
      "Shell history or auditd EXECVE record for kubectl config set-credentials with base64 certificate data"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log showing successful authentication with credentials that match a known kubeconfig pattern but originate from an unexpected client IP or user agent, indicating use of a stolen kubeconfig.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: user.groups contains system:masters or high-privilege group, sourceIPs not matching any known admin workstation or CI/CD IP range",
      "Kubernetes audit event: userAgent=kubectl/<version> from IP outside corporate egress range after business hours",
      "Kubernetes audit event: verb=get, objectRef.resource=secrets, user.username=admin from new geographic location"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[]
```

(No MITRE technique ID means no canonical DET IDs exist. Detection is inferred from the Microsoft matrix description and community practice.)

**Notes / Confidence:**
- No MITRE ID for this technique; data components are inferred from what the MS matrix says the technique does (file access of kubeconfig, subsequent API authentication). Confidence for data component selection: **Likely**.
- The K8s audit log surface (DS0015 / DC0038) is the primary post-exploitation detection surface once the stolen kubeconfig is used. Confidence: **Likely**.
- No dedicated Sigma rule found in SigmaHQ targeting kubeconfig file reads specifically.

**Open questions:**
- Whether MITRE will eventually map this to T1552.001 (Credentials In Files) or T1078 is unresolved; no authoritative mapping found.

---

### MS-TA9004 - Application Vulnerability

**MITRE IDs:** T1190

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1190/` - Exploit Public-Facing Application
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20Vulnerability/`
- SigmaHQ: No dedicated K8s application vulnerability Sigma rule found; `kubernetes_audit_potential_enumeration_activity.yml` is post-exploit.
- Falco: `run_shell_untrusted` and `terminal_shell_in_container` rules detect shells spawned by web application processes (T1059.004). AN0222 in DET0080 explicitly covers containerized app exploitation.
- Atomic Red Team: No direct T1190 atomics for Kubernetes specifically; nearest tests are in T1190 directory for web application exploitation generally.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Ingress controller, web application firewall, and application-level logs recording exploit attempt patterns against vulnerable containerized applications, including anomalous HTTP methods, oversized payloads, and deserialization attack signatures.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Ingress controller (nginx/traefik) access log: 4xx/5xx spike from single source IP, suspicious URI patterns (e.g., /../, %00, JNDI:// strings)",
      "Web application log: unexpected deserialization or template injection pattern in request body",
      "Kubernetes audit event: verb=create, objectRef.resource=pods/exec from the application's own service account (indicates post-exploit pivot)"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process creation events inside the containerized application's process namespace, showing shells or unusual child processes spawned by the application process tree, which indicates successful RCE.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Falco event: spawned_process, container=true, proc.pname in [java, python, node, php, ruby], proc.name in [bash, sh, dash, curl, wget, nc]",
      "Linux auditd: EXECVE record inside container namespace showing shell spawned by web server process",
      "Container runtime log: unexpected exec event on existing container by application process"
    ]
  },
  {
    "id": null,
    "name": "Network Traffic Flow",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Outbound network connections from the vulnerable application container to external IPs or to the Kubernetes API server, indicating successful exploitation and subsequent C2 or lateral movement to the cluster.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Network policy violation: container egress to non-whitelisted external IP after application process spawned shell",
      "Connection to Kubernetes API server (10.0.0.1:443 or kube-apiserver FQDN) from application container using pod service account token",
      "Outbound connection to cloud metadata endpoint (169.254.169.254) from application container"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0080",
    "name": "Exploit Public-Facing Application – multi-signal correlation (request to error to post-exploit process/egress)",
    "summary": "Multi-signal chain: suspicious ingress/app logs, container process spawning a shell or exec, then egress to metadata API or external C2. AN0222 specifically covers containerized app exploitation via ingress.",
    "url": "https://attack.mitre.org/techniques/T1190/",
    "data_component_refs": ["Application Log Content", "Process Creation", "Network Traffic Flow"]
  }
]
```

**Notes / Confidence:**
- DET0080 confirmed from STIX with AN0222 explicitly describing containerized app exploitation chain. Confidence: **Confirmed**.
- DS0009 Process Creation (DC0032) and DS0015 Application Log Content (DC0038) are the primary surfaces. Confidence: **Likely** (STIX `x_mitre_data_sources` field is empty for T1190 in the current bundle).
- The Falco `terminal_shell_in_container` and `run_shell_untrusted` rules directly implement the process creation detection vector. Confidence for Falco coverage: **Confirmed** (read the actual rule conditions).

**Open questions:**
- STIX `x_mitre_data_sources` for T1190 is empty in the current bundle version. DS assignments are from the ATT&CK technique page text (which lists "Application Log: Application Log Content" and "Process: Process Creation" in the detection section of the webpage). Flagged as **STIX field empty; DS inferred from ATT&CK page text**.

---

### MS-TA9005 - Exposed Sensitive Interfaces

**MITRE IDs:** T1133

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1133/` - External Remote Services
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exposed%20sensitive%20interfaces/`
- SigmaHQ: No dedicated rule for exposed Kubernetes dashboards or Argo/Kubeflow. The `kubernetes_audit_unauthorized_unauthenticated_actions.yml` rule in the K8s audit directory is relevant.
- Falco: `contact_k8s_api_server_from_container` rule (T1565 tagged) partially covers internal cluster access to the dashboard.
- Atomic Red Team: T1133 atomics exist (`atomics/T1133/`) but focus on VPN/RDP; no K8s-specific test found.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Access logs from the exposed management interfaces themselves (Kubernetes dashboard, Argo Workflows, Kubeflow, Weave Scope), recording unauthenticated or anomalous access attempts from external or unexpected internal IPs.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes dashboard access log: HTTP request without Authorization header or with anonymous user from external IP",
      "Argo Workflows: unauthenticated API call to /api/v1/workflows from source outside cluster network",
      "Kubernetes audit event: user.username=system:anonymous, verb=list, objectRef.resource=pods (indicates unauthenticated dashboard access)"
    ]
  },
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "New inbound TCP connections to cluster management service ports (e.g., 8080/8443 for dashboard, 2746 for Argo) from external sources or unexpected internal containers, indicating access to an exposed sensitive interface.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Network flow: inbound connection to NodePort or LoadBalancer IP on port 8080 or 8443 from public internet to kubernetes-dashboard service",
      "Network flow: container-to-container connection from application pod to kubernetes-dashboard pod on port 8080 (lateral discovery via dashboard)",
      "Kubernetes Service of type=LoadBalancer with selector matching dashboard or argo-server pods receiving connections from outside cluster CIDR"
    ]
  },
  {
    "id": null,
    "name": "Logon Session Creation",
    "data_source_id": "DS0028",
    "data_source_name": "Logon Session",
    "definition": "Session establishment events on the Kubernetes API server or management interfaces using service account tokens belonging to dashboard or workflow components, especially when initiated from external or unusual sources.",
    "url": "https://attack.mitre.org/datasources/DS0028/",
    "relevant_events": [
      "Kubernetes audit event: user.username=system:serviceaccount:kubernetes-dashboard:kubernetes-dashboard, sourceIPs containing external/non-pod IP",
      "Kubernetes audit event: user.groups contains system:unauthenticated for any verb other than healthz/readyz",
      "HTTP session cookie or bearer token issuance event in dashboard application logs for anonymous user"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0354",
    "name": "Behavior-chain detection for T1133 External Remote Services across Windows, Linux, macOS, Containers",
    "summary": "AN1007 specifically covers connections to exposed container services (Docker API, Kubernetes API server) from unauthorized external IPs, followed by abnormal container creation and lateral cluster activity.",
    "url": "https://attack.mitre.org/techniques/T1133/",
    "data_component_refs": ["Application Log Content", "Network Connection Creation", "Logon Session Creation"]
  }
]
```

**Notes / Confidence:**
- DET0354 and AN1007 confirmed from STIX. AN1007 description explicitly states: "Connections to exposed container services (e.g., Docker API, Kubernetes API server) from unauthorized external IPs." Confidence: **Confirmed**.
- The distinction between Docker API and Kubernetes management services is not made in AN1007's STIX description; both are in scope. Confidence: **Confirmed** for coverage, **Likely** for the specific K8s dashboard scenario.

**Open questions:**
- STIX `x_mitre_data_sources` for T1133 is empty in the current bundle. DS assignments inferred from ATT&CK page text and DET/AN descriptions.

---

## EXECUTION

---

### MS-TA9007 - bash or cmd Inside Container

**MITRE IDs:** T1059

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1059/` - Command and Scripting Interpreter
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/bash%20or%20cmd%20inside%20container/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml` (ID: a1b0ca4e) - detects `kubectl exec` via Kubernetes audit log (`verb=create, objectRef.resource=pods, objectRef.subresource=exec`). Tags: `attack.t1609`. Note: Sigma uses T1609, not T1059, for this specific Kubernetes exec vector.
- Falco: `terminal_shell_in_container` (T1059, maturity_stable) - `spawned_process and container and shell_procs and proc.tty != 0`; `run_shell_untrusted` (T1059.004, maturity_stable).
- Atomic Red Team: `atomics/T1059.004/` - Create and Execute Bash Shell Script, Command-Line Interface.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording exec sub-resource requests against pods, which captures kubectl exec or equivalent API calls used to run bash or cmd inside a running container.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=create, objectRef.resource=pods, objectRef.subresource=exec - this is the primary signal for kubectl exec into container",
      "Kubernetes audit event: verb=create, objectRef.resource=pods, objectRef.subresource=attach - covers interactive shell attach",
      "Kubernetes audit event: user performing exec not in expected admin service account list, or exec targeting a pod in production namespace"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process creation events inside the container namespace showing shell interpreter processes (bash, sh, cmd, powershell) spawned by the container's init process or by kubectl exec, detectable via container runtime or host-level syscall monitoring.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Falco: spawned_process, container=true, proc.name in [bash, sh, dash, cmd.exe], proc.tty != 0 (attached terminal)",
      "Linux auditd: EXECVE syscall inside container cgroup namespace with comm=bash or sh, ppid matching container init PID",
      "Container runtime (containerd/cri-o) exec event: ExecSync or ExecProcess API call with command=['/bin/bash', '-c', ...]"
    ]
  },
  {
    "id": null,
    "name": "Command Execution",
    "data_source_id": "DS0017",
    "data_source_name": "Command",
    "definition": "Specific commands executed inside a container shell session, observable via audit trails, shell history, or runtime syscall monitoring, providing visibility into what the attacker did once shell access was gained.",
    "url": "https://attack.mitre.org/datasources/DS0017/",
    "relevant_events": [
      "Shell command executed inside container: env, cat /var/run/secrets/kubernetes.io/serviceaccount/token (service account token exfiltration)",
      "Shell command inside container: curl http://169.254.169.254/latest/meta-data/ (metadata API probe)",
      "Shell command inside container: wget or curl to external IP (C2 beacon or tool download)"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0516",
    "name": "Behavioral Detection of Command and Scripting Interpreter Abuse",
    "summary": "AN1429 specifically covers shell interpreters (bash, sh, python, perl) initiated by processes not normally executing them, especially when chaining suspicious utilities. In K8s context, the kubectl exec API call + subsequent shell process combination is the primary chain.",
    "url": "https://attack.mitre.org/techniques/T1059/",
    "data_component_refs": ["Process Creation", "Command Execution", "Application Log Content"]
  }
]
```

**Notes / Confidence:**
- The Sigma rule `kubernetes_audit_exec_into_container.yml` uses `attack.t1609` (Kubernetes Exec into Container), not T1059. T1609 is a separate MITRE ATT&CK technique for the Kubernetes-specific exec vector. The MS matrix maps this to T1059, which represents the shell/command interpreter dimension. Both are valid; this report follows the stub's T1059 mapping. Confidence: **Confirmed** that the Sigma rule exists and addresses this behavior; **Likely** that T1059 is the right primary mapping per the stub.
- DET0516 confirmed from STIX for T1059. Confidence: **Confirmed**.
- AN1429 description mentions shell interpreters initiated by unusual processes; directly applicable in K8s context.

**Open questions:**
- Should this also reference T1609 (Kubernetes Exec)? The current stub maps to T1059 only. T1609 has its own detection strategy in MITRE and dedicated Sigma rules. Consider adding T1609 reference when authoring JSON updates.

---

### MS-TA9009 - Application Exploit (RCE)

**MITRE IDs:** T1190

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1190/` (same as MS-TA9004; this is the execution-phase manifestation of the same MITRE technique)
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20Exploit%20%28RCE%29/`
- SigmaHQ: same observation as MS-TA9004; no dedicated K8s RCE Sigma rule. Post-exploit signals covered by `kubernetes_audit_exec_into_container.yml` and `kubernetes_audit_secrets_enumeration.yml`.
- Falco: `run_shell_untrusted` (T1059.004), `terminal_shell_in_container` - same as MS-TA9004.
- Atomic Red Team: T1190 atomics are non-K8s-specific.

This technique represents T1190 in the Execution tactic context (code execution achieved via RCE vulnerability in a deployed app). The detection surface differs slightly from MS-TA9004 (Initial Access) in that the initial exploitation is already inside the cluster.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process creation events showing unexpected child processes spawned by a containerized application process, indicating successful RCE exploitation. This is the primary in-cluster execution signal.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Falco: spawned_process, container=true, proc.pname in [java, python, node, php-fpm, ruby, nginx], proc.name in [bash, sh, dash, nc, curl, wget, id, whoami]",
      "Linux auditd: EXECVE inside container cgroup showing unexpected process ancestry chain from application to shell",
      "eBPF/Sysdig: unexpected process exec in container PID namespace - process not present in original container image"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Application-level and ingress logs capturing the exploit request that triggered RCE, and Kubernetes audit logs capturing subsequent cluster API calls made using the pod's mounted service account token.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Application error log: stack trace or exception indicating deserialization, SSTI, SSRF, or command injection just before unexpected child process creation",
      "Kubernetes audit event: verb=list, objectRef.resource=secrets, user.username=system:serviceaccount:<ns>:<name> where the pod was not expected to list secrets",
      "Kubernetes audit event: verb=create, objectRef.resource=pods from the exploited pod's service account (lateral movement to deploy additional pods)"
    ]
  },
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "New outbound network connections from the compromised container to external C2 infrastructure or to the Kubernetes API server, made by the newly spawned shell process after RCE success.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Network policy violation log: egress connection from application container to external IP on non-standard port (reverse shell)",
      "Network flow: connection to 169.254.169.254 (cloud metadata) from application container process not matching the app's normal communication pattern",
      "DNS query from container for external hostname not in application's known allow-list, shortly after application anomaly"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0080",
    "name": "Exploit Public-Facing Application – multi-signal correlation (request to error to post-exploit process/egress)",
    "summary": "Same DET as MS-TA9004 but emphasizing the process-creation and Kubernetes API call chain post-RCE. AN0222 covers containerized app exploitation via ingress with process spawn and egress to metadata service.",
    "url": "https://attack.mitre.org/techniques/T1190/",
    "data_component_refs": ["Process Creation", "Application Log Content", "Network Connection Creation"]
  }
]
```

**Notes / Confidence:**
- DET0080 confirmed from STIX for T1190. Confidence: **Confirmed**.
- The data components are identical in kind to MS-TA9004; the K8s context shifts emphasis to post-exploitation pivot via service account. Confidence for DC selection: **Likely**.

**Open questions:**
- MS-TA9009 and MS-TA9004 share the same MITRE ID (T1190) but represent different phases (Initial Access vs. Execution). No separate DET/AN exists for the execution-phase variant. The `relevant_events` above attempt to make the distinction concrete.

---

### MS-TA9010 - SSH Server Running Inside Container

**MITRE IDs:** None (MS-only technique)

**Authoritative sources fetched:**
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/SSH%20server%20running%20inside%20container/`
- No canonical MITRE technique page.
- SigmaHQ: No dedicated rule for SSH server inside container found.
- Falco: `disallowed_ssh_connection_non_standard_port` rule in `falco_rules.yaml` covers outbound SSH on non-standard ports. No rule specifically for inbound SSH to a container found. The `container_not_allowed` and image allow-list rules could catch unexpected images running sshd.
- Atomic Red Team: No K8s-specific SSH server atomic found.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Inbound TCP connections to port 22 (or non-standard SSH port) on a container, and any Kubernetes Service or NodePort exposing SSH from a container to the cluster network or external internet.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Network flow: inbound TCP SYN to container port 22 from source IP outside expected bastion/jump-host CIDR",
      "Kubernetes Service definition: containerPort=22 or targetPort=22 in any Service object (indicates sshd exposed by design or by attacker)",
      "Network policy violation: pod accepting connections on port 22 without an explicit allow rule"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process creation events showing sshd or similar SSH daemon running inside a container, which is rarely present in production images and indicates a backdoor or vulnerable image.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Falco: spawned_process, container=true, proc.name=sshd (sshd is almost never a legitimate container entrypoint)",
      "Container runtime exec or start event: PID 1 or child of PID 1 in container is sshd binary",
      "Linux auditd: EXECVE record for /usr/sbin/sshd inside container cgroup namespace"
    ]
  },
  {
    "id": null,
    "name": "Logon Session Creation",
    "data_source_id": "DS0028",
    "data_source_name": "Logon Session",
    "definition": "SSH authentication events (successful or failed) on the containerized SSH daemon, detectable via PAM logs, sshd auth.log, or container stdout/stderr if sshd is running in the container.",
    "url": "https://attack.mitre.org/datasources/DS0028/",
    "relevant_events": [
      "Container stdout/stderr: sshd log message 'Accepted password for root from <IP>' or 'Failed password for root from <IP>'",
      "Linux PAM log inside container: pam_unix auth event for sshd",
      "Repeated SSH authentication failure events to a container IP preceding a successful login (brute force indicator)"
    ]
  },
  {
    "id": null,
    "name": "Container Start",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Container image inspection events revealing sshd binary or OpenSSH server package in the container image layer, or container start events for images not in the approved image catalog.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "Image scan result: openssh-server or sshd binary found in container image layers",
      "Kubernetes audit event: verb=create, objectRef.resource=pods with image not in allowed-image-list containing sshd",
      "Admission controller webhook: pod creation rejected or alerted because container image contains port 22 EXPOSE declaration"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[]
```

(No MITRE technique ID; no canonical DET IDs. Closest MITRE technique would be T1021.004 SSH but that maps to lateral movement, not container execution context.)

**Notes / Confidence:**
- No MITRE ID; data components are inferred from the MS matrix description. Confidence: **Likely**.
- The most actionable detection is DS0032 Container Start (image scanning) and DS0009 Process Creation (sshd running in container). Confidence for these two: **Likely** (well-established community practice; Falco covers the process creation vector).
- The Falco `disallowed_ssh_connection_non_standard_port` rule covers outbound SSH from containers (attacker pivoting out) but not inbound SSH to a container sshd. The process creation vector (`proc.name=sshd` in container) is not present as a named rule in `falco_rules.yaml`; it would need to be authored.

**Open questions:**
- Should this technique be mapped to T1021.004 (SSH) or T1133 (External Remote Services)? The MS matrix places it in Execution; community consensus would likely place it in Lateral Movement or Persistence. No authoritative resolution found.

---

### MS-TA9011 - Sidecar Injection

**MITRE IDs:** T1610

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1610/` - Deploy Container
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20Injection/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml` (ID: ad9012a6) - detects `verb=patch, apiGroup=apps, objectRef.resource=deployments`. Tags: `attack.t1609`. Note: Same observation as MS-TA9007; Sigma uses T1609 for this K8s-specific vector.
- Falco: `drop_and_execute_new_binary_in_container` (T1059/T1027) and `terminal_shell_in_container` are the closest Falco rules; no sidecar-injection-specific rule in the stable ruleset.
- Atomic Red Team: `atomics/T1610/T1610.md` - Test T1610-1: Deploy Docker container (GUID: 59aa6f26) simulates container deployment with malicious image.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording patch operations against Deployments, StatefulSets, or DaemonSets that modify the pod template spec to add new container definitions, which is the primary API surface for sidecar injection.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=patch, apiGroup=apps, objectRef.resource in [deployments, statefulsets, daemonsets] - inspect request body for new containers[] entries",
      "Kubernetes audit event: verb=update, objectRef.resource=pods with new containers in spec.containers (direct pod mutation, less common path)",
      "Admission webhook audit: MutatingAdmissionWebhook invoked during pod creation and adding unexpected container to spec"
    ]
  },
  {
    "id": null,
    "name": "Pod Modification",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Pod specification modification events showing new container entries added to existing pod or workload definitions, either directly or via workload controller patch.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "Kubernetes audit event: verb=patch on Deployment object where diff shows new entry in spec.template.spec.containers[]",
      "Kubernetes audit event: verb=create on Pod where spec.containers has more entries than the expected count for that Deployment",
      "kubectl audit: `kubectl patch deployment <name> --patch` executed by non-CI/CD service account"
    ]
  },
  {
    "id": null,
    "name": "Container Creation",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "New container creation events within an existing pod, triggered by the scheduler after a Deployment patch, where the new container image was not part of the original pod template.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "Container runtime event: new container created within an existing pod sandbox (same pod UID) with an image not in the approved image catalog",
      "Kubernetes event: reason=Created, for container with name not matching any known sidecar pattern (e.g., not istio-proxy, linkerd-proxy, datadog-agent)",
      "Image pull event: unexpected image pulled for a container added to an existing Deployment via patch operation"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0249",
    "name": "Behavior-chain detection for T1610 Deploy Container across Docker and Kubernetes control/node planes",
    "summary": "AN0693 covers API-driven container creation with non-allowlisted images, non-admin principals, or risky attributes. Sidecar injection via kubectl patch triggers the same container creation signals on the Kubernetes node plane.",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "data_component_refs": ["Application Log Content", "Pod Modification", "Container Creation"]
  }
]
```

**Notes / Confidence:**
- DET0249 and AN0693 confirmed from STIX for T1610. Confidence: **Confirmed**.
- The Sigma rule `kubernetes_audit_sidecar_injection.yml` provides a concrete implementation of the Application Log Content detection (verb=patch on Deployments). Confidence: **Confirmed** (rule read in full).
- Pod Modification (DC0030) and Container Creation (DC0072) are MITRE catalog DC IDs confirmed from STIX. Confidence: **Confirmed** for DC IDs.

**Open questions:**
- T1610 and T1609 overlap in practice for Kubernetes. The Sigma rule community uses T1609; the stub uses T1610. Both are valid MITRE IDs covering different aspects of the behavior.

---

## PERSISTENCE

---

### MS-TA9012 - Backdoor Container

**MITRE IDs:** T1543

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1543/` - Create or Modify System Process
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Backdoor%20container/`
- SigmaHQ: No dedicated Sigma rule for backdoor container via DaemonSet/Deployment. The `kubernetes_audit_privileged_pod_creation.yml` rule overlaps when a backdoor container is deployed with elevated privileges.
- Falco: `drop_and_execute_new_binary_in_container` (persistence, T1027) and `container_started_with_unexpected_flags` (community rules) are closest.
- Atomic Red Team: T1543 atomics (`atomics/T1543.002/`, `T1543.003/`, `T1543.004/`) focus on Linux systemd services and macOS launch daemons. AN1578 in DET0571 specifically covers container system process creation.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording creation of DaemonSets, Deployments, or ReplicaSets with unusual images, overly permissive security contexts, or in unexpected namespaces - the primary signal for backdoor container deployment.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=create, apiGroup=apps, objectRef.resource=daemonsets - DaemonSets run on every node and are a persistence mechanism",
      "Kubernetes audit event: verb=create, apiGroup=apps, objectRef.resource=deployments with image not in approved registry or with restartPolicy=Always (ensures persistence)",
      "Kubernetes audit event: verb=create, objectRef.resource=pods with no owner reference (orphan pod manually created for persistence)"
    ]
  },
  {
    "id": null,
    "name": "Container Creation",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Container creation events on cluster nodes showing new containers with images outside the approved catalog, running in privileged mode or with host namespace access, indicating a backdoor container deployment.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "Container runtime event: new container started from image not matching any organizational approved registry pattern",
      "Falco: spawned_process in new container with image not in known_container_images macro",
      "Node-level: crictl ps showing container not corresponding to any known Kubernetes workload or associated with anomalous pod spec"
    ]
  },
  {
    "id": null,
    "name": "Pod Creation",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Pod creation events triggered by DaemonSet or Deployment controllers for pods running malicious container images, or direct pod creation by an attacker's service account to ensure persistent execution.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "Kubernetes event: pod created in kube-system or default namespace by non-system service account",
      "Kubernetes audit event: verb=create, objectRef.resource=pods, user.username not in expected CI/CD principals and objectRef.namespace=kube-system",
      "Pod spec contains hostPID=true, hostNetwork=true, or securityContext.privileged=true - common attributes of backdoor containers"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0571",
    "name": "Detection of System Process Creation or Modification Across Platforms",
    "summary": "AN1578 specifically detects creation of new container system processes via kubectl exec to init containers, modification of container init specs, and containers that override entrypoints - all signals for backdoor container deployment.",
    "url": "https://attack.mitre.org/techniques/T1543/",
    "data_component_refs": ["Application Log Content", "Container Creation", "Pod Creation"]
  }
]
```

**Notes / Confidence:**
- DET0571 confirmed from STIX for T1543. AN1578 description directly references `kubectl exec` to init containers and container init spec modification. Confidence: **Confirmed**.
- The K8s-specific mapping of T1543 (typically for host-level service persistence) to Kubernetes DaemonSet/Deployment persistence is a community convention; MITRE has no K8s-specific sub-technique of T1543. The STIX `x_mitre_data_sources` for T1543 is not empty in the ATT&CK webpage but could not be verified from the STIX bundle's data-source-ref field. Confidence for DS assignments: **Likely**.

**Open questions:**
- T1543.005 (Container Service) is a newer MITRE sub-technique specifically for container service persistence. The stub maps to T1543 parent. Authoring JSON updates should consider adding T1543.005 as the primary mapping.

---

### MS-TA9014 - Kubernetes CronJob

**MITRE IDs:** T1053, T1053.007

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1053/007/` - Container Orchestration Job
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Kubernetes%20CronJob/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_cronjob_modification.yml` (ID: 0c9b3bda) - detects creation/modification of CronJobs and Jobs via K8s audit log. Also `rules/cloud/gcp/audit/gcp_kubernetes_cronjob.yml` and `rules/cloud/azure/activity_logs/azure_kubernetes_cronjob.yml`. Tags: `attack.persistence`.
- Falco: No dedicated Falco rule for CronJob creation found in `falco_rules.yaml` (syscall-level Falco does not observe K8s API operations; K8s audit plugin would cover this).
- Atomic Red Team: `atomics/T1053.007/T1053.007.md` - Test 1: ListCronjobs (GUID: ddfb0bc1); Test 2: CreateCronjob (GUID: f2fa019e) - creates a CronJob from YAML manifest via `kubectl create`.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Scheduled Job Creation",
    "data_source_id": "DS0003",
    "data_source_name": "Scheduled Job",
    "definition": "Creation of Kubernetes CronJob or Job resources in the cluster API, recording the schedule expression, pod template spec, and requesting principal - the definitive signal for T1053.007.",
    "url": "https://attack.mitre.org/datasources/DS0003/",
    "relevant_events": [
      "Kubernetes audit event: verb=create, apiGroup=batch, objectRef.resource=cronjobs - record schedule, image, and requesting user",
      "Kubernetes audit event: verb=create, apiGroup=batch, objectRef.resource=jobs (direct job creation without CronJob parent)",
      "Kubernetes CronJob spec fields indicating abuse: schedule='*/1 * * * *' (every minute), restartPolicy=OnFailure, image outside approved registry"
    ]
  },
  {
    "id": null,
    "name": "Scheduled Job Modification",
    "data_source_id": "DS0003",
    "data_source_name": "Scheduled Job",
    "definition": "Modification of existing CronJob schedules or pod templates to inject malicious containers or change execution frequency, indicating an attacker hijacking an existing legitimate CronJob for persistence.",
    "url": "https://attack.mitre.org/datasources/DS0003/",
    "relevant_events": [
      "Kubernetes audit event: verb in [update, patch], apiGroup=batch, objectRef.resource=cronjobs - diff of spec.schedule or spec.jobTemplate.spec.template.spec.containers",
      "Kubernetes audit event: verb=delete, apiGroup=batch, objectRef.resource=cronjobs (deletion could be cleanup after malicious execution)",
      "Change to CronJob's serviceAccountName field to use a higher-privileged service account"
    ]
  },
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit logs providing full context for CronJob/Job lifecycle events, including the requesting principal, source IP, and full resource spec for forensic analysis.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit log: full request body for verb=create on batch/cronjobs containing malicious image and privileged pod spec",
      "Kubernetes event: SuccessfulCreate for Job triggered by CronJob, showing which node the workload ran on",
      "Kubernetes audit log: GET or LIST on cronjobs by a service account that should not be enumerating scheduled jobs"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0206",
    "name": "Detection of Malicious Kubernetes CronJob Scheduling",
    "summary": "AN0582 specifically detects abuse of container orchestration platforms where adversaries create CronJobs to maintain persistence or execute malicious Jobs across the cluster. Confirmed STIX object targeting T1053.007.",
    "url": "https://attack.mitre.org/techniques/T1053/007/",
    "data_component_refs": ["Scheduled Job Creation", "Scheduled Job Modification", "Application Log Content"]
  }
]
```

**Notes / Confidence:**
- DET0206 and AN0582 confirmed from STIX targeting T1053.007. This is the only technique in this batch with a dedicated, Kubernetes-specific MITRE detection strategy. Confidence: **Confirmed**.
- The Sigma rule `kubernetes_audit_cronjob_modification.yml` provides a concrete, immediately deployable implementation. Confidence: **Confirmed** (read full rule).
- DS0003 Scheduled Job as the primary data source for T1053.007 is well-established; DC0001 (Scheduled Job Creation) and DC0012 (Scheduled Job Modification) are the canonical components. Confidence: **Confirmed** from STIX.

**Open questions:**
- None significant. This is the best-supported technique in the batch from a MITRE coverage perspective.

---

### MS-TA9015 - Malicious Admission Controller

**MITRE IDs:** T1546

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1546/` - Event Triggered Execution
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Malicious%20admission%20controller/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml` (ID: eed82177) - detects modification of MutatingWebhookConfiguration and ValidatingWebhookConfiguration objects. Tags: `attack.persistence, attack.t1078, attack.t1552`. Also `rules/cloud/azure/activity_logs/azure_kubernetes_admission_controller.yml` and `rules/cloud/gcp/audit/gcp_kubernetes_admission_controller.yml`.
- Falco: No Falco rule for admission webhook modification found (syscall-level Falco does not observe K8s API operations).
- Atomic Red Team: T1546 parent atomics exist but focus on WMI/init scripts; no K8s admission controller atomic found.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording creation or modification of MutatingWebhookConfiguration and ValidatingWebhookConfiguration objects, which is the primary signal for malicious admission controller deployment.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb in [create, update, patch], objectRef.apiGroup=admissionregistration.k8s.io, objectRef.resource=mutatingwebhookconfigurations",
      "Kubernetes audit event: verb in [create, update, patch], objectRef.apiGroup=admissionregistration.k8s.io, objectRef.resource=validatingwebhookconfigurations",
      "Kubernetes audit event: webhook configuration points to an external URL (clientConfig.url) outside cluster-internal namespace-based service references"
    ]
  },
  {
    "id": null,
    "name": "Cluster Metadata",
    "data_source_id": "DS0031",
    "data_source_name": "Cluster",
    "definition": "Cluster-wide configuration state including the set of registered admission webhooks and their service endpoint bindings, used to establish a baseline and detect unauthorized additions.",
    "url": "https://attack.mitre.org/datasources/DS0031/",
    "relevant_events": [
      "Periodic audit of kubectl get mutatingwebhookconfigurations showing webhook rules with namespaceSelector or objectSelector matching all pods",
      "New webhook registration with failurePolicy=Ignore (attacker uses this to avoid breaking the cluster while still intercepting requests)",
      "Webhook clientConfig.service pointing to a namespace or service account not associated with any known service mesh or admission control product"
    ]
  },
  {
    "id": null,
    "name": "Pod Modification",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Pod creation events where the admitted pod spec differs from the requested spec, indicating a mutating webhook has injected additional containers or modified security contexts without operator knowledge.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "Kubernetes audit event: requestObject.spec.containers differs from responseObject.spec.containers for verb=create on pods (webhook mutation detected)",
      "New container in pod spec not matching any known sidecar injector (e.g., not istio-proxy, vault-agent) after pod is scheduled",
      "Kubernetes audit event: admission webhook call logged for pod creation where webhook adds containers[] entry with malicious image"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0010",
    "name": "Behavioral Detection of Event Triggered Execution Across Platforms",
    "summary": "T1546 is Event Triggered Execution; AN0027 covers cloud function creation triggered by audit log events. For K8s, the webhook registration IS the event trigger setup. The detection chain is: webhook configuration created/modified (audit log) + subsequent pod mutations observed.",
    "url": "https://attack.mitre.org/techniques/T1546/",
    "data_component_refs": ["Application Log Content", "Cluster Metadata", "Pod Modification"]
  }
]
```

**Notes / Confidence:**
- DET0010 confirmed from STIX for T1546. The analytics (AN0024-AN0029) are mostly Windows/macOS/cloud-function focused; AN0027 (cloud function triggered by audit events) is the closest analogue. The K8s webhook scenario is not explicitly called out in any AN description. Confidence for DET0010 applicability: **Likely** (correct DET, but analytics were not written with K8s webhooks in mind).
- The Sigma rule `kubernetes_audit_change_admission_controller.yml` is the most directly applicable detection and is **Confirmed** (read the full rule). Its tags include `attack.t1078` in addition to persistence, matching the credential-access potential of a malicious admission controller.

**Open questions:**
- T1546 has no K8s-specific sub-technique. The closest candidate would be a custom "Kubernetes Admission Controller" sub-technique, but no such MITRE sub-technique exists. The mapping is a community convention, not an official MITRE assignment.

---

### MS-TA9017 - Static Pods

**MITRE IDs:** None (MS-only technique)

**Authoritative sources fetched:**
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Static%20Pods/`
- No canonical MITRE technique page.
- SigmaHQ: No dedicated Sigma rule for static pod manifest modification found in the audit rules directory.
- Falco: `drop_and_execute_new_binary_in_container` would catch execution within a static pod container after the fact. No rule specifically for static pod manifest file writes found.
- Atomic Red Team: No K8s static pod atomic found.
- Kubernetes upstream docs: Static pod manifests are located in `/etc/kubernetes/manifests/` by default (configurable via kubelet's `staticPodPath`). The kubelet itself has no authentication for manifest file changes; detection must happen at the file system level.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "File Creation",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "File system creation or modification events on the kubelet's static pod manifest directory (default: /etc/kubernetes/manifests/), where an attacker writes a new YAML file to cause kubelet to start a persistent container outside API server control.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Linux auditd: audit rule on -w /etc/kubernetes/manifests/ -p wa -k static_pod_manifest - any write or attribute change to the directory",
      "inotifywait: IN_CREATE or IN_MODIFY event on /etc/kubernetes/manifests/*.yaml or *.json",
      "Falco: open_write with fd.name matching /etc/kubernetes/manifests/*.yaml by process not in [kubeadm, kubelet, known-upgrade-script]"
    ]
  },
  {
    "id": null,
    "name": "File Modification",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Modification of existing static pod manifest files to alter the image, command, or security context of existing system pods (e.g., kube-apiserver.yaml, etcd.yaml), representing a high-impact persistence path.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Linux auditd: WRITE syscall on /etc/kubernetes/manifests/kube-apiserver.yaml or any existing manifest by non-kubelet process",
      "File integrity monitoring alert: hash change on /etc/kubernetes/manifests/*.yaml",
      "Git/version-control event: change committed to infrastructure-as-code static pod manifest files outside normal change window"
    ]
  },
  {
    "id": null,
    "name": "Pod Creation",
    "data_source_id": "DS0014",
    "data_source_name": "Pod",
    "definition": "Mirror pod creation events on the Kubernetes API server that represent kubelet-managed static pods. A new mirror pod with no corresponding Deployment or DaemonSet owner, running on a specific node, indicates a static pod was started.",
    "url": "https://attack.mitre.org/datasources/DS0014/",
    "relevant_events": [
      "Kubernetes audit event: pod creation where pod name ends with node hostname suffix (static pod naming convention, e.g., attacker-pod-node01)",
      "Kubernetes event: pod with ownerReferences=[] and annotations['kubernetes.io/config.source']=file on a specific node",
      "Kubernetes API: GET pods --field-selector spec.nodeName=<node> showing pod with no Deployment/RS owner reference and suspicious image"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[]
```

(No MITRE technique ID; no canonical DET IDs. Closest MITRE technique might be T1543 or T1053 but no authoritative mapping found.)

**Notes / Confidence:**
- No MITRE ID; data components are inferred from the MS matrix description and Kubernetes kubelet documentation. Confidence: **Likely**.
- File system monitoring (DS0022) of the static pod manifest directory is the most actionable detection surface. This is well-established in Kubernetes hardening guides (CIS Kubernetes Benchmark recommends file integrity monitoring on this path). Confidence: **Likely**.
- The mirror pod approach (DS0014 Pod Creation) provides a secondary, API-level detection that does not require node-level access. Confidence: **Likely**.

**Open questions:**
- Possible MITRE mapping: T1543.005 (Container Service) could apply; T1543 (Create or Modify System Process) is a reasonable parent. No authoritative resolution found.

---

## PRIVILEGE ESCALATION

---

### MS-TA9018 - Privileged Container

**MITRE IDs:** T1610

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1610/` - Deploy Container
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml` (ID: c5cd1b20) - detects creation of pods with privileged security context, hostNetwork, or excessive Linux capabilities. Tags: `attack.t1611` (Escape to Host), `attack.privilege-escalation`. Note: Sigma tags this as T1611 (Escape to Host) rather than T1610.
- Falco: `debugfs_launched_in_privileged_container` (T1611, maturity_stable) and `detect_release_agent_file_container_escapes` cover post-exploitation of privileged containers. No rule for the deployment creation of a privileged container.
- Atomic Red Team: T1610 Test T1610-1 (Deploy Docker container with docker run) - can simulate deploying privileged containers.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording creation of pods with privileged security contexts (securityContext.privileged=true), dangerous Linux capabilities, or host namespace bindings (hostPID, hostNetwork, hostIPC), indicating privileged container deployment.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=create, objectRef.resource=pods where spec.containers[].securityContext.privileged=true",
      "Kubernetes audit event: verb=create, objectRef.resource=pods where spec.hostPID=true or spec.hostNetwork=true or spec.hostIPC=true",
      "Kubernetes audit event: verb=create, objectRef.resource=pods where spec.containers[].securityContext.capabilities.add contains SYS_ADMIN, SYS_PTRACE, NET_ADMIN, or ALL"
    ]
  },
  {
    "id": null,
    "name": "Container Creation",
    "data_source_id": "DS0032",
    "data_source_name": "Container",
    "definition": "Container creation events on cluster nodes where the container runtime starts a container with privileged mode or host namespace access, detectable via container runtime events or node-level audit.",
    "url": "https://attack.mitre.org/datasources/DS0032/",
    "relevant_events": [
      "containerd/cri-o event: container started with linux.security_context.privileged=true in container spec",
      "crictl inspect output: Privileged: true for a running container not associated with a known infrastructure workload",
      "Node-level: container process running as UID 0 with full capabilities visible in /proc/<pid>/status CapBnd: ffffffffffffffff"
    ]
  },
  {
    "id": null,
    "name": "Process Creation",
    "data_source_id": "DS0009",
    "data_source_name": "Process",
    "definition": "Process creation events inside a privileged container showing host escape attempts such as debugfs, nsenter, chroot into host filesystem mounts, or release_agent manipulation - these confirm exploitation rather than just deployment.",
    "url": "https://attack.mitre.org/datasources/DS0009/",
    "relevant_events": [
      "Falco: spawned_process, container=true, container.privileged=true, proc.name=debugfs (Escape to Host indicator)",
      "Falco: open_write, container=true, fd.name endswith /sys/fs/cgroup/release_agent (cgroup escape attempt)",
      "Linux auditd: nsenter or chroot executed inside privileged container namespace, targeting host PID namespace"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0249",
    "name": "Behavior-chain detection for T1610 Deploy Container across Docker and Kubernetes control/node planes",
    "summary": "AN0693 specifically flags containers started with risky runtime attributes including --privileged and host namespace sharing. The privileged container creation is the deployment event; Falco rules cover the subsequent escape activity.",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "data_component_refs": ["Application Log Content", "Container Creation", "Process Creation"]
  }
]
```

**Notes / Confidence:**
- DET0249 confirmed from STIX for T1610. AN0693 description explicitly mentions `--privileged` and host namespace sharing as risky runtime attributes. Confidence: **Confirmed**.
- The Sigma rule `kubernetes_audit_privileged_pod_creation.yml` tags this as T1611 (Escape to Host), which is the downstream effect. The deployment itself is T1610. Both DET IDs apply in sequence. Confidence: **Confirmed** for Sigma rule existence.
- Falco's `debugfs_launched_in_privileged_container` rule covers the container escape phase (T1611) and is a complementary detection to the deployment-phase signals here. Confidence: **Confirmed** (read rule condition).

**Open questions:**
- The MS matrix places this in Privilege Escalation while MITRE T1610 is tagged Execution/Defense Evasion. The privilege escalation dimension comes from the subsequent host escape (T1611). Consider referencing T1611 in the JSON updates.

---

### MS-TA9019 - Cluster-admin Binding

**MITRE IDs:** T1078, T1078.003

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1078/003/` - Local Accounts sub-technique
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster-admin%20binding/`
- SigmaHQ: `rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml` (ID: 10b97915) - detects creation/modification of ClusterRoleBindings and RoleBindings. Tags: `attack.privilege-escalation`. Also `azure_kubernetes_role_access.yml`.
- Falco: No dedicated Falco rule for RBAC binding creation in `falco_rules.yaml` (this is a K8s API operation, not a syscall).
- Atomic Red Team: `atomics/T1078.003/T1078.003.md` exists but focuses on Windows local account abuse; no K8s cluster-admin binding atomic found.

Note: T1078.003 (Local Accounts) is an imperfect MITRE mapping for this technique; the behavior is closer to T1078 parent or T1098 (Account Manipulation). The MS matrix uses T1078.003 for the "valid local Kubernetes account" dimension.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Kubernetes API server audit log recording creation or modification of ClusterRoleBindings and RoleBindings, especially those granting cluster-admin or other high-privilege roles to subjects not previously holding them.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "Kubernetes audit event: verb=create, objectRef.apiGroup=rbac.authorization.k8s.io, objectRef.resource=clusterrolebindings where roleRef.name=cluster-admin",
      "Kubernetes audit event: verb=create, objectRef.apiGroup=rbac.authorization.k8s.io, objectRef.resource=rolebindings where roleRef.name in [cluster-admin, admin, edit] and objectRef.namespace=kube-system",
      "Kubernetes audit event: verb in [update, patch], objectRef.resource=clusterrolebindings - any modification to an existing cluster-admin binding subjects list"
    ]
  },
  {
    "id": null,
    "name": "User Account Modification",
    "data_source_id": "DS0002",
    "data_source_name": "User Account",
    "definition": "Changes to Kubernetes RBAC bindings that effectively modify a user's or service account's permission set - equivalent to modifying a user's group membership or role assignment in an identity system.",
    "url": "https://attack.mitre.org/datasources/DS0002/",
    "relevant_events": [
      "Kubernetes audit event: new ClusterRoleBinding created binding a service account, user, or group to cluster-admin ClusterRole",
      "Kubernetes audit event: existing ClusterRoleBinding patched to add a new subject (subjects[] modified) for a high-privilege role",
      "Cloud provider IAM event: AKS Azure AD group added to cluster-admin binding, or EKS aws-auth ConfigMap modified to add new user ARN"
    ]
  },
  {
    "id": null,
    "name": "Cluster Metadata",
    "data_source_id": "DS0031",
    "data_source_name": "Cluster",
    "definition": "Periodic enumeration of cluster-wide RBAC state (ClusterRoleBindings, RoleBindings) to detect unauthorized bindings to privileged roles, used as a baseline comparison or policy enforcement check.",
    "url": "https://attack.mitre.org/datasources/DS0031/",
    "relevant_events": [
      "kubectl get clusterrolebindings -o json: any subject with namespace that is not kube-system bound to cluster-admin",
      "RBAC audit tool output: service account in user namespace with cluster-admin ClusterRoleBinding (policy violation)",
      "Admission controller (OPA/Gatekeeper) constraint violation: ClusterRoleBinding creation blocked or alerted for binding to cluster-admin role by non-privileged principal"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0407",
    "name": "Detection of Local Account Abuse for Initial Access and Persistence",
    "summary": "AN1137-AN1139 cover anomalous usage of local accounts outside expected context. In K8s, the Kubernetes ServiceAccount and User subjects in RBAC bindings are the local account equivalents. AN1139 (abnormal logins via local accounts via SSH) maps to unexpected use of newly-bound cluster-admin service accounts.",
    "url": "https://attack.mitre.org/techniques/T1078/003/",
    "data_component_refs": ["Application Log Content", "User Account Modification"]
  },
  {
    "id": "DET0560",
    "name": "Detection of Valid Account Abuse Across Platforms",
    "summary": "AN1547 specifically covers containerized service account misuse for cluster access from unexpected nodes or IPs, which is the downstream effect of an illegitimate cluster-admin binding being used.",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "data_component_refs": ["Application Log Content", "Cluster Metadata"]
  }
]
```

**Notes / Confidence:**
- DET0407 confirmed from STIX for T1078.003. Confidence: **Confirmed**. The mapping of K8s RBAC subjects to "local accounts" is a community convention, not a MITRE-native mapping; T1078.003 was written for host-level local accounts. Confidence for K8s-specific relevance: **Likely**.
- DET0560 confirmed from STIX for T1078 parent, with AN1547 directly mentioning containerized service account misuse. Confidence: **Confirmed**.
- The Sigma rule `kubernetes_audit_rolebinding_modification.yml` is the most directly applicable detection; **Confirmed** (read full rule, it exactly targets the rbac.authorization.k8s.io API group for rolebinding and clusterrolebinding objects).

**Open questions:**
- T1078.003 is an awkward mapping; T1078.004 (Cloud Accounts) might be more accurate when the cluster-admin binding is for a cloud-managed identity. The mapping is retained per the stub definition but flagged for review.

---

### MS-TA9020 - Access Cloud Resources

**MITRE IDs:** T1078, T1078.004

**Authoritative sources fetched:**
- `https://attack.mitre.org/techniques/T1078/004/` - Cloud Accounts
- `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20cloud%20resources/`
- SigmaHQ: No dedicated Sigma rule for cloud metadata API access from K8s pods found. The `kubernetes_audit_hostpath_mount.yml` rule (ID: 402b955c) covers the hostPath mount vector that can expose `/etc/kubernetes/azure.json`.
- Falco: `find_aws_credentials` rule (T1552, maturity_stable) covers processes searching for AWS credentials. `read_sensitive_file_untrusted` covers unauthorized reads of `/etc/kubernetes/azure.json` if added to sensitive files macro.
- Atomic Red Team: `atomics/T1078.004/T1078.004.md` - GCP service account key creation, Azure Automation Runbook persistence, GCP custom IAM role creation.

**Recommended `data_components[]`:**

```json
[
  {
    "id": null,
    "name": "Application Log Content",
    "data_source_id": "DS0015",
    "data_source_name": "Application Log",
    "definition": "Cloud provider audit logs and Kubernetes audit logs recording API calls made from pods using cloud-managed identities (managed identity tokens, EC2 instance profile, GCP Workload Identity), especially calls to services outside the cluster's expected scope.",
    "url": "https://attack.mitre.org/datasources/DS0015/",
    "relevant_events": [
      "AWS CloudTrail: API call from EC2 instance role (node identity) or pod-assumed IAM role for S3, IAM, or EC2 operations not normally performed by the cluster",
      "Azure Activity Log: operation from AKS managed identity (type=ManagedIdentity) accessing Key Vault, Storage Account, or subscription-level resources",
      "GCP Cloud Audit Log: API call using a Workload Identity-mapped service account accessing GCS, BigQuery, or IAM admin APIs from unexpected pod"
    ]
  },
  {
    "id": null,
    "name": "File Access",
    "data_source_id": "DS0022",
    "data_source_name": "File",
    "definition": "Read access to cloud credential files on the cluster node (e.g., /etc/kubernetes/azure.json for AKS service principal, /var/lib/kubelet/kubeconfig) from container processes via hostPath mounts, which is the file-based credential theft vector.",
    "url": "https://attack.mitre.org/datasources/DS0022/",
    "relevant_events": [
      "Linux auditd: open_read syscall on /etc/kubernetes/azure.json by a process not in [kubelet, cloud-controller-manager]",
      "Falco: read_sensitive_file_untrusted - proc reading /etc/kubernetes/azure.json or /var/lib/kubelet/kubeconfig with proc.name not in trusted kubelet processes",
      "Kubernetes audit event: verb=create on pod with spec.volumes[].hostPath.path matching /etc/kubernetes/ or /var/lib/kubelet/"
    ]
  },
  {
    "id": null,
    "name": "Network Connection Creation",
    "data_source_id": "DS0029",
    "data_source_name": "Network Traffic",
    "definition": "Outbound network connections from pods to the cloud metadata service endpoint (169.254.169.254 or platform-specific alternatives), indicating an attempt to retrieve cloud identity tokens or configuration data.",
    "url": "https://attack.mitre.org/datasources/DS0029/",
    "relevant_events": [
      "Network flow: TCP connection from pod to 169.254.169.254:80 by process not in [kubelet, cloud-controller-manager, node-local-dns]",
      "Network flow: HTTP GET to http://169.254.169.254/metadata/identity/oauth2/token (Azure IMDS) or http://169.254.169.254/latest/meta-data/iam/security-credentials/ (AWS IMDS) from application container",
      "Falco: container process opening connection to 169.254.169.254 when container is not expected to use managed identity"
    ]
  },
  {
    "id": null,
    "name": "Logon Session Creation",
    "data_source_id": "DS0028",
    "data_source_name": "Logon Session",
    "definition": "Cloud IAM token issuance events triggered by pods requesting temporary credentials via the Instance Metadata Service or Workload Identity federation, where the requesting pod's identity or IP is unexpected.",
    "url": "https://attack.mitre.org/datasources/DS0028/",
    "relevant_events": [
      "AWS: STS AssumeRoleWithWebIdentity or AssumeRole call using EKS pod identity token from unexpected namespace or service account",
      "Azure: IMDS token request from a node IP not associated with a known workload that requires cloud resource access",
      "GCP: google.oauth2.service_accounts.generateAccessToken called for Workload Identity-mapped service account from pod in unexpected namespace"
    ]
  }
]
```

**Recommended `detection_strategies[]`:**

```json
[
  {
    "id": "DET0546",
    "name": "Detection of Abused or Compromised Cloud Accounts for Access and Persistence",
    "summary": "AN1503-AN1506 cover anomalous cloud account authentication patterns. AN1504 specifically targets API calls exceeding normal scope (e.g., IAM changes or access to services never used before), which is the pattern when a pod accesses cloud resources it should not reach.",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "data_component_refs": ["Application Log Content", "Logon Session Creation"]
  },
  {
    "id": "DET0560",
    "name": "Detection of Valid Account Abuse Across Platforms",
    "summary": "AN1547 covers containerized service account or compromised kubeconfig being used for cluster access from unexpected nodes or IPs. This extends to cloud resource access made using the pod's cloud identity.",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "data_component_refs": ["Application Log Content", "Logon Session Creation", "Network Connection Creation"]
  }
]
```

**Notes / Confidence:**
- DET0546 confirmed from STIX for T1078.004. AN1504 description explicitly covers API calls exceeding normal scope. Confidence: **Confirmed**.
- DET0560 confirmed from STIX for T1078 parent, with AN1547 mentioning containerized service account misuse. Confidence: **Confirmed**.
- The hostPath mount vector to `/etc/kubernetes/azure.json` is documented in the MS matrix description. The Sigma rule `kubernetes_audit_hostpath_mount.yml` covers the deployment phase of this attack. Confidence: **Confirmed** (rule read in full).

**Open questions:**
- The IMDS access restriction (MS-M9018) and pod identity assignment (MS-M9019) are the recommended mitigations but are outside the detection scope of this report.

---

## Summary Table

| ID | MS Technique Name | MITRE IDs | Recommended data_components count | Recommended detection_strategies count |
|----|-------------------|-----------|-----------------------------------|----------------------------------------|
| MS-TA9001 | Using Cloud Credentials | T1078, T1078.004 | 3 | 2 |
| MS-TA9003 | Kubeconfig file | (none) | 3 | 0 |
| MS-TA9004 | Application Vulnerability | T1190 | 3 | 1 |
| MS-TA9005 | Exposed sensitive interfaces | T1133 | 3 | 1 |
| MS-TA9007 | bash or cmd inside container | T1059 | 3 | 1 |
| MS-TA9009 | Application Exploit (RCE) | T1190 | 3 | 1 |
| MS-TA9010 | SSH server running inside container | (none) | 4 | 0 |
| MS-TA9011 | Sidecar Injection | T1610 | 3 | 1 |
| MS-TA9012 | Backdoor container | T1543 | 3 | 1 |
| MS-TA9014 | Kubernetes CronJob | T1053, T1053.007 | 3 | 1 |
| MS-TA9015 | Malicious admission controller | T1546 | 3 | 1 |
| MS-TA9017 | Static Pods | (none) | 3 | 0 |
| MS-TA9018 | Privileged container | T1610 | 3 | 1 |
| MS-TA9019 | Cluster-admin binding | T1078, T1078.003 | 3 | 2 |
| MS-TA9020 | Access cloud resources | T1078, T1078.004 | 4 | 2 |

**Totals:** 15 techniques, 47 data_component recommendations, 15 detection_strategy recommendations.

---

## Cross-Cutting Observations

**On STIX `x_mitre_data_sources` emptiness:**
The current MITRE ATT&CK STIX bundle (fetched from `github.com/mitre/cti`, main branch, 2026-05-04) stores data source relationships as identity references rather than as DS ID strings in `x_mitre_data_sources`. For the techniques in this batch, all DS and DC assignments are inferred from:
1. The ATT&CK technique web pages (fetched and read).
2. The DET/AN analytic descriptions in the STIX bundle.
3. The MITRE data source catalog (`attack.mitre.org/datasources/`).

The DET IDs and AN IDs ARE confirmed from the STIX bundle (detection strategy objects and their analytic refs were read directly). The DS and DC IDs are confirmed from the STIX data-source and data-component object lists. The DS-to-technique association is inferred, not read from a STIX field. This is flagged per the project's epistemic discipline.

**Preferred DS for Kubernetes audit log:**
DS0015 (Application Log) + DC0038 (Application Log Content) is the recommended primary data source when the detection signal is the Kubernetes API server audit log. This is consistent with the T1053.007 detection strategy (DET0206/AN0582) which was authored with Kubernetes in mind and the Sigma rules which all use `logsource.product=kubernetes, service=audit`.

**Sigma T1609 vs T1059 / T1610 gap:**
The SigmaHQ Kubernetes audit rules frequently tag behavior with `attack.t1609` (Kubernetes Exec) rather than T1059 or T1610. T1609 is a valid separate MITRE technique (Kubernetes Exec Into Container). Where the stub maps to T1059/T1610, the Sigma rule implementing the same behavior uses T1609. Authors of JSON updates should be aware of this discrepancy and may want to add T1609 cross-references to MS-TA9007 and MS-TA9011.

---

## Research Process

### Searches Performed

1. (No WebSearch queries used; all evidence gathered via WebFetch and GitHub API)

### Pages Fetched and Read

**Official MITRE sources:**
- [Official] `https://attack.mitre.org/techniques/T1078/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1078/004/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1078/003/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1190/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1133/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1059/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1610/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1543/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1053/007/` (fetched, read)
- [Official] `https://attack.mitre.org/techniques/T1546/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/DS0002/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/DS0009/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/DS0015/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/DS0029/` (fetched, read)
- [Official] `https://attack.mitre.org/datasources/DS0032/` (fetched, read)
- [Official] `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` (fetched via curl, parsed Python: extracted all x-mitre-data-source, x-mitre-data-component, x-mitre-detection-strategy, x-mitre-analytic, and 'detects' relationship objects)

**Microsoft Kubernetes Threat Matrix sources:**
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Using%20Cloud%20Credentials/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Kubeconfig%20file/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20Vulnerability/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exposed%20sensitive%20interfaces/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/bash%20or%20cmd%20inside%20container/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20Exploit%20%28RCE%29/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/SSH%20server%20running%20inside%20container/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20Injection/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Backdoor%20container/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Kubernetes%20CronJob/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Malicious%20admission%20controller/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Static%20Pods/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster-admin%20binding/` (fetched, read)
- [Official] `https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20cloud%20resources/` (fetched, read)

**SigmaHQ rules (via GitHub API, fetched in full):**
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_cronjob_modification.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml` (read in full)
- [Community] `rules/application/kubernetes/audit/kubernetes_audit_serviceaccount_creation.yml` (read in full)
- [Community] Full directory listing: `rules/application/kubernetes/audit/` (16 files enumerated)

**Falco rules (via GitHub API + WebFetch):**
- [Community] `https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml` (fetched, relevant rules extracted)

**Atomic Red Team (via GitHub API + WebFetch):**
- [Community] `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1610/T1610.md` (fetched, read)
- [Community] `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1053.007/T1053.007.md` (fetched, read)
- [Community] `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1078.004/T1078.004.md` (fetched, read)
- [Community] `atomics/T1059.004/T1059.004.yaml` (fetched via GitHub API, read)

### Sources Rejected

- Direct fetch of `enterprise-attack.json` via WebFetch: rejected (file exceeds 10MB limit). Used `curl` via Bash instead.
- GitHub code search results for Reddit/community blogs: not pursued; official STIX + Sigma + Falco sources provided sufficient evidence.
- `falco-incubating_rules.yaml`: URL retrieved but content not fetched; stable rules provided sufficient coverage for this research scope.

### Gaps

- No dedicated Sigma rules found for: kubeconfig file access, SSH server in container, static pod manifest modification, cloud metadata API access from pods.
- MITRE technique pages for T1078.003, T1078.004, T1190, T1133, T1059, T1543, T1546 returned detection analytics but listed "Data Sources: Not explicitly listed" - the STIX bundle confirms these fields are empty in the current spec version. DS assignments are from the ATT&CK technique page text (read via WebFetch) and the DET/AN content.
- No Atomic Red Team tests found for: Kubeconfig file theft, SSH server in container, static pod persistence, malicious admission controller, cluster-admin binding in Kubernetes.
- Falco rules for K8s API operations (DaemonSet creation, ClusterRoleBinding modification, CronJob creation) are absent from the syscall-based `falco_rules.yaml`; these require the Kubernetes audit log plugin for Falco, which is a separate configuration.

### Tools Used

- WebFetch: 20 pages fetched
- Bash (GitHub API via `gh`): 12 queries (Sigma rule listing and content fetching, Atomic Red Team searching)
- Bash (curl): 4 queries (STIX bundle download and parsing via Python)
- Read: 3 files (15 stub JSON files via single batch read, persisted output file)
