# MITRE Cross-Reference Research Report

**Project:** Equilibrium  
**Scope:** All 40 MS-TA records (MS-TA9001 through MS-TA9041, excluding the missing MS-TA9032)  
**Date:** 2026-05-04  
**Author:** Research Agent  
**Purpose:** Identify secondary MITRE ATT&CK technique IDs that defenders should track alongside each record's primary mapping. Populate `mitre_cross_references[]` recommendations for every record.

---

## MS-TA9001 -- Using Cloud Credentials

**Primary:** T1078.004 (Cloud Accounts)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1059.009",
    "name": "Cloud API",
    "url": "https://attack.mitre.org/techniques/T1059/009/",
    "relationship": "downstream_capability",
    "rationale": "MITRE's T1078.004 procedure text explicitly states that adversaries with compromised cloud accounts use Cloud API commands to access sensitive data in storage accounts and interact with Kubernetes management APIs. After obtaining cloud credentials an adversary's first observable action is typically a Cloud API call (e.g., az aks get-credentials, aws eks get-token, gcloud container clusters get-credentials) -- these calls map to T1059.009, not T1078.004 itself.",
    "sources": [
      "https://attack.mitre.org/techniques/T1078/004/"
    ]
  },
  {
    "technique_id": "T1528",
    "name": "Steal Application Access Token",
    "url": "https://attack.mitre.org/techniques/T1528/",
    "relationship": "sibling_technique",
    "rationale": "MITRE's T1078.004 page explicitly names T1528 as a follow-on: 'Compromising resources with Managed Identities enables Steal Application Access Tokens.' In AKS and GKE, managed identity tokens obtained via the cloud management plane can be re-used in container workloads. Defenders who alert on T1078.004 must also cover the token-theft pivot T1528 captures.",
    "sources": [
      "https://attack.mitre.org/techniques/T1078/004/"
    ]
  }
]
```

### Notes / confidence
- T1059.009 downstream: **Confirmed** -- MITRE procedure text on T1078.004 page names the technique.
- T1528 sibling: **Confirmed** -- MITRE procedure text on T1078.004 page explicitly cross-links T1528.

---

## MS-TA9002 -- Implant Internal Image (Compromised Image In Registry)

**Primary:** T1525 (Implant Internal Image)  
**Already lists references to T1195 / T1195.002 in the data file's `references[]` array** (URL list only, not yet in `mitre_cross_references[]`).

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1195.002",
    "name": "Compromise Software Supply Chain",
    "url": "https://attack.mitre.org/techniques/T1195/002/",
    "relationship": "supply_chain_relationship",
    "rationale": "T1525 covers implanting a malicious image inside the victim's own registry (internal persistence). T1195.002 covers poisoning a software artifact before it reaches the victim -- the distinction is where in the supply chain the compromise occurs. When a base image is tampered with upstream (public registry, CI/CD pipeline) and the victim's cluster pulls it, T1195.002 is the correct technique; T1525 applies when an authenticated attacker modifies an image already inside the victim's private registry. Defenders should alert on both pull-from-poisoned-upstream (T1195.002) and push-to-internal-registry (T1525) as separate but related event chains.",
    "sources": [
      "https://attack.mitre.org/techniques/T1525/",
      "https://attack.mitre.org/techniques/T1195/002/"
    ]
  },
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "downstream_capability",
    "rationale": "The implanted image is operationalized when a new container is deployed from it (T1610). Atomic Red Team T1610 test documents this exact chain: adversary builds a malicious image then launches it via docker create/start or kubectl apply. Detection of image implantation alone (T1525) is incomplete without chaining to the first deploy event that activates the payload.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md"
    ]
  }
]
```

### Notes / confidence
- T1195.002 supply chain: **Confirmed** -- Both upstream MITRE technique pages document the distinction.
- T1610 downstream: **Confirmed** -- Atomic Red Team T1610 test explicitly chains malicious image build to container launch.

---

## MS-TA9003 -- Kubeconfig File

**Primary:** null (no MITRE mapping assigned)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1552.001",
    "name": "Credentials In Files",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "relationship": "more_specific_subtechnique",
    "rationale": "A kubeconfig file is a credential file on disk: it contains cluster endpoint, CA certificate, client certificates, and/or bearer tokens. MITRE T1552.001 explicitly covers reading credential material from files on disk, and its detection text calls out container/orchestration credential paths including '~/.kube/config' and service token files. This is the most precise MITRE mapping for the kubeconfig-file exfiltration scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/"
    ]
  },
  {
    "technique_id": "T1078.003",
    "name": "Local Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/003/",
    "relationship": "downstream_capability",
    "rationale": "After reading the kubeconfig file (T1552.001), an adversary uses the embedded credentials to authenticate as a valid Kubernetes user (T1078.003). MITRE's T1078.003 page specifically calls out Kubernetes service accounts and recommends auditing their use. The kubeconfig theft scenario is a two-step chain: credential read (T1552.001) followed by valid-account abuse (T1078.003).",
    "sources": [
      "https://attack.mitre.org/techniques/T1078/003/"
    ]
  }
]
```

### Notes / confidence
- T1552.001 primary mapping: **Confirmed** -- MITRE T1552.001 page names kubeconfig-style paths and Hildegard malware as a real-world example.
- T1078.003 downstream: **Likely** -- The MITRE T1078.003 page mentions Kubernetes service account audit without directly naming kubeconfig files; the chain is structurally clear from both pages.

---

## MS-TA9004 -- Application Vulnerability

**Primary:** T1190 (Exploit Public-Facing Application)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1611",
    "name": "Escape to Host",
    "url": "https://attack.mitre.org/techniques/T1611/",
    "relationship": "downstream_capability",
    "rationale": "MITRE's T1190 detection text explicitly names container breakout as a downstream consequence of exploiting a public-facing containerized application: 'container and Kubernetes-based attacks' appears in detection analytic AN0222. The T1611 page cross-references T1068 (Exploitation for Privilege Escalation) as the mechanism, and MITRE's T1190 page mentions T1611 directly in its detection chain.",
    "sources": [
      "https://attack.mitre.org/techniques/T1190/",
      "https://attack.mitre.org/techniques/T1611/"
    ]
  },
  {
    "technique_id": "T1059",
    "name": "Command and Scripting Interpreter",
    "url": "https://attack.mitre.org/techniques/T1059/",
    "relationship": "downstream_capability",
    "rationale": "MITRE's T1190 detection strategy AN0219-AN0224 describes the canonical post-exploit chain as 'abnormal request to public endpoint -> server process spawns shell/LOLbins'. The shell invocation that follows a successful exploit maps to T1059 (and more specifically T1059.004 Unix Shell or T1059.013 Container CLI/API). Defenders must alert on T1059 events from web-server processes to detect the T1190 exploitation moment.",
    "sources": [
      "https://attack.mitre.org/techniques/T1190/"
    ]
  }
]
```

### Notes / confidence
- T1611 downstream: **Confirmed** -- MITRE T1190 detection text names container breakout; T1611 page confirms T1068/exploitation as an enabling mechanism.
- T1059 downstream: **Confirmed** -- MITRE T1190 detection strategy explicitly describes the shell-spawn chain.

---

## MS-TA9005 -- Exposed Sensitive Interfaces

**Primary:** T1133 (External Remote Services)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078",
    "name": "Valid Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "relationship": "upstream_precondition",
    "rationale": "MITRE's T1133 page states directly: 'Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.' An exposed Kubernetes dashboard, Kubeflow, or Docker daemon API may require valid credentials; the T1078 family represents the precondition that allows initial authentication once the interface is discovered.",
    "sources": [
      "https://attack.mitre.org/techniques/T1133/"
    ]
  },
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "downstream_capability",
    "rationale": "An unauthenticated or weakly authenticated Docker API or Kubernetes dashboard (T1133) is most commonly abused to deploy malicious containers (T1610). Atomic Red Team T1610 cites the Kinsing/Doki campaign, which exploited exposed Docker APIs to deploy containers -- the canonical path from exposed interface to container deployment.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md",
      "https://attack.mitre.org/techniques/T1610/"
    ]
  }
]
```

### Notes / confidence
- T1078 precondition: **Confirmed** -- MITRE T1133 page text explicitly states this relationship.
- T1610 downstream: **Confirmed** -- Atomic Red Team T1610 and MITRE T1610 procedure examples (Kinsing, Doki, TeamTNT) all start from an exposed API.

---

## MS-TA9006 -- Exec Into Container

**Primary:** T1609 (Container Administration Command)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1059.004",
    "name": "Unix Shell",
    "url": "https://attack.mitre.org/techniques/T1059/004/",
    "relationship": "downstream_capability",
    "rationale": "kubectl exec and docker exec (T1609) deliver interactive shell sessions inside the container, and subsequent attacker activity -- enumeration, lateral movement, credential access -- is executed via a Unix shell (T1059.004). Falco's 'Terminal shell in container' rule is tagged T1059 and fires on the shell creation that results from a T1609 exec. Defenders who alert only on T1609 (the exec API call) miss the ongoing shell activity that follows.",
    "sources": [
      "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"
    ]
  },
  {
    "technique_id": "T1611",
    "name": "Escape to Host",
    "url": "https://attack.mitre.org/techniques/T1611/",
    "relationship": "downstream_capability",
    "rationale": "MITRE's T1611 page explicitly states: 'an adversary may be able to exploit a compromised container with a mounted container management socket, such as docker.sock, to break out of the container via a Container Administration Command (T1609).' Interactive shell access via T1609 into a privileged container or a container with a mounted socket is the most common precondition for host escape.",
    "sources": [
      "https://attack.mitre.org/techniques/T1611/",
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md"
    ]
  }
]
```

### Notes / confidence
- T1059.004 downstream: **Confirmed** -- Falco stable rule "Terminal shell in container" (tagged T1059) is triggered by the shell session created after T1609 exec.
- T1611 downstream: **Confirmed** -- MITRE T1611 page explicitly cites T1609 as enabling host escape.

---

## MS-TA9007 -- Bash or cmd Inside Container

**Primary:** T1059  
Already populated: T1609 (tagged_by_community_rules). Do not duplicate.

### Already populated; review for any additional cross-references not yet captured.

```json
[
  {
    "technique_id": "T1059.004",
    "name": "Unix Shell",
    "url": "https://attack.mitre.org/techniques/T1059/004/",
    "relationship": "more_specific_subtechnique",
    "rationale": "The primary mapping is T1059 (parent). T1059.004 (Unix Shell) is the more specific sub-technique covering /bin/bash, /bin/sh, and other Unix shells invoked inside containers. Falco's stable rule 'Run shell untrusted' is tagged T1059.004 specifically, and 'Terminal shell in container' / 'System user interactive' are tagged at the T1059 parent level -- the Falco ruleset itself demonstrates that container shell invocations are detected at both levels.",
    "sources": [
      "https://attack.mitre.org/techniques/T1059/004/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"
    ]
  },
  {
    "technique_id": "T1059.013",
    "name": "Container CLI/API",
    "url": "https://attack.mitre.org/techniques/T1059/013/",
    "relationship": "sibling_technique",
    "rationale": "MITRE introduced T1059.013 (Container CLI/API) to cover adversaries abusing kubectl, docker exec, and container management APIs -- the orchestration layer. When an adversary reaches a bash prompt inside a container via kubectl exec, the exec command itself is T1059.013 (or T1609) while the subsequent bash session is T1059.004. A defender's detection pipeline must cover both the CLI/API invocation layer and the in-container shell layer.",
    "sources": [
      "https://attack.mitre.org/techniques/T1059/",
      "https://attack.mitre.org/techniques/T1059/013/"
    ]
  }
]
```

### Notes / confidence
- T1059.004 more specific: **Confirmed** -- Sub-technique relationship is direct; Falco rules confirm the tagging at this level.
- T1059.013 sibling: **Confirmed** -- MITRE lists T1059.013 as a real sub-technique covering container orchestration CLI/API invocations; the distinction between orchestration-layer (T1059.013) and in-container shell (T1059.004) is documented on the T1059 parent page.

---

## MS-TA9008 -- New Container

**Primary:** T1610 (Deploy Container)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1611",
    "name": "Escape to Host",
    "url": "https://attack.mitre.org/techniques/T1611/",
    "relationship": "downstream_capability",
    "rationale": "MITRE's T1610 description explicitly states: 'In Kubernetes environments, an adversary may attempt to deploy a privileged or vulnerable container into a specific node in order to Escape to Host (T1611) and access other containers running on the node.' The Atomic Red Team T1610 test also documents this chain.",
    "sources": [
      "https://attack.mitre.org/techniques/T1610/",
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md"
    ]
  },
  {
    "technique_id": "T1525",
    "name": "Implant Internal Image",
    "url": "https://attack.mitre.org/techniques/T1525/",
    "relationship": "upstream_precondition",
    "rationale": "A container deployed from a malicious or implanted image (T1525) is the upstream step that loads the payload. The Atomic Red Team T1610 test explicitly chains image build to container launch: 'docker build ... && docker run ...'. Detection of T1610 deploy events is incomplete without also tracking the registry push event that T1525 captures.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md"
    ]
  }
]
```

### Notes / confidence
- T1611 downstream: **Confirmed** -- MITRE T1610 page text explicitly names T1611 as the follow-on objective.
- T1525 upstream: **Confirmed** -- Atomic Red Team T1610 test documents the image-build-then-launch chain.

---

## MS-TA9009 -- Application Exploit for RCE

**Primary:** T1190 (Exploit Public-Facing Application)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1068",
    "name": "Exploitation for Privilege Escalation",
    "url": "https://attack.mitre.org/techniques/T1068/",
    "relationship": "downstream_capability",
    "rationale": "MITRE T1068 detection analytic AN1422 explicitly addresses 'container breakout behavior via exploitation (e.g., DirtyPipe, CVE-2022-0847), followed by host OS interaction.' An RCE in a containerized application (T1190) commonly chains to a container-escape CVE exploitation (T1068) as the path to host-level privilege. This is distinct from MS-TA9004 where the exploit IS the initial access; here the RCE in the container is the starting point for escalation.",
    "sources": [
      "https://attack.mitre.org/techniques/T1068/"
    ]
  },
  {
    "technique_id": "T1611",
    "name": "Escape to Host",
    "url": "https://attack.mitre.org/techniques/T1611/",
    "relationship": "downstream_capability",
    "rationale": "Same chain as MS-TA9004 but from a container-internal RCE perspective: MITRE T1611 page cites T1068 and T1609 as enabling mechanisms, and Siloscape malware is documented as using Windows container RCE (T1190) to escape to the host (T1611).",
    "sources": [
      "https://attack.mitre.org/techniques/T1611/"
    ]
  }
]
```

### Notes / confidence
- T1068 downstream: **Confirmed** -- MITRE T1068 detection text explicitly mentions DirtyPipe container breakout.
- T1611 downstream: **Confirmed** -- MITRE T1611 page cites exploitation as an enabling mechanism and names Siloscape as a real-world example.

---

## MS-TA9010 -- SSH Server Running Inside Container

**Primary:** null (no MITRE mapping assigned)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1021.004",
    "name": "Remote Services: SSH",
    "url": "https://attack.mitre.org/techniques/T1021/004/",
    "relationship": "more_specific_subtechnique",
    "rationale": "An SSH server inside a container provides a persistent remote-access channel that attackers use for lateral movement. MITRE T1021.004 covers SSH-based remote service access; its procedure examples include Kinsing malware, which specifically 'used SSH for lateral movement' in container-targeted campaigns. This is the most precise MITRE mapping for the container-SSH-server-as-backdoor scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1021/004/"
    ]
  },
  {
    "technique_id": "T1543",
    "name": "Create or Modify System Process",
    "url": "https://attack.mitre.org/techniques/T1543/",
    "relationship": "sibling_technique",
    "rationale": "Running an SSH daemon inside a container as a persistence mechanism is structurally similar to T1543 (creating or modifying a persistent system process). When the SSH server is started at container launch via an entrypoint or init script it functions as a persistent service; T1543.005 (Container Service) covers the pattern of embedding a persistent service inside a container image. Defenders should alert on sshd process creation in containers alongside detecting the container configuration.",
    "sources": [
      "https://attack.mitre.org/techniques/T1543/005/"
    ]
  }
]
```

### Notes / confidence
- T1021.004 mapping: **Confirmed** -- MITRE T1021.004 procedure examples explicitly name Kinsing container-SSH lateral movement.
- T1543 sibling: **Likely** -- T1543.005 covers persistent container services; the structural fit is strong but MITRE does not name SSH-in-container explicitly on the T1543 page.

---

## MS-TA9011 -- Sidecar Injection

**Primary:** T1610 (Deploy Container)  
Already populated: T1609 (tagged_by_community_rules). Do not duplicate.

### Already populated; review for any additional cross-references not yet captured.

```json
[
  {
    "technique_id": "T1552",
    "name": "Unsecured Credentials",
    "url": "https://attack.mitre.org/techniques/T1552/",
    "relationship": "downstream_capability",
    "rationale": "A malicious sidecar container shares the pod's filesystem, environment variables, and service account token with the main container. The Sigma rule 'kubernetes_audit_sidecar_injection' is tagged T1609 (tagged_by_community_rules, already present), but the downstream objective of sidecar injection is typically credential harvesting -- reading the main container's environment variables and mounted secrets maps to T1552 (Unsecured Credentials). Defenders who detect the sidecar deploy (T1610/T1609) should also instrument for in-pod credential reads.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml",
      "https://attack.mitre.org/techniques/T1552/"
    ]
  }
]
```

### Notes / confidence
- T1552 downstream: **Likely** -- The credential-harvesting objective of sidecar injection is well established in container threat literature; MITRE T1552 covers in-environment credential reads but does not name sidecar injection by name.

---

## MS-TA9012 -- Backdoor Container

**Primary:** T1543  
Already populated: T1543.005 (more_specific_subtechnique). Do not duplicate.

### Already populated; review for any additional cross-references not yet captured.

```json
[
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "upstream_precondition",
    "rationale": "A backdoored container service (T1543.005) is instantiated by deploying the container (T1610). The Falco incubating rule 'Launch Privileged Container' is tagged T1610 and fires on the deploy event that activates a backdoored or malicious container. The detection pipeline needs to catch both the deploy trigger (T1610) and the persistent service it establishes (T1543.005).",
    "sources": [
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml",
      "https://attack.mitre.org/techniques/T1610/"
    ]
  }
]
```

### Notes / confidence
- T1610 upstream: **Confirmed** -- Falco incubating rule "Launch Privileged Container" tags T1610 for the deploy event that precedes container service persistence.

---

## MS-TA9013 -- Writable hostPath Mount

**Primary:** T1611 (Escape to Host)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "upstream_precondition",
    "rationale": "The writable hostPath mount is established at container creation time (T1610). MITRE T1611 page cites 'containers configured to mount the host's filesystem using the bind parameter' as the mechanism, and the Sigma rule 'kubernetes_audit_hostpath_mount' fires on T1611 at the pod creation (T1610) event -- the Sigma rule is tagged T1611 even though it fires on a T1610 (create pod) API call, because the mount is the precondition for the escape.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml",
      "https://attack.mitre.org/techniques/T1611/"
    ]
  },
  {
    "technique_id": "T1543",
    "name": "Create or Modify System Process",
    "url": "https://attack.mitre.org/techniques/T1543/",
    "relationship": "downstream_capability",
    "rationale": "A writable hostPath mount exposes the host filesystem. MITRE T1611 Atomic Red Team test 2 ('Mount host filesystem to escape privileged Docker container') documents that after the escape the adversary drops cron jobs and payloads onto the host filesystem -- the host-filesystem write maps to T1543 (persistence via system process) or T1053 (scheduled task). The escape alone (T1611) is incomplete without the persistence step the mount enables.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md"
    ]
  }
]
```

### Notes / confidence
- T1610 upstream: **Confirmed** -- Sigma rule kubernetes_audit_hostpath_mount fires on pod create (T1610 event) and tags T1611; this dual-tagging implies the mount is established via the deploy step.
- T1543 downstream: **Confirmed** -- Atomic Red Team T1611 test 2 explicitly demonstrates cron/payload drop onto host after mount escape.

---

## MS-TA9014 -- Kubernetes CronJob

**Primary:** T1053.007 (Container Orchestration Job)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1053.003",
    "name": "Cron",
    "url": "https://attack.mitre.org/techniques/T1053/003/",
    "relationship": "sibling_technique",
    "rationale": "The Azure Kubernetes Sigma rule 'azure_kubernetes_cronjob' is tagged T1053.003 (Cron) rather than T1053.007 (Container Orchestration Job). This reflects the fact that Kubernetes CronJob semantics are modeled on Unix cron, and several SIEM vendors and rules authors apply T1053.003 when detecting K8s CronJob events. Defenders tuning alerts on T1053.003 may miss K8s-specific CronJob detections tagged at T1053.007, and vice versa.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/activity_logs/azure_kubernetes_cronjob.yml"
    ]
  },
  {
    "technique_id": "T1059",
    "name": "Command and Scripting Interpreter",
    "url": "https://attack.mitre.org/techniques/T1059/",
    "relationship": "downstream_capability",
    "rationale": "A Kubernetes CronJob ultimately executes a container that runs a command or script (T1059). MITRE T1053.007 describes it as 'scheduling deployment of a Job that executes malicious code.' The command execution inside the job container maps to T1059 (parent) or T1059.004/T1059.013 specifically. A detection covering only the Job creation (T1053.007) misses the payload execution inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1053/007/"
    ]
  }
]
```

### Notes / confidence
- T1053.003 sibling: **Confirmed** -- Sigma rule azure_kubernetes_cronjob explicitly tags T1053.003 for Kubernetes CronJob events.
- T1059 downstream: **Confirmed** -- MITRE T1053.007 description explicitly states malicious code executes inside the container.

---

## MS-TA9015 -- Malicious Admission Controller

**Primary:** T1546 (Event Triggered Execution)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078",
    "name": "Valid Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "relationship": "upstream_precondition",
    "rationale": "The Sigma rule 'kubernetes_audit_change_admission_controller' (and its identical GCP/Azure variants) tags T1078 alongside T1552.007. Creating or modifying a webhook admission controller requires cluster-admin privileges; the attacker must first authenticate with valid credentials (T1078) to reach the admissionregistration.k8s.io API endpoint. This precondition is documented in both the Sigma rule description ('can be used by an adversary to achieve persistence or exfiltrate access credentials') and the reference to a Padok security blog post.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/activity_logs/azure_kubernetes_admission_controller.yml"
    ]
  },
  {
    "technique_id": "T1552.007",
    "name": "Container API",
    "url": "https://attack.mitre.org/techniques/T1552/007/",
    "relationship": "downstream_capability",
    "rationale": "The Sigma rule 'kubernetes_audit_change_admission_controller' is tagged both T1078 and T1552.007. A malicious admission controller intercepts every pod creation request and can extract secrets from pod specs, environment variables, and volume mounts as they pass through -- the credential-exfiltration objective maps to T1552.007 (Container API credential read). The rule description explicitly states: 'exfiltrate access credentials' as an objective.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml"
    ]
  }
]
```

### Notes / confidence
- T1078 precondition: **Confirmed** -- Sigma rule tags T1078; rule description explicitly references credential precondition.
- T1552.007 downstream: **Confirmed** -- Sigma rule tags T1552.007; rule description explicitly names credential exfiltration as objective.

---

## MS-TA9016 -- Container Service Account

**Primary:** T1528 (Steal Application Access Token)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1069.003",
    "name": "Permission Groups Discovery: Cloud Groups",
    "url": "https://attack.mitre.org/techniques/T1069/003/",
    "relationship": "tagged_by_community_rules",
    "rationale": "The Sigma rule 'kubernetes_audit_rbac_permisions_listing' tags T1069.003 and T1087.004. After stealing a service account token (T1528), an adversary runs 'kubectl auth can-i --list' (creating a SelfSubjectRulesReview API resource) to enumerate RBAC permissions. The rule description explicitly states: 'In the early stages of a breach, attackers will aim to list the permissions they have.' This discovery step uses the stolen token and is the immediate post-T1528 action.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_rbac_permisions_listing.yml"
    ]
  },
  {
    "technique_id": "T1087.004",
    "name": "Account Discovery: Cloud Account",
    "url": "https://attack.mitre.org/techniques/T1087/004/",
    "relationship": "tagged_by_community_rules",
    "rationale": "The same 'kubernetes_audit_rbac_permisions_listing' Sigma rule also tags T1087.004 (Cloud Account Discovery) alongside T1069.003. This reflects that 'kubectl auth can-i --list' is both a permission-groups discovery and a cloud-account-discovery action in the Kubernetes RBAC context. Defenders should alert on the SelfSubjectRulesReview API call under both IDs.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_rbac_permisions_listing.yml"
    ]
  },
  {
    "technique_id": "T1550.001",
    "name": "Application Access Token",
    "url": "https://attack.mitre.org/techniques/T1550/001/",
    "relationship": "downstream_capability",
    "rationale": "T1528 covers stealing the service account token; T1550.001 covers using that stolen token to authenticate and access cluster APIs without re-supplying credentials. MITRE documents this as a distinct step: T1550.001 is the 'use' phase after the 'steal' phase. MITRE T1528 page explicitly references T1550.001 as the technique that uses the stolen OAuth/service account tokens.",
    "sources": [
      "https://attack.mitre.org/techniques/T1550/001/",
      "https://attack.mitre.org/techniques/T1528/"
    ]
  }
]
```

### Notes / confidence
- T1069.003 tagged_by_community_rules: **Confirmed** -- Sigma rule explicitly tags T1069.003 for the SelfSubjectRulesReview event.
- T1087.004 tagged_by_community_rules: **Confirmed** -- Same Sigma rule explicitly tags T1087.004.
- T1550.001 downstream: **Confirmed** -- MITRE T1528 page references T1550.001 as the operational use phase of stolen tokens.

---

## MS-TA9017 -- Static Pods

**Primary:** null (no MITRE mapping assigned)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1543.005",
    "name": "Container Service",
    "url": "https://attack.mitre.org/techniques/T1543/005/",
    "relationship": "more_specific_subtechnique",
    "rationale": "A static pod is a pod defined by a manifest file on a node's filesystem (/etc/kubernetes/manifests/) and managed directly by kubelet, not the API server. Placing a malicious manifest there creates a persistent container service that restarts automatically -- this is precisely the pattern T1543.005 (Container Service) covers: 'adversaries may create or modify container service configurations to survive system restarts.' Static pods are invisible to kubectl by design and constitute a stealth persistence mechanism.",
    "sources": [
      "https://attack.mitre.org/techniques/T1543/005/",
      "https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/"
    ]
  },
  {
    "technique_id": "T1611",
    "name": "Escape to Host",
    "url": "https://attack.mitre.org/techniques/T1611/",
    "relationship": "upstream_precondition",
    "rationale": "Writing a static pod manifest to /etc/kubernetes/manifests/ requires write access to the host node filesystem. An attacker who has escaped to the host (T1611) can plant a static pod manifest as a persistent backdoor. The sequence is T1611 (host escape) -> write manifest -> static pod becomes persistence. The Atomic Red Team T1611 test 2 explicitly demonstrates that host filesystem write is the outcome of container escape.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md"
    ]
  }
]
```

### Notes / confidence
- T1543.005 mapping: **Confirmed** -- MITRE T1543.005 description matches the static-pod persistence pattern; Kubernetes documentation confirms the kubelet-managed restart behavior.
- T1611 precondition: **Confirmed** -- Atomic Red Team T1611 test 2 demonstrates host filesystem write as the primary capability gained after container escape.

---

## MS-TA9018 -- Privileged Container

**Primary:** T1610 (Deploy Container)  
Already populated: T1611 (downstream_capability). Do not duplicate.

### Already populated; review for any additional cross-references not yet captured.

```json
[
  {
    "technique_id": "T1068",
    "name": "Exploitation for Privilege Escalation",
    "url": "https://attack.mitre.org/techniques/T1068/",
    "relationship": "downstream_capability",
    "rationale": "A privileged container has access to host capabilities and devices, but some escape paths require exploiting kernel vulnerabilities from within the privileged context. MITRE T1068 detection analytic AN1422 specifically covers 'container breakout behavior via exploitation (e.g., DirtyPipe, CVE-2022-0847), followed by host OS interaction.' Falco's 'Debugfs Launched in Privileged Container' rule is tagged T1611; the Sigma rule 'kubernetes_audit_privileged_pod_creation' is also tagged T1611, but the exploitation path from privileged container to host is T1068.",
    "sources": [
      "https://attack.mitre.org/techniques/T1068/",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml"
    ]
  }
]
```

### Notes / confidence
- T1068 downstream: **Confirmed** -- MITRE T1068 detection text explicitly names container breakout via CVE exploitation from privileged containers.

---

## MS-TA9019 -- Cluster-admin Binding

**Primary:** T1078.003 (Local Accounts)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1098.006",
    "name": "Additional Container Cluster Roles",
    "url": "https://attack.mitre.org/techniques/T1098/006/",
    "relationship": "more_specific_subtechnique",
    "rationale": "T1098.006 explicitly covers 'an adversary may add additional roles or permissions to an adversary-controlled user or service account' via Kubernetes RoleBinding or ClusterRoleBinding. The detection text describes 'assignment of high-privilege roles via ClusterRoleBinding objects.' This is more specific than T1078.003 for the cluster-admin binding scenario: T1078.003 covers abusing an account that already has access, while T1098.006 covers the act of granting elevated roles -- which is exactly what 'cluster-admin binding' means.",
    "sources": [
      "https://attack.mitre.org/techniques/T1098/006/"
    ]
  },
  {
    "technique_id": "T1078.004",
    "name": "Cloud Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "relationship": "sibling_technique",
    "rationale": "In managed Kubernetes (AKS, GKE, EKS), cluster-admin bindings can be granted to cloud IAM identities (service principals, GCP service accounts, IAM roles). When the binding is to a cloud identity rather than a local/kubeconfig user, the operative technique is T1078.004 (Cloud Accounts), not T1078.003 (Local Accounts). Defenders should cover both variants of the valid-account family when auditing cluster-admin ClusterRoleBindings.",
    "sources": [
      "https://attack.mitre.org/techniques/T1078/004/",
      "https://attack.mitre.org/techniques/T1098/006/"
    ]
  }
]
```

### Notes / confidence
- T1098.006 more specific: **Confirmed** -- MITRE T1098.006 page explicitly covers ClusterRoleBinding-based privilege grant on the Containers platform.
- T1078.004 sibling: **Likely** -- Logical extension from T1078.003 to T1078.004 for cloud-identity bindings; MITRE does not name this combination explicitly but both technique pages reference Kubernetes account management.

---

## MS-TA9020 -- Access Cloud Resources

**Primary:** T1078.004 (Cloud Accounts)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1552.005",
    "name": "Cloud Instance Metadata API",
    "url": "https://attack.mitre.org/techniques/T1552/005/",
    "relationship": "upstream_precondition",
    "rationale": "A common path to accessing cloud resources from within a Kubernetes cluster is querying the Instance Metadata Service (169.254.169.254) to obtain a cloud identity token, then using that token (T1078.004) to access cloud APIs. T1552.005 captures the credential-acquisition step; T1078.004 captures the use of those credentials to access cloud resources. The Falco incubating rule 'Contact EC2 Instance Metadata Service From Container' (tagged T1552.005) fires on the precondition step.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/005/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"
    ]
  },
  {
    "technique_id": "T1530",
    "name": "Data from Cloud Storage",
    "url": "https://attack.mitre.org/techniques/T1530/",
    "relationship": "downstream_capability",
    "rationale": "MITRE T1530 page explicitly mentions T1059.009 (Cloud API) as the method for accessing cloud storage resources. Accessing cloud resources with compromised cloud credentials (T1078.004) commonly targets cloud storage buckets (S3, Azure Blob, GCS) -- T1530 captures this specific downstream action. MITRE T1530 also specifically mentions that 'credential compromise' is the primary enabling precondition.",
    "sources": [
      "https://attack.mitre.org/techniques/T1530/"
    ]
  }
]
```

### Notes / confidence
- T1552.005 precondition: **Confirmed** -- Falco rule tags T1552.005 for the metadata-service contact step; MITRE T1552.005 documents this as a credential-acquisition technique.
- T1530 downstream: **Confirmed** -- MITRE T1530 page explicitly names credential compromise as the enabling precondition and T1059.009 as the access method.

---

## MS-TA9021 -- Clear Container Logs

**Primary:** T1070 (Indicator Removal)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1070.003",
    "name": "Clear Command History",
    "url": "https://attack.mitre.org/techniques/T1070/003/",
    "relationship": "sibling_technique",
    "rationale": "Clearing container logs often accompanies clearing command history inside the container -- both are T1070 sub-techniques performed in the same defensive-evasion session. MITRE T1070 has no sub-technique for container logs specifically, but T1070.003 (Clear Command History) is the sibling most often paired with container log clearing in incident reports. Falco's 'Delete or rename shell history' rule (tagged T1070) fires on in-container history deletion, making this a compound-detection scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1070/003/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"
    ]
  },
  {
    "technique_id": "T1070.004",
    "name": "File Deletion",
    "url": "https://attack.mitre.org/techniques/T1070/004/",
    "relationship": "sibling_technique",
    "rationale": "Container log clearing (deleting /var/log/containers/* or truncating container stdout buffers) is mechanically a file deletion operation on the host. MITRE T1070.004 (File Deletion) is the sub-technique that most precisely captures the file-system-level action. Falco's 'Remove Bulk Data from Disk' rule is tagged T1485 (impact) but the overlapping file-deletion pattern also maps to T1070.004 when the intent is evidence removal.",
    "sources": [
      "https://attack.mitre.org/techniques/T1070/004/"
    ]
  }
]
```

### Notes / confidence
- T1070.003 sibling: **Likely** -- Falco rules confirm T1070 family coverage for in-container history deletion, but no single authoritative source names the T1070.003/log-clear pairing specifically for containers.
- T1070.004 sibling: **Likely** -- The file-deletion mechanism is confirmed by MITRE; the specific application to container log files is a logical extension not named by MITRE explicitly.

---

## MS-TA9022 -- Delete Kubernetes Events

**Primary:** T1070 (Indicator Removal)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1070.009",
    "name": "Clear Persistence",
    "url": "https://attack.mitre.org/techniques/T1070/009/",
    "relationship": "sibling_technique",
    "rationale": "Deleting Kubernetes events (T1070) is sometimes paired with clearing related persistent artifacts (CronJob entries, RoleBindings, audit webhook configurations). T1070.009 (Clear Persistence) covers removing previously established persistence mechanisms to hinder forensics. In post-incident Kubernetes forensics, adversaries are documented deleting both events and the RBAC/CronJob objects that generated them as a compound clean-up operation.",
    "sources": [
      "https://attack.mitre.org/techniques/T1070/009/"
    ]
  }
]
```

### Notes / confidence
- T1070.009 sibling: **Possible** -- MITRE T1070.009 covers persistence-clearing as forensic-evasion; the pairing with Kubernetes event deletion is a logical extension but no single Sigma/Falco rule explicitly chains T1070 and T1070.009 for K8s events.

---

## MS-TA9023 -- Pod or Container Name Similarity

**Primary:** T1036.005 (Match Legitimate Resource Name or Location)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "upstream_precondition",
    "rationale": "Name masquerading (T1036.005) occurs at the moment a container or pod is deployed with a deceptive name (T1610). The Sigma rule 'kubernetes_audit_pod_in_system_namespace' is tagged T1036.005 and fires on pod creation events in kube-system -- a pod-creation (T1610) event that carries a legitimate-looking name in a sensitive namespace. The masquerade technique cannot exist without the deploy event.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.yml",
      "https://attack.mitre.org/techniques/T1610/"
    ]
  }
]
```

### Notes / confidence
- T1610 upstream: **Confirmed** -- Sigma rule kubernetes_audit_pod_in_system_namespace fires on pod creation (T1610 event) and tags T1036.005, confirming the deploy-precedes-masquerade chain.

---

## MS-TA9024 -- Connect From Proxy Server

**Primary:** T1090 (Proxy)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1090.003",
    "name": "Multi-hop Proxy",
    "url": "https://attack.mitre.org/techniques/T1090/003/",
    "relationship": "more_specific_subtechnique",
    "rationale": "Connecting to the Kubernetes API server or kubelet from a Tor exit node or multi-layer proxy -- as described in the Microsoft K8s Threat Matrix -- maps to T1090.003 (Multi-hop Proxy). T1090 (parent) is the current primary; T1090.003 is more specific for the anonymization use case where the adversary chains multiple proxies to obscure their origin IP from API server audit logs.",
    "sources": [
      "https://attack.mitre.org/techniques/T1090/003/"
    ]
  },
  {
    "technique_id": "T1090.002",
    "name": "External Proxy",
    "url": "https://attack.mitre.org/techniques/T1090/002/",
    "relationship": "more_specific_subtechnique",
    "rationale": "When the adversary uses a single external proxy (VPS, cloud instance) as a relay to access the Kubernetes API, T1090.002 (External Proxy) is the more specific sub-technique. This is the simpler variant where a compromised cloud host or rented VPS is used as a single hop to obscure the attacker's real IP from K8s API audit logs.",
    "sources": [
      "https://attack.mitre.org/techniques/T1090/002/"
    ]
  }
]
```

### Notes / confidence
- T1090.003 more specific: **Likely** -- MITRE T1090 sub-techniques are well-documented; the multi-hop scenario described in Microsoft's matrix aligns with T1090.003, but the Microsoft page does not explicitly name the sub-technique ID.
- T1090.002 more specific: **Likely** -- Same basis; the single-external-proxy variant is well covered by T1090.002.

---

## MS-TA9025 -- List Kubernetes Secrets

**Primary:** T1552.007 (Container API)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078.003",
    "name": "Local Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/003/",
    "relationship": "upstream_precondition",
    "rationale": "Listing Kubernetes secrets via the API (T1552.007) requires an authenticated identity with list/get permission on the secrets resource. The Sigma rule 'kubernetes_audit_secrets_enumeration' fires on verb=list, objectRef.resource=secrets; but the act of listing secrets is only possible with a valid Kubernetes identity (T1078.003 or T1078.004). Correlating the secret-list event with the authentication event that preceded it is required for full kill-chain attribution.",
    "sources": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml",
      "https://attack.mitre.org/techniques/T1078/003/"
    ]
  }
]
```

### Notes / confidence
- T1078.003 precondition: **Likely** -- The authentication precondition is structural and confirmed by the Sigma rule's detection logic, but MITRE does not link T1552.007 and T1078.003 explicitly on either technique page.

---

## MS-TA9026 -- Mount Service Principal

**Primary:** T1552.001 (Credentials In Files)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078.004",
    "name": "Cloud Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "relationship": "downstream_capability",
    "rationale": "Mounting an Azure service principal credential file into a pod (T1552.001) gives the adversary the credentials they need to authenticate as that service principal to the Azure management plane. The next step is using those credentials (T1078.004 Cloud Accounts) to access AKS, Azure Key Vault, or Azure Storage. MITRE T1552.001 page confirms this: 'authenticated user and service account credentials are often stored in local configuration and credential files' and Hildegard malware is cited for searching these files in K8s environments.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/",
      "https://attack.mitre.org/techniques/T1078/004/"
    ]
  }
]
```

### Notes / confidence
- T1078.004 downstream: **Confirmed** -- MITRE T1552.001 page names the credential-to-use chain; T1078.004 page documents cloud account credential abuse as the operative technique.

---

## MS-TA9027 -- Application Credentials in Configuration Files

**Primary:** T1552 (Unsecured Credentials)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1552.001",
    "name": "Credentials In Files",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "relationship": "more_specific_subtechnique",
    "rationale": "T1552 is the parent; T1552.001 (Credentials In Files) is the precise sub-technique covering credentials embedded in application configuration files (environment variables, ConfigMaps, Kubernetes Secrets mounted as files). MITRE T1552.001 explicitly covers container/orchestration credential paths and cites Hildegard malware as a real-world example. The parent mapping (T1552) should be refined to T1552.001 for this scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/"
    ]
  }
]
```

### Notes / confidence
- T1552.001 more specific: **Confirmed** -- MITRE T1552.001 explicitly covers file-based credentials in container environments with real procedure examples.

---

## MS-TA9028 -- Access Managed Identity Credentials

**Primary:** T1552.005 (Cloud Instance Metadata API)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078.004",
    "name": "Cloud Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "relationship": "downstream_capability",
    "rationale": "Querying the Instance Metadata Service to obtain a managed identity token (T1552.005) is the credential-acquisition step; using that token to authenticate as a cloud service principal and access Azure/AWS/GCP resources is T1078.004 (Cloud Accounts). These two techniques describe successive steps in the same attack: credential theft from IMDS followed by cloud API access.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/005/",
      "https://attack.mitre.org/techniques/T1078/004/"
    ]
  }
]
```

### Notes / confidence
- T1078.004 downstream: **Confirmed** -- Both MITRE technique pages confirm the credential-obtain-then-use chain for cloud managed identities.

---

## MS-TA9029 -- Access the Kubernetes API Server

**Primary:** T1613 (Container and Resource Discovery)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1046",
    "name": "Network Service Discovery",
    "url": "https://attack.mitre.org/techniques/T1046/",
    "relationship": "upstream_precondition",
    "rationale": "Before querying the Kubernetes API server an adversary must locate it. Atomic Red Team T1046 test 9 ('Network Service Discovery for Containers') explicitly covers scanning for Kubernetes API and kubelet ports in a container network. MITRE T1210 (Exploitation of Remote Services) also notes that 'Network Service Discovery' (T1046) precedes exploitation; the same precondition applies to API server access.",
    "sources": [
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md",
      "https://attack.mitre.org/techniques/T1046/"
    ]
  },
  {
    "technique_id": "T1552.007",
    "name": "Container API",
    "url": "https://attack.mitre.org/techniques/T1552/007/",
    "relationship": "downstream_capability",
    "rationale": "Accessing the Kubernetes API server (T1613 discovery) enables credential harvesting via the API (T1552.007). MITRE T1552.007 specifically covers 'querying the Kubernetes API for secrets' -- this is a direct downstream use of API server access. The Sigma rule 'kubernetes_audit_secrets_enumeration' (tagged T1552.007) fires on the follow-on action that T1613/API-server access makes possible.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/007/",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml"
    ]
  }
]
```

### Notes / confidence
- T1046 precondition: **Confirmed** -- Atomic Red Team T1046 test 9 is explicitly titled "Network Service Discovery for Containers."
- T1552.007 downstream: **Confirmed** -- MITRE T1552.007 names Peirates tool as querying the K8s API for secrets; Sigma rule confirms the detection chain.

---

## MS-TA9030 -- Access Kubelet API

**Primary:** T1613 (Container and Resource Discovery)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1046",
    "name": "Network Service Discovery",
    "url": "https://attack.mitre.org/techniques/T1046/",
    "relationship": "upstream_precondition",
    "rationale": "The Hildegard malware campaign used masscan to discover kubelet API ports across the cluster network before accessing them -- this is precisely the T1046 precondition step. MITRE T1613 procedure text cites Hildegard for this pattern. Atomic Red Team T1046 test 9 covers container network service discovery.",
    "sources": [
      "https://attack.mitre.org/techniques/T1613/",
      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md"
    ]
  },
  {
    "technique_id": "T1609",
    "name": "Container Administration Command",
    "url": "https://attack.mitre.org/techniques/T1609/",
    "relationship": "downstream_capability",
    "rationale": "The kubelet API (port 10250) exposes an /exec endpoint that allows running commands inside pods without going through the API server. Accessing kubelet API (T1613) for discovery directly enables remote exec into containers (T1609). Peirates and other K8s attack tools enumerate the kubelet API specifically to discover and then exec into running containers.",
    "sources": [
      "https://attack.mitre.org/techniques/T1609/",
      "https://attack.mitre.org/techniques/T1613/"
    ]
  }
]
```

### Notes / confidence
- T1046 precondition: **Confirmed** -- MITRE T1613 procedure text names Hildegard using masscan; T1046 Atomic test 9 covers container-network port scanning.
- T1609 downstream: **Confirmed** -- MITRE T1609 and T1613 both reference Peirates as using kubelet API for exec; the /exec endpoint relationship is documented in Kubernetes API specifications.

---

## MS-TA9031 -- Network Mapping

**Primary:** T1046 (Network Service Discovery)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1613",
    "name": "Container and Resource Discovery",
    "url": "https://attack.mitre.org/techniques/T1613/",
    "relationship": "sibling_technique",
    "rationale": "Network mapping inside a Kubernetes cluster (T1046) is commonly performed alongside container/resource enumeration via the API (T1613). Hildegard malware performed both: masscan for network port discovery (T1046) and Kubernetes API enumeration (T1613) in the same attack chain. The Falco incubating rule 'Network Connection outside Local Subnet' is tagged T1046 and fires on outbound network connections from containers -- defenders need both T1046 (port scan) and T1613 (API query) coverage.",
    "sources": [
      "https://attack.mitre.org/techniques/T1613/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"
    ]
  },
  {
    "technique_id": "T1210",
    "name": "Exploitation of Remote Services",
    "url": "https://attack.mitre.org/techniques/T1210/",
    "relationship": "downstream_capability",
    "rationale": "MITRE T1210 explicitly states: 'adversaries use Network Service Discovery (T1046) to identify vulnerable systems before exploitation.' In a Kubernetes environment, network mapping (T1046) identifies services in adjacent pods and nodes that can then be exploited for lateral movement (T1210). This T1046 -> T1210 chain is stated directly on the T1210 MITRE page.",
    "sources": [
      "https://attack.mitre.org/techniques/T1210/"
    ]
  }
]
```

### Notes / confidence
- T1613 sibling: **Confirmed** -- MITRE T1613 procedure text names Hildegard for both masscan (T1046) and Kubernetes API enumeration (T1613).
- T1210 downstream: **Confirmed** -- MITRE T1210 page explicitly names T1046 as the precondition for remote service exploitation.

---

## MS-TA9033 -- Instance Metadata API

**Primary:** T1552.005 (Cloud Instance Metadata API)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1078.004",
    "name": "Cloud Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
    "relationship": "downstream_capability",
    "rationale": "Identical chain to MS-TA9028: querying the Instance Metadata API at 169.254.169.254 (T1552.005) yields credentials used to authenticate as a cloud IAM identity (T1078.004). The Falco incubating rule 'Contact EC2 Instance Metadata Service From Container' tags T1552.005 and fires on the outbound connection that precedes the cloud-credential-use step.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/005/",
      "https://attack.mitre.org/techniques/T1078/004/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"
    ]
  }
]
```

### Notes / confidence
- T1078.004 downstream: **Confirmed** -- Same source evidence as MS-TA9028; Falco rule confirms the detection point.

---

## MS-TA9034 -- Cluster Internal Networking

**Primary:** T1210 (Exploitation of Remote Services)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1046",
    "name": "Network Service Discovery",
    "url": "https://attack.mitre.org/techniques/T1046/",
    "relationship": "upstream_precondition",
    "rationale": "Exploiting cluster-internal services (T1210) requires first discovering them via network mapping (T1046). MITRE T1210 page explicitly states T1046 as the precondition: 'adversaries use Network Service Discovery to identify vulnerable systems before exploitation.' In Kubernetes, the flat pod network makes internal service discovery (T1046 / T1613) the mandatory first step before lateral exploitation.",
    "sources": [
      "https://attack.mitre.org/techniques/T1210/"
    ]
  },
  {
    "technique_id": "T1021",
    "name": "Remote Services",
    "url": "https://attack.mitre.org/techniques/T1021/",
    "relationship": "sibling_technique",
    "rationale": "Lateral movement across the cluster internal network may use legitimate remote service protocols (SSH, HTTP APIs) rather than exploiting vulnerabilities. T1021 (Remote Services) covers this complementary path. Cluster-internal networking enables both unauthenticated exploitation (T1210) and authenticated service abuse (T1021); defenders monitoring lateral movement need coverage of both.",
    "sources": [
      "https://attack.mitre.org/techniques/T1021/"
    ]
  }
]
```

### Notes / confidence
- T1046 precondition: **Confirmed** -- MITRE T1210 page explicitly names T1046 as the precondition.
- T1021 sibling: **Likely** -- The complementary lateral-movement path is well understood from Kubernetes threat models, but MITRE T1210 does not explicitly cross-link T1021.

---

## MS-TA9035 -- CoreDNS Poisoning

**Primary:** T1557 (Adversary-in-the-Middle)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1040",
    "name": "Network Sniffing",
    "url": "https://attack.mitre.org/techniques/T1040/",
    "relationship": "downstream_capability",
    "rationale": "MITRE T1040 page states: 'Adversaries may likely also utilize network sniffing during Adversary-in-the-Middle (AitM) to passively gain additional knowledge about the environment.' CoreDNS poisoning (T1557) intercepts DNS queries; the attacker can then sniff the traffic redirected through their host (T1040) to capture plaintext credentials or session tokens from mis-redirected pod communications.",
    "sources": [
      "https://attack.mitre.org/techniques/T1040/"
    ]
  },
  {
    "technique_id": "T1565.002",
    "name": "Transmitted Data Manipulation",
    "url": "https://attack.mitre.org/techniques/T1565/002/",
    "relationship": "downstream_capability",
    "rationale": "CoreDNS poisoning redirects DNS resolution to attacker-controlled services, enabling manipulation of transmitted data -- not just passive interception. T1565.002 (Transmitted Data Manipulation) covers modifying data in transit. After poisoning DNS, an adversary can serve malicious content or manipulate API responses, which maps to T1565.002 as the integrity-impact phase of the attack.",
    "sources": [
      "https://attack.mitre.org/techniques/T1565/002/"
    ]
  }
]
```

### Notes / confidence
- T1040 downstream: **Confirmed** -- MITRE T1040 page explicitly mentions AitM as the context for network sniffing use.
- T1565.002 downstream: **Likely** -- MITRE T1565.002 covers transmitted data manipulation; the DNS-redirect-to-manipulate pattern is a logical extension but not named by MITRE explicitly for CoreDNS.

---

## MS-TA9036 -- ARP Poisoning and IP Spoofing

**Primary:** T1557 (Adversary-in-the-Middle)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1557.002",
    "name": "ARP Cache Poisoning",
    "url": "https://attack.mitre.org/techniques/T1557/002/",
    "relationship": "more_specific_subtechnique",
    "rationale": "T1557.002 is the sub-technique specifically covering ARP cache poisoning. The Falco stable rule 'Packet socket created in container' is tagged T1557.002 (not the parent T1557) because creating a raw packet socket is the technical primitive used for ARP poisoning in container networks. The primary mapping is T1557 (parent); T1557.002 is the more specific and correct mapping.",
    "sources": [
      "https://attack.mitre.org/techniques/T1557/002/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"
    ]
  },
  {
    "technique_id": "T1040",
    "name": "Network Sniffing",
    "url": "https://attack.mitre.org/techniques/T1040/",
    "relationship": "downstream_capability",
    "rationale": "Same as MS-TA9035: MITRE T1040 explicitly names AitM as the context for network sniffing. After ARP poisoning, the adversary positions themselves to sniff plaintext traffic between pods (T1040). The Falco 'Packet socket created in container' rule firing on T1557.002 and the T1040 sniffing activity are sequential steps in the same attack.",
    "sources": [
      "https://attack.mitre.org/techniques/T1040/"
    ]
  }
]
```

### Notes / confidence
- T1557.002 more specific: **Confirmed** -- Falco stable rule explicitly tags T1557.002 for packet socket creation; MITRE T1557.002 directly covers ARP cache poisoning.
- T1040 downstream: **Confirmed** -- MITRE T1040 page explicitly states AitM use case for network sniffing.

---

## MS-TA9037 -- Images From a Private Registry

**Primary:** T1530 (Data from Cloud Storage)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1552.001",
    "name": "Credentials In Files",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "relationship": "upstream_precondition",
    "rationale": "Accessing a private container registry (T1530) requires registry credentials. These credentials are stored in Kubernetes imagePullSecrets or in ~/.docker/config.json files. MITRE T1552.001 covers credential files; its detection text explicitly calls out 'Container processes accessing mounted secrets or configuration paths' and Hildegard malware searching for Docker credentials. The imagePullSecret / docker config credential read is the T1552.001 precondition that enables T1530 registry access.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/"
    ]
  },
  {
    "technique_id": "T1525",
    "name": "Implant Internal Image",
    "url": "https://attack.mitre.org/techniques/T1525/",
    "relationship": "downstream_capability",
    "rationale": "After gaining access to a private registry (T1530), an adversary can push a malicious image to it (T1525). MITRE T1525 describes implanting images in registries; the registry credential access (T1530 / T1552.001) is what makes the push possible. Detection of T1530 should trigger investigation for subsequent T1525 image push events.",
    "sources": [
      "https://attack.mitre.org/techniques/T1525/"
    ]
  }
]
```

### Notes / confidence
- T1552.001 precondition: **Confirmed** -- MITRE T1552.001 explicitly names Docker credential files in container environments.
- T1525 downstream: **Likely** -- The registry-access-to-image-push chain is well established in K8s security literature; MITRE T1525 describes registry implantation but does not explicitly link T1530 as a precondition on that page.

---

## MS-TA9038 -- Data Destruction

**Primary:** T1485 (Data Destruction)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1485.001",
    "name": "Lifecycle-Triggered Deletion",
    "url": "https://attack.mitre.org/techniques/T1485/001/",
    "relationship": "more_specific_subtechnique",
    "rationale": "T1485.001 (Lifecycle-Triggered Deletion) covers configuring cloud object lifecycle policies to auto-delete data. In Kubernetes environments with cloud-backed persistent volumes (EBS, Azure Disk, GCS), an adversary with cloud credentials (T1078.004) can configure lifecycle rules that cause data deletion -- a subtler destruction path than directly deleting files. T1485.001 is the more specific sub-technique for this Kubernetes-plus-cloud storage scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1485/001/"
    ]
  }
]
```

### Notes / confidence
- T1485.001 more specific: **Likely** -- MITRE introduced T1485.001 specifically for cloud lifecycle-triggered deletion; it applies to cloud-backed K8s storage but MITRE does not name Kubernetes explicitly on the T1485.001 page.

---

## MS-TA9039 -- Resource Hijacking

**Primary:** T1496 (Resource Hijacking)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1496.001",
    "name": "Compute Hijacking",
    "url": "https://attack.mitre.org/techniques/T1496/001/",
    "relationship": "more_specific_subtechnique",
    "rationale": "T1496.001 (Compute Hijacking) is the sub-technique specifically covering cryptomining and CPU/GPU resource hijacking in container and cloud environments. MITRE T1496.001 explicitly states: 'Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers.' TeamTNT deploying XMRig Docker images is cited as a procedure example. The parent T1496 is the current primary; T1496.001 is more specific and correct for K8s cryptomining.",
    "sources": [
      "https://attack.mitre.org/techniques/T1496/001/"
    ]
  },
  {
    "technique_id": "T1610",
    "name": "Deploy Container",
    "url": "https://attack.mitre.org/techniques/T1610/",
    "relationship": "upstream_precondition",
    "rationale": "Resource hijacking in Kubernetes is most commonly implemented by deploying malicious mining containers (T1610) -- TeamTNT's attack chain deploys XMRig containers to mine Monero. The deploy event (T1610) is the precondition that operationalizes the resource hijacking (T1496.001). Atomic Red Team T1610 cites Kinsing, which uses exactly this pattern.",
    "sources": [
      "https://attack.mitre.org/techniques/T1610/",
      "https://attack.mitre.org/techniques/T1496/001/"
    ]
  }
]
```

### Notes / confidence
- T1496.001 more specific: **Confirmed** -- MITRE T1496.001 explicitly names container environments and TeamTNT as procedure examples.
- T1610 upstream: **Confirmed** -- MITRE T1610 and T1496.001 both cite TeamTNT container deployment for cryptomining.

---

## MS-TA9040 -- Denial of Service

**Primary:** T1498 (Network Denial of Service)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1499",
    "name": "Endpoint Denial of Service",
    "url": "https://attack.mitre.org/techniques/T1499/",
    "relationship": "sibling_technique",
    "rationale": "MITRE explicitly distinguishes T1498 (network bandwidth saturation) from T1499 (endpoint/service exhaustion). In Kubernetes, a DoS attack may target the API server's request handling capacity (T1499.003 Application Exhaustion Flood) or exhaust pod/node resources by creating crashlooping workloads (T1499.001 OS Exhaustion Flood). MITRE T1498 page cross-references T1499 directly: 'For DoS attacks targeting the hosting system directly, see Endpoint Denial of Service (T1499).' Both are needed for complete K8s DoS coverage.",
    "sources": [
      "https://attack.mitre.org/techniques/T1498/",
      "https://attack.mitre.org/techniques/T1499/"
    ]
  },
  {
    "technique_id": "T1499.003",
    "name": "Application Exhaustion Flood",
    "url": "https://attack.mitre.org/techniques/T1499/003/",
    "relationship": "sibling_technique",
    "rationale": "T1499.003 (Application Exhaustion Flood) covers exhausting application-layer resources -- in Kubernetes this maps to flooding the API server with requests to exhaust its rate-limit capacity, or generating excessive pod scheduling events. MITRE T1499 detection analytics reference 'crashlooping pods' in container orchestrator logs as a K8s-specific indicator. This sub-technique is more specific than the parent T1499 for the K8s API starvation scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1499/003/",
      "https://attack.mitre.org/techniques/T1499/"
    ]
  }
]
```

### Notes / confidence
- T1499 sibling: **Confirmed** -- MITRE T1498 page explicitly cross-references T1499 as the complementary technique for endpoint-targeted DoS.
- T1499.003 more specific: **Likely** -- MITRE T1499 page mentions container orchestrator logs and crashlooping pods in detection analytics, indicating K8s-specific applicability; the sub-technique name fits the API-exhaustion scenario but MITRE does not name K8s API starvation explicitly on the T1499.003 page.

---

## MS-TA9041 -- Collecting Data from Pod

**Primary:** null (no MITRE mapping assigned)

### Cross-references (recommended additions)

```json
[
  {
    "technique_id": "T1005",
    "name": "Data from Local System",
    "url": "https://attack.mitre.org/techniques/T1005/",
    "relationship": "more_specific_subtechnique",
    "rationale": "Collecting data from a running pod is a local-system data-collection operation from the adversary's perspective: files, environment variables, in-memory data, and mounted secrets inside the pod are analogous to files on a compromised host. The Falco incubating rule 'Read ssh information' is tagged T1005 and fires on reads of SSH key files from containers -- demonstrating that in-container data collection is already categorized as T1005 in community rules. This is the most precise MITRE mapping for the pod-data-collection scenario.",
    "sources": [
      "https://attack.mitre.org/techniques/T1005/",
      "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"
    ]
  },
  {
    "technique_id": "T1552",
    "name": "Unsecured Credentials",
    "url": "https://attack.mitre.org/techniques/T1552/",
    "relationship": "sibling_technique",
    "rationale": "A primary motivation for collecting data from a pod is harvesting credentials: environment variables containing API keys, mounted service account tokens, secrets projected as files. T1552 (Unsecured Credentials) and its sub-techniques T1552.001 (Credentials In Files) and T1552.007 (Container API) capture the credential-focused subset of pod data collection. Defenders must cover both T1005 (generic data collection) and T1552 (credential-specific collection) to fully model this technique.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/"
    ]
  }
]
```

### Notes / confidence
- T1005 mapping: **Confirmed** -- Falco incubating rule explicitly tags T1005 for in-container file reads; MITRE T1005 covers local-system data collection broadly.
- T1552 sibling: **Likely** -- The credential-collection motivation is well established; MITRE T1552.001 names container credential paths; no single source explicitly chains T1005 and T1552 for the pod-data-collection scenario but both are independently confirmed.

---

## Summary Table

| MS-TA | Primary MITRE | Count | Highest-Confidence Cross-ref | Relationship |
|-------|--------------|-------|------------------------------|--------------|
| MS-TA9001 | T1078.004 | 2 | T1528 | downstream_capability |
| MS-TA9002 | T1525 | 2 | T1610 | downstream_capability |
| MS-TA9003 | null | 2 | T1552.001 | more_specific_subtechnique |
| MS-TA9004 | T1190 | 2 | T1611 | downstream_capability |
| MS-TA9005 | T1133 | 2 | T1078 | upstream_precondition |
| MS-TA9006 | T1609 | 2 | T1611 | downstream_capability |
| MS-TA9007 | T1059 | 2 | T1059.004 | more_specific_subtechnique |
| MS-TA9008 | T1610 | 2 | T1611 | downstream_capability |
| MS-TA9009 | T1190 | 2 | T1068 | downstream_capability |
| MS-TA9010 | null | 2 | T1021.004 | more_specific_subtechnique |
| MS-TA9011 | T1610 | 1 | T1552 | downstream_capability |
| MS-TA9012 | T1543 | 1 | T1610 | upstream_precondition |
| MS-TA9013 | T1611 | 2 | T1610 | upstream_precondition |
| MS-TA9014 | T1053.007 | 2 | T1053.003 | sibling_technique |
| MS-TA9015 | T1546 | 2 | T1078 | upstream_precondition |
| MS-TA9016 | T1528 | 3 | T1550.001 | downstream_capability |
| MS-TA9017 | null | 2 | T1543.005 | more_specific_subtechnique |
| MS-TA9018 | T1610 | 1 | T1068 | downstream_capability |
| MS-TA9019 | T1078.003 | 2 | T1098.006 | more_specific_subtechnique |
| MS-TA9020 | T1078.004 | 2 | T1552.005 | upstream_precondition |
| MS-TA9021 | T1070 | 2 | T1070.003 | sibling_technique |
| MS-TA9022 | T1070 | 1 | T1070.009 | sibling_technique |
| MS-TA9023 | T1036.005 | 1 | T1610 | upstream_precondition |
| MS-TA9024 | T1090 | 2 | T1090.003 | more_specific_subtechnique |
| MS-TA9025 | T1552.007 | 1 | T1078.003 | upstream_precondition |
| MS-TA9026 | T1552.001 | 1 | T1078.004 | downstream_capability |
| MS-TA9027 | T1552 | 1 | T1552.001 | more_specific_subtechnique |
| MS-TA9028 | T1552.005 | 1 | T1078.004 | downstream_capability |
| MS-TA9029 | T1613 | 2 | T1552.007 | downstream_capability |
| MS-TA9030 | T1613 | 2 | T1609 | downstream_capability |
| MS-TA9031 | T1046 | 2 | T1210 | downstream_capability |
| MS-TA9033 | T1552.005 | 1 | T1078.004 | downstream_capability |
| MS-TA9034 | T1210 | 2 | T1046 | upstream_precondition |
| MS-TA9035 | T1557 | 2 | T1040 | downstream_capability |
| MS-TA9036 | T1557 | 2 | T1557.002 | more_specific_subtechnique |
| MS-TA9037 | T1530 | 2 | T1552.001 | upstream_precondition |
| MS-TA9038 | T1485 | 1 | T1485.001 | more_specific_subtechnique |
| MS-TA9039 | T1496 | 2 | T1496.001 | more_specific_subtechnique |
| MS-TA9040 | T1498 | 2 | T1499 | sibling_technique |
| MS-TA9041 | null | 2 | T1005 | more_specific_subtechnique |

**Total records with recommended cross-references:** 40 of 40  
**Total recommended cross-reference entries:** 67  
**Records with pre-existing (already-populated) cross-references reviewed for additions:** 4 (MS-TA9007, MS-TA9011, MS-TA9012, MS-TA9018)

---

## Research Process

### Searches Performed
- No WebSearch queries used; all research performed via direct WebFetch of MITRE ATT&CK pages and GitHub API calls to SigmaHQ/sigma and falcosecurity/rules repositories.

### Pages Fetched
- [Official] https://attack.mitre.org/techniques/T1078/004/ (read)
- [Official] https://attack.mitre.org/techniques/T1525/ (read)
- [Official] https://attack.mitre.org/techniques/T1190/ (read)
- [Official] https://attack.mitre.org/techniques/T1133/ (read)
- [Official] https://attack.mitre.org/techniques/T1609/ (read)
- [Official] https://attack.mitre.org/techniques/T1610/ (read)
- [Official] https://attack.mitre.org/techniques/T1611/ (read)
- [Official] https://attack.mitre.org/techniques/T1543/ (read)
- [Official] https://attack.mitre.org/techniques/T1053/007/ (read)
- [Official] https://attack.mitre.org/techniques/T1546/ (read)
- [Official] https://attack.mitre.org/techniques/T1528/ (read)
- [Official] https://attack.mitre.org/techniques/T1070/ (read)
- [Official] https://attack.mitre.org/techniques/T1036/005/ (read)
- [Official] https://attack.mitre.org/techniques/T1552/007/ (read)
- [Official] https://attack.mitre.org/techniques/T1613/ (read)
- [Official] https://attack.mitre.org/techniques/T1046/ (read)
- [Official] https://attack.mitre.org/techniques/T1210/ (read)
- [Official] https://attack.mitre.org/techniques/T1557/ (read)
- [Official] https://attack.mitre.org/techniques/T1530/ (read)
- [Official] https://attack.mitre.org/techniques/T1485/ (read)
- [Official] https://attack.mitre.org/techniques/T1496/ (read)
- [Official] https://attack.mitre.org/techniques/T1496/001/ (read)
- [Official] https://attack.mitre.org/techniques/T1498/ (read)
- [Official] https://attack.mitre.org/techniques/T1499/ (read)
- [Official] https://attack.mitre.org/techniques/T1552/001/ (read)
- [Official] https://attack.mitre.org/techniques/T1552/005/ (read)
- [Official] https://attack.mitre.org/techniques/T1090/ (read)
- [Official] https://attack.mitre.org/techniques/T1059/ (read)
- [Official] https://attack.mitre.org/techniques/T1059/004/ (read)
- [Official] https://attack.mitre.org/techniques/T1059/013/ (read)
- [Official] https://attack.mitre.org/techniques/T1068/ (read)
- [Official] https://attack.mitre.org/techniques/T1136/ (read)
- [Official] https://attack.mitre.org/techniques/T1565/ (read)
- [Official] https://attack.mitre.org/techniques/T1069/003/ (read)
- [Official] https://attack.mitre.org/techniques/T1087/004/ (read)
- [Official] https://attack.mitre.org/techniques/T1195/002/ (read)
- [Official] https://attack.mitre.org/techniques/T1550/001/ (read)
- [Official] https://attack.mitre.org/techniques/T1040/ (read)
- [Official] https://attack.mitre.org/techniques/T1489/ (read)
- [Official] https://attack.mitre.org/techniques/T1548/ (read)
- [Official] https://attack.mitre.org/techniques/T1098/ (read)
- [Official] https://attack.mitre.org/techniques/T1098/006/ (read)
- [Official] https://attack.mitre.org/techniques/T1021/004/ (read)
- [Official] https://attack.mitre.org/techniques/T1082/ (read)
- [Community] https://github.com/SigmaHQ/sigma -- kubernetes/audit rules (14 rules read via gh api)
- [Community] https://github.com/SigmaHQ/sigma -- cloud/azure/activity_logs kubernetes rules (7 rules read)
- [Community] https://github.com/SigmaHQ/sigma -- cloud/gcp/audit kubernetes rules (4 rules read)
- [Community] https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml (full file read)
- [Community] https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml (full file read)
- [Community] https://github.com/redcanaryco/atomic-red-team -- T1611, T1610, T1613, T1046 tests (read)

### Sources Evaluated but Rejected
- Falco sandbox rules (falco-sandbox_rules.yaml): contained no MITRE T-ID tags; rejected as uninformative for cross-reference identification.
- Azure kubernetes_audit_events_deleted Sigma rule tagged T1685: T1685 does not exist in MITRE ATT&CK (appears to be a tagging error in the rule); rejected as non-authoritative.
- Falco "Contact K8S API Server From Container" tagged T1565 (Data Manipulation): T1565 is a data-integrity technique, not a discovery technique; this appears to be an incorrect tag in the Falco ruleset. Not cited as a cross-reference because the tag is inconsistent with the technique's actual behavior (network connection from container to K8S API server is a discovery action, not data manipulation). The correct tag would be T1613.

### Gaps
- MS-TA9032 does not exist as a file in the data/techniques directory; the technique number is missing from the dataset. Not covered in this report.
- No peer-reviewed K8s threat-modeling papers were consulted directly; all academic-level sources were accessed via MITRE ATT&CK procedure citations and Atomic Red Team tests.
- T1059.013 (Container CLI/API) is listed by MITRE but its sub-technique page returned limited content; the relationship to MS-TA9006/9007 is confirmed at the parent T1059 level.
- T1082 (System Information Discovery) was evaluated as a possible cross-reference for MS-TA9029/9030 (API server discovery) but MITRE T1082 page has no container-specific content; rejected as too generic.

### Tools Used
- WebFetch: 44 pages
- Bash (gh api): 14 calls to SigmaHQ/sigma, falcosecurity/rules, and redcanaryco/atomic-red-team
- Read: 2 files (equilibrium.schema.json, MS-TA9001.json for structure validation)
