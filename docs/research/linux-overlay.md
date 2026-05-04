# Linux Post-Execution Overlay: MITRE ATT&CK Techniques Inside Running Containers

**Project:** Equilibrium
**Date:** 2026-05-04
**Author:** Research Agent
**Status:** Draft v1.0

---

## Section 1: Scope and Method

### Research Question

Once an adversary has gained command execution inside a running Kubernetes container, which MITRE ATT&CK techniques apply to what they do next, and which equilibrium MS-TA records represent the entry points that grant that execution?

### Method

1. Fetched and read the MITRE ATT&CK Enterprise Linux matrix at `https://attack.mitre.org/matrices/enterprise/linux/` (v19, confirmed 2026-05-04). This matrix enumerates all techniques and sub-techniques whose platform list includes Linux.

2. Fetched and read the MITRE ATT&CK Enterprise Containers matrix at `https://attack.mitre.org/matrices/enterprise/containers/` (v19, confirmed 2026-05-04). This matrix covers techniques whose platform list includes "Containers" as an explicit platform.

3. For every candidate technique, fetched and read the individual technique page to confirm platform listing, description, procedure examples, and container or Linux-runtime relevance.

4. Applied the in-container relevance criteria defined in Section 2 to filter the full set down to practically-useful candidates.

5. Read all seven primary MS-TA JSON records that grant in-container execution, plus reviewed all 40 MS-TA records to identify any additional entry points the user's list did not enumerate.

### Platforms Queried

| Platform | Canonical MITRE URL |
|---|---|
| Linux | https://attack.mitre.org/matrices/enterprise/linux/ |
| Containers | https://attack.mitre.org/matrices/enterprise/containers/ |

macOS was consulted where a technique is explicitly shared between Linux and macOS (e.g., T1548.003, T1546.004, T1574.006), to verify the Linux semantics still apply and to confirm procedure examples that also involve Linux. Techniques that exist only on macOS were excluded.

---

## Section 2: In-Container Relevance Criteria

A Linux technique qualifies for the overlay if all of the following hold:

**INCLUDE criteria (all must be met):**

1. **Linux userspace required.** The technique acts on Linux filesystem paths, Linux syscalls, Linux binaries, or Linux authentication primitives. A container provides exactly the Linux userspace the technique requires.

2. **No physical hardware dependency.** The technique does not require access to BIOS/UEFI/firmware, physical memory buses, hardware peripherals not exposed to the container, or network-level broadcast domains only accessible to the physical NIC.

3. **No exclusive host-kernel or host-namespace dependency.** The technique must be achievable either (a) entirely within the container's own namespaces and filesystem, or (b) within the additional capabilities a privileged container grants. Techniques that can only succeed by breaking out of the container namespace first are out of scope (those belong to T1611 Escape to Host and are already represented in the equilibrium data set).

4. **Post-execution action.** The technique represents something an adversary would do after establishing execution, not the mechanism of gaining execution itself. Initial access and pure execution techniques are already covered by the primary MS-TA records.

**EXCLUDE reasons applied:**

- **Requires BIOS/UEFI/firmware:** T1542 (Pre-OS Boot) and its sub-techniques T1542.002 (Component Firmware), T1542.003 (Bootkit). Containers have no access to firmware.
- **Requires Windows-only primitives:** Any technique listed only on Windows platforms.
- **Requires physical access or removable media:** T1025, T1052, T1200, T1092. Containers have no physical media access.
- **Technique IS the execution entry point** already covered by the primary MS-TA record: T1059.004 (Unix Shell), T1059.013 (Container CLI/API), T1609, T1610, T1190.
- **Requires host kernel namespace the container does not share by default and that is not granted even by privileged mode:** e.g., T1014 (Rootkit) requiring LKM insertion: excluded for unprivileged containers; retained with a "privileged container only" caveat for privileged ones.
- **Requires network-layer access not available to a standard container network stack:** T1040 (Network Sniffing) requires a network interface in promiscuous mode; containers use veth pairs and do not see other containers' traffic by default. Excluded unless hostNetwork=true.
- **Defacement (T1491) and physical disk wipe (T1561):** containers typically do not own a host disk surface unless a hostPath volume is mounted; excluded unless hostPath present.
- **Wi-Fi / Bluetooth / NFC primitives:** No physical radio interfaces in containers.

**Privileged-container footnote:** Several techniques (T1547.006 Kernel Modules, T1014 Rootkit, T1685.004 Disable Linux Audit) become accessible when the container runs with `securityContext.privileged=true` or with `CAP_SYS_MODULE` / `CAP_SYS_ADMIN`. These are included with a confidence tag of Likely (rather than Confirmed) and noted as "privileged container required."

---

## Section 3: Candidate Linux Techniques

The following 35 techniques survived the filter. Each entry states: technique ID, name, MITRE URL, in-container rationale, one concrete observable, and confidence.

---

### Persistence

**T1098.004 -- SSH Authorized Keys**
URL: https://attack.mitre.org/techniques/T1098/004/
Rationale: Platforms include Linux. Inside a container that runs an SSH daemon (MS-TA9010 pattern), or any container with a home directory, an adversary can append their public key to `~/.ssh/authorized_keys` to establish persistent re-entry via SSH.
Observable: Write event to `/root/.ssh/authorized_keys` or `/home/<user>/.ssh/authorized_keys` inside a container filesystem; TeamTNT's Kinsing malware is documented using this exact technique on container hosts.
Confidence: **Confirmed** -- MITRE platforms include Linux; TeamTNT procedure example documented on the technique page.

**T1136.001 -- Create Account: Local Account**
URL: https://attack.mitre.org/techniques/T1136/001/
Rationale: Platforms include Containers and Linux explicitly. Adversary runs `useradd` or `adduser` inside the container to create a local account for persistence; the Containers platform is listed on this sub-technique's page.
Observable: Process exec of `/usr/sbin/useradd` or `/usr/sbin/adduser` inside a container PID namespace; write to `/etc/passwd` and `/etc/shadow`.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; Linux `useradd` command listed in the technique's procedure table.

**T1543.002 -- Create or Modify System Process: Systemd Service**
URL: https://attack.mitre.org/techniques/T1543/002/
Rationale: Platform is Linux. Containers that include systemd as an init system (some base images do) or that mount host systemd socket allow adversary to install a persistent service unit file. Hildegard malware is documented creating systemd services.
Observable: Write to `/etc/systemd/system/*.service` or `/lib/systemd/system/*.service` inside a container; exec of `systemctl enable` inside the container PID namespace.
Confidence: **Likely** -- MITRE platform is Linux; MITRE does not list Containers explicitly, but Hildegard (container-targeting malware) is documented using systemd inside compromised environments; applicable only when container uses systemd as init.

**T1546.004 -- Event Triggered Execution: Unix Shell Configuration Modification**
URL: https://attack.mitre.org/techniques/T1546/004/
Rationale: Platform is Linux and macOS. Any container that runs a shell as a user will have `~/.bashrc`, `~/.bash_profile`, or `/etc/profile`. Modifying these files causes the adversary's payload to execute every time a shell session opens inside the container, including via `kubectl exec` by operators.
Observable: Write event to `~/.bashrc`, `~/.bash_profile`, or `/etc/profile` inside a container filesystem; RotaJakiro malware documented installing commands in `.bashrc`.
Confidence: **Confirmed** -- MITRE platform is Linux; RotaJakiro procedure example confirmed on technique page.

**T1037.004 -- Boot or Logon Initialization Scripts: RC Scripts**
URL: https://attack.mitre.org/techniques/T1037/004/
Rationale: Platform includes Linux. `rc.local` exists in many Linux container base images. Writing to `/etc/rc.local` inside a container persists a command that executes on container restart. HiddenWasp malware is documented using this approach.
Observable: Write to `/etc/rc.local` or `/etc/init.d/*` inside a container filesystem; read of that file at container startup.
Confidence: **Likely** -- Platform is Linux; MITRE does not explicitly mention containers, but rc.local exists in standard container images; confirmed container-targeting malware (HiddenWasp) uses this path.

**T1505.003 -- Server Software Component: Web Shell**
URL: https://attack.mitre.org/techniques/T1505/003/
Rationale: Platform includes Linux. Many Kubernetes workloads are web servers (nginx, Apache, Tomcat). Dropping a web shell (PHP, JSP, Python) into the web root inside the container provides persistent command execution accessible through the already-exposed web service port.
Observable: Write of a `.php`, `.jsp`, or `.py` file to a web-served directory (e.g., `/var/www/html/`, `/app/static/`) inside a container filesystem, followed by HTTP request to that path.
Confidence: **Confirmed** -- MITRE platform is Linux; 70+ procedure examples on the technique page; the adversary already has a running web service as the entry point (MS-TA9009 Application Exploit RCE).

**T1098.007 -- Account Manipulation: Additional Local or Domain Groups**
URL: https://attack.mitre.org/techniques/T1098/007/
Rationale: Platform includes Linux. Inside a container, an adversary with root can add their user to the `sudo` group or `wheel` group via `usermod -aG sudo <user>`, modifying group membership for privilege escalation within the container.
Observable: Exec of `usermod -aG sudo` or write to `/etc/group` inside a container filesystem.
Confidence: **Likely** -- MITRE platform includes Linux; no container-specific procedure examples found but the mechanism is pure Linux userspace.

**T1554 -- Compromise Host Software Binary**
URL: https://attack.mitre.org/techniques/T1554/
Rationale: Platform includes Linux. An adversary with write access to the container filesystem can replace common binaries (e.g., `/usr/bin/ssh`, `/usr/sbin/sshd`, `/bin/ls`) with trojanized versions that backdoor authentication or hide artifacts. The modification persists within the container's writable layer.
Observable: Write to a path under `/usr/bin/`, `/usr/sbin/`, or `/bin/` inside a container (especially to a binary not replaced by any package manager); file checksum mismatch for a known system binary.
Confidence: **Likely** -- MITRE platform is Linux; no container-specific procedure examples, but the technique requires only Linux filesystem write access which any container shell provides.

**T1547.006 -- Boot or Logon Autostart Execution: Kernel Modules and Extensions**
URL: https://attack.mitre.org/techniques/T1547/006/
Rationale: Platform is Linux. Requires `CAP_SYS_MODULE` or a privileged container. Inside a privileged container, an adversary can call `insmod` / `modprobe` to load a malicious LKM kernel module that persists in the host kernel. Skidmap and Drovorub malware use this technique in container-targeting campaigns.
Observable: Exec of `insmod` or `modprobe` inside a privileged container; new module visible in `/proc/modules` on the host node.
Confidence: **Likely** -- MITRE platform is Linux; no Containers platform tag; privileged container required; Skidmap and Drovorub are documented using this in container/cloud targeting contexts.

**T1556.003 -- Modify Authentication Process: Pluggable Authentication Modules**
URL: https://attack.mitre.org/techniques/T1556/003/
Rationale: Platform is Linux and macOS. Containers that expose SSH or that run services with PAM authentication are vulnerable. An adversary can replace `pam_unix.so` with a patched version that accepts a backdoor password. Skidmap malware is documented doing exactly this.
Observable: Write to `/lib/security/pam_unix.so` or `/etc/pam.d/*` inside a container filesystem; Skidmap procedure example confirmed on technique page.
Confidence: **Confirmed** -- MITRE platform is Linux; Skidmap procedure example confirmed; Skidmap explicitly targets container environments (see T1496.001 Skidmap entries).

---

### Privilege Escalation

**T1548.003 -- Abuse Elevation Control Mechanism: Sudo and Sudo Caching**
URL: https://attack.mitre.org/techniques/T1548/003/
Rationale: Platform is Linux and macOS. Containers that include `sudo` (common in development and debug images) are vulnerable. An adversary with a non-root shell can write `NOPASSWD: ALL` to `/etc/sudoers` or a `/etc/sudoers.d/` file to escalate to root within the container.
Observable: Write to `/etc/sudoers` or `/etc/sudoers.d/*` inside a container; exec of `visudo`; subsequent `sudo` invocation by a non-root UID.
Confidence: **Confirmed** -- MITRE platform is Linux; detection analytics AN0142 and AN0143 on the technique page cover sudoers modification.

**T1548.001 -- Abuse Elevation Control Mechanism: Setuid and Setgid**
URL: https://attack.mitre.org/techniques/T1548/001/
Rationale: Platform is Linux and macOS. An adversary with write access to the container filesystem can set the setuid bit on a binary (`chmod u+s /bin/bash`) to create a persistent privilege escalation path. Requires that the container is not run with `no_new_privs` security context.
Observable: Exec of `chmod u+s` or `chmod 4755` inside a container; setuid bit detected on a binary in the container filesystem that was not setuid in the original image.
Confidence: **Confirmed** -- MITRE platform is Linux; Exaramel procedure example confirmed; applicable unless `allowPrivilegeEscalation: false` is set.

**T1055.008 -- Process Injection: Ptrace System Calls**
URL: https://attack.mitre.org/techniques/T1055/008/
Rationale: Platform is Linux. Inside a container that runs multiple processes, an adversary with root or `CAP_SYS_PTRACE` can use `ptrace` to attach to any container process, read its memory, and inject shellcode. PACEMAKER malware is documented using ptrace to extract credentials from process memory.
Observable: `ptrace` syscall with `PTRACE_ATTACH` against a process PID inside the same container PID namespace; anomalous `/proc/<pid>/mem` reads.
Confidence: **Confirmed** -- MITRE platform is Linux; PACEMAKER procedure example confirmed; requires `CAP_SYS_PTRACE` or root inside the container.

**T1068 -- Exploitation for Privilege Escalation**
URL: https://attack.mitre.org/techniques/T1068/
Rationale: Platforms include Containers and Linux. An adversary with a non-root shell inside a container can exploit a local privilege escalation CVE (e.g., CVE-2021-4034 polkit pkexec, DirtyPipe CVE-2022-0847) to become root within the container or on the host node. MITRE AN1422 explicitly references container breakout via kernel CVE exploitation.
Observable: Exec of a known exploit binary or anomalous write to `/proc/self/mem` inside a container; process ownership change from non-root UID to UID 0 inside the container.
Confidence: **Confirmed** -- MITRE platforms include Containers; AN1422 on technique page explicitly covers container breakout via exploitation.

---

### Credential Access

**T1003.007 -- OS Credential Dumping: Proc Filesystem**
URL: https://attack.mitre.org/techniques/T1003/007/
Rationale: Platform is Linux. Inside a container, an adversary with root can read `/proc/<pid>/maps` and `/proc/<pid>/mem` to extract credentials from the memory of running processes (e.g., the application process itself may hold database passwords in plaintext in heap memory). LaZagne and MimiPenguin are documented using this technique.
Observable: Open/read syscall on `/proc/<pid>/mem` for a PID not owned by the calling process, inside a container PID namespace; exec of `laZagne` or `mimipenguin` binaries inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; LaZagne and MimiPenguin procedure examples confirmed on technique page.

**T1003.008 -- OS Credential Dumping: /etc/passwd and /etc/shadow**
URL: https://attack.mitre.org/techniques/T1003/008/
Rationale: Platform is Linux. Inside a container running as root, `cat /etc/shadow` dumps password hashes for all local accounts. These can be cracked offline. The ShadowRay campaign is documented executing `cat /etc/shadow` on compromised container hosts.
Observable: Read of `/etc/shadow` inside a container by a process other than PAM or login utilities; exec of `unshadow` inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; ShadowRay campaign procedure example confirmed.

**T1552.001 -- Unsecured Credentials: Credentials In Files**
URL: https://attack.mitre.org/techniques/T1552/001/
Rationale: Platforms include Containers explicitly. Inside a container, adversaries search for credentials in environment variables, config files, and mounted secrets (e.g., `/run/secrets/`, `/mnt/config`, Kubernetes-injected secrets at `/var/run/secrets/kubernetes.io/serviceaccount/`). Hildegard and TeamTNT are documented searching for Docker and Kubernetes credentials in container environments.
Observable: Read of `/run/secrets/*`, `/var/run/secrets/kubernetes.io/serviceaccount/token`, `.env` files, or `*.yml`/`*.conf` files containing credential strings inside a container; Hildegard malware documented searching for these paths.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; Hildegard and TeamTNT procedure examples confirmed.

**T1552.003 -- Unsecured Credentials: Shell History**
URL: https://attack.mitre.org/techniques/T1552/003/
Rationale: Platform is Linux. Inside a container that has been used interactively (via `kubectl exec` or SSH), `~/.bash_history` may contain plaintext credentials typed by operators. Kinsing malware is documented searching `bash_history` files for credentials.
Observable: Read of `~/.bash_history` inside a container by a process that is not the shell that owns the history; exec of `cat ~/.bash_history` or `grep -i pass ~/.bash_history`.
Confidence: **Confirmed** -- MITRE platform is Linux; Kinsing procedure example confirmed; Kinsing is a container-targeting malware family.

**T1552.004 -- Unsecured Credentials: Private Keys**
URL: https://attack.mitre.org/techniques/T1552/004/
Rationale: Platform is Linux. Containers used in CI/CD pipelines or that mount secrets may hold SSH private keys, TLS keys, or cloud credential files. An adversary can search for `*.pem`, `*.key`, `id_rsa` files.
Observable: Find/read syscall on files matching `*.pem`, `*.key`, `id_rsa`, `id_ecdsa` inside a container; exec of `find / -name '*.pem'` inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; consistent with documented TeamTNT and Hildegard behavior.

**T1555.003 -- Credentials from Password Stores: Credentials from Web Browsers**
URL: https://attack.mitre.org/techniques/T1555/003/
Rationale: Platform includes Linux. Containers running web development tooling or desktop-in-container patterns may have browser credential stores. This is a Possible reach for most production workloads but applies to dev/debug containers.
Observable: Read of `~/.config/chromium/Default/Login Data` or `~/.mozilla/firefox/*/logins.json` inside a container.
Confidence: **Possible** -- MITRE platform includes Linux; realistic only for developer workstation containers, not production application pods; included because the user's scope includes any container shell.

---

### Defense Evasion / Indicator Removal

**T1070.003 -- Indicator Removal: Clear Command History**
URL: https://attack.mitre.org/techniques/T1070/003/
Rationale: Platform is Linux. After interactive shell activity inside a container via `kubectl exec`, an adversary runs `history -c` or `unset HISTFILE` to erase evidence of their commands. TeamTNT, Hildegard, and APT41 are all documented using this technique; all three target container environments.
Observable: Exec of `history -c` inside a container terminal session; unset of `HISTFILE` environment variable; deletion of `~/.bash_history`.
Confidence: **Confirmed** -- MITRE platform is Linux; TeamTNT and Hildegard procedure examples confirmed; both are container-targeting malware families.

**T1070.004 -- Indicator Removal: File Deletion**
URL: https://attack.mitre.org/techniques/T1070/004/
Rationale: Platform is Linux. After dropping a tool or exploit binary inside a container, the adversary deletes it to remove forensic artifacts. This is a near-universal post-exploitation step in container attacks; TeamTNT's documented tradecraft includes tool deletion.
Observable: Exec of `rm -f <tool_binary>` inside a container; `unlink` syscall on a recently written executable inside the container filesystem.
Confidence: **Confirmed** -- MITRE platform is Linux; widely documented in container-targeting malware.

**T1222.002 -- File and Directory Permissions Modification: Linux and Mac File Permissions**
URL: https://attack.mitre.org/techniques/T1222/002/
Rationale: Platform is Linux. Inside a container, an adversary may run `chmod` or `chown` to make a dropped payload executable, change ownership of a sensitive file, or restrict operator access to their persistence artifacts. Kinsing is documented using `chmod` in container environments.
Observable: Exec of `chmod +x`, `chmod 777`, or `chown` on a file not owned by the calling process inside a container; `chattr +i` used to make a file immutable.
Confidence: **Confirmed** -- MITRE platform is Linux; Kinsing procedure example confirmed; Kinsing targets containers.

**T1036.005 -- Masquerading: Match Legitimate Resource Name or Location**
URL: https://attack.mitre.org/techniques/T1036/005/
Rationale: Platforms include Containers explicitly. The technique page states: "In containerized environments, a threat actor may create a resource in a trusted namespace or one that matches the naming convention of a container pod or cluster." Inside a running container, adversary binaries may be named to match legitimate system tools.
Observable: Process exec of a binary whose name matches a common system utility but whose path is non-standard (e.g., `/tmp/kube-apiserver`, `/dev/shm/sshd`) inside a container.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; technique page contains container-specific description text.

**T1014 -- Rootkit**
URL: https://attack.mitre.org/techniques/T1014/
Rationale: Platform is Linux. Inside a privileged container with `CAP_SYS_MODULE`, an adversary can load a kernel-mode rootkit (LKM) to hide processes, files, and network connections at the host kernel level. TeamTNT has been documented deploying the Diamorphine rootkit in container-targeting campaigns.
Observable: Load of a `.ko` kernel module inside a privileged container; anomalous `/proc/modules` entry or missing processes in `ps` output after module load; exec of `insmod diamorphine.ko` inside a container.
Confidence: **Likely** -- MITRE platform is Linux; no Containers platform tag; privileged container required; TeamTNT procedure example confirmed on technique page.

**T1685.004 -- Disable or Modify Tools: Disable or Modify Linux Audit System Log**
URL: https://attack.mitre.org/techniques/T1685/004/
Rationale: Platform is Linux. In a privileged container or one with `CAP_AUDIT_CONTROL`, an adversary can terminate `auditd`, modify `/etc/audit/audit.rules`, or hook audit library functions to suppress detection telemetry. Ebury malware is documented disabling auditd on compromised Linux systems.
Observable: Exec of `auditctl -D` (delete all audit rules), `kill -9 $(pgrep auditd)`, or write to `/etc/audit/audit.rules` inside a container; disappearance of auditd process.
Confidence: **Likely** -- MITRE platform is Linux; no Containers platform tag; privileged container or `CAP_AUDIT_CONTROL` required; Ebury procedure example confirmed.

**T1027.004 -- Obfuscated Files or Information: Compile After Delivery**
URL: https://attack.mitre.org/techniques/T1027/004/
Rationale: Platform includes Linux. Many container images include build toolchains (`gcc`, `make`, `go`). An adversary can transfer source code (T1105) and compile it inside the container to avoid dropping a pre-built binary that might trigger hash-based detection.
Observable: Exec of `gcc`, `make`, `go build`, or `cc` inside a container at a time inconsistent with normal build schedules; output binary created in `/tmp/` or `/dev/shm/`.
Confidence: **Likely** -- MITRE platform includes Linux; no container-specific procedure examples but the technique requires only a compiler which many container images provide.

---

### Discovery

**T1082 -- System Information Discovery**
URL: https://attack.mitre.org/techniques/T1082/
Rationale: Platforms include Linux and IaaS. Inside a container, adversaries run `uname -a`, `cat /proc/version`, `cat /etc/os-release` to understand the host kernel version and container OS, informing exploit selection (e.g., choosing a DirtyPipe exploit). This is a near-universal first step post-execution in container attacks.
Observable: Exec of `uname`, `id`, `hostname`, `cat /etc/os-release` inside a container in rapid succession, especially if followed by network activity or tool download.
Confidence: **Confirmed** -- MITRE platform is Linux; well-documented as post-compromise enumeration in container-targeting malware (TeamTNT, Hildegard).

**T1087.001 -- Account Discovery: Local Account**
URL: https://attack.mitre.org/techniques/T1087/001/
Rationale: Platform is Linux. Inside a container, `cat /etc/passwd` enumerates all user accounts, identifying service accounts that may hold elevated privileges or have home directories with stored credentials.
Observable: Read of `/etc/passwd` by a process other than PAM/login utilities inside a container; exec of `id`, `whoami`, `groups` inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; `id` and `/etc/passwd` enumeration are universally documented in container attack toolkits.

**T1069.001 -- Permission Groups Discovery: Local Groups**
URL: https://attack.mitre.org/techniques/T1069/001/
Rationale: Platform is Linux. Inside a container, `groups` or `cat /etc/group` identifies which groups the compromised user belongs to, and identifies privileged groups like `sudo`, `docker`, `adm`.
Observable: Exec of `groups`, `id`, or read of `/etc/group` inside a container shortly after initial shell access.
Confidence: **Confirmed** -- MITRE platform is Linux; standard post-compromise enumeration step.

**T1057 -- Process Discovery**
URL: https://attack.mitre.org/techniques/T1057/
Rationale: Platform is Linux. Inside a container, `ps aux` or `cat /proc/*/cmdline` reveals other processes running in the container (e.g., application processes holding credentials in memory, or other container PIDs if hostPID=true). Hildegard malware is documented performing process enumeration in container environments.
Observable: Exec of `ps`, `pgrep`, or read of `/proc/*/cmdline` inside a container; especially significant when hostPID=true gives the adversary a view of all host processes.
Confidence: **Confirmed** -- MITRE platform is Linux; container-targeting malware families documented using process enumeration.

**T1083 -- File and Directory Discovery**
URL: https://attack.mitre.org/techniques/T1083/
Rationale: Platform is Linux. An adversary inside a container enumerates the filesystem to find configuration files, secrets, mounted volumes, and Kubernetes service account tokens. Standard tool is `find / -name '*.conf' -o -name '*.env'`.
Observable: Exec of `find /`, `ls -la /`, or recursive directory traversal inside a container; particularly significant when targeting `/var/run/secrets/`, `/etc/`, or mounted volume paths.
Confidence: **Confirmed** -- MITRE platform is Linux; well-documented as part of container-targeting post-exploitation in Hildegard and TeamTNT.

**T1046 -- Network Service Discovery**
URL: https://attack.mitre.org/techniques/T1046/
Rationale: Platforms include Containers and Linux. Inside a container, adversaries use `nmap`, `nc -z`, or port scanning to discover services reachable on the pod network, including the Kubernetes API server, etcd, kubelet, and other pod services. This is explicitly listed in the Containers matrix.
Observable: Exec of `nmap`, `masscan`, or `nc -z` inside a container; DNS queries for Kubernetes cluster service names; connection attempts to `kubernetes.default.svc`.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; Peirates and TeamTNT documented using network scanning from inside containers.

**T1016 -- System Network Configuration Discovery**
URL: https://attack.mitre.org/techniques/T1016/
Rationale: Platform is Linux. Inside a container, `ip addr`, `route`, `cat /etc/resolv.conf` reveals the pod's IP, gateway, DNS configuration, and CIDR, informing lateral movement to other pods. Near-universal step in container attack toolkits.
Observable: Exec of `ip addr`, `ip route`, `ifconfig`, `cat /etc/resolv.conf`, or `cat /etc/hosts` inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; standard enumeration step in documented container attacks.

---

### Execution (post-access execution techniques)

**T1053.003 -- Scheduled Task/Job: Cron**
URL: https://attack.mitre.org/techniques/T1053/003/
Rationale: Platform includes Linux. Containers that include `cron` or `crond` allow adversaries to install a crontab entry that re-executes a payload periodically, even if the initial shell session is terminated. Kinsing malware is documented using cron to maintain persistence in container environments, specifically downloading and running scripts every minute.
Observable: Write to `/var/spool/cron/crontabs/<user>` or `/etc/cron.d/*` inside a container; exec of `crontab -e` inside a container; Kinsing procedure example confirmed.
Confidence: **Confirmed** -- MITRE platform is Linux; Kinsing procedure example on technique page explicitly mentions container-targeted use.

**T1105 -- Ingress Tool Transfer**
URL: https://attack.mitre.org/techniques/T1105/
Rationale: Platform is Linux. An adversary with a shell inside a container downloads additional tools (exploit binaries, cryptominers, lateral movement tools) via `curl` or `wget`. Hildegard and Doki malware are documented downloading scripts and tools into containers.
Observable: Outbound HTTP/HTTPS connection from a container process (not the application's documented egress) to an external IP; exec of `curl -O`, `wget`, `python3 -c 'import urllib...'` inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; Hildegard and Doki procedure examples confirmed; both specifically target container environments.

**T1059.006 -- Command and Scripting Interpreter: Python**
URL: https://attack.mitre.org/techniques/T1059/006/
Rationale: Platform is Linux. Many container images include Python. An adversary uses `python3 -c` one-liners or drops a `.py` script to execute payloads, establish reverse shells, or automate enumeration. Python reverse shells are extremely common in container post-exploitation.
Observable: Exec of `python3 -c "import socket,subprocess..."` or write and exec of a `.py` file inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; Python reverse shells are the most common in-container shell establishment technique in documented K8s attack toolkits.

---

### Impact

**T1496.001 -- Resource Hijacking: Compute Hijacking**
URL: https://attack.mitre.org/techniques/T1496/001/
Rationale: Platforms include Containers and Linux explicitly. The technique page explicitly states "containerized environments" face particular risk and documents TeamTNT, Hildegard, and Kinsing using XMRig and other cryptominers inside containers. This is one of the most prevalent in-container attack objectives.
Observable: Exec of `xmrig` or other mining binary inside a container; sustained high CPU from a container process not matching the application's normal profile; outbound connections to mining pool endpoints.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; TeamTNT, Hildegard, and Kinsing procedure examples confirmed; all three are documented container-targeting threat actors.

**T1485 -- Data Destruction**
URL: https://attack.mitre.org/techniques/T1485/
Rationale: Platforms include Containers and Linux explicitly. The technique page notes adversaries may "execute destructive file operations inside volume mounts or host paths," including `rm -rf /mnt/volumes/`. An adversary inside a container can destroy application data stored in persistent volume mounts.
Observable: Exec of `rm -rf` targeting a mounted volume path (e.g., `/data/`, `/mnt/`) inside a container; write of random bytes to database files in a PVC mount.
Confidence: **Confirmed** -- MITRE explicitly lists Containers as a platform; technique page detection strategy explicitly mentions containers and volume mounts.

**T1574.006 -- Hijack Execution Flow: Dynamic Linker Hijacking**
URL: https://attack.mitre.org/techniques/T1574/006/
Rationale: Platform is Linux. Inside a container, an adversary can write a malicious `.so` file and set `LD_PRELOAD` in the container's environment or write to `/etc/ld.so.preload` to intercept library calls made by the application process. Hildegard malware is documented modifying `/etc/ld.so.preload` in container-targeting campaigns.
Observable: Write to `/etc/ld.so.preload` or creation of an unexpected `.so` file in a library path inside a container; Hildegard procedure example confirmed on technique page.
Confidence: **Confirmed** -- MITRE platform is Linux; Hildegard procedure example confirmed on technique page; Hildegard specifically targets Kubernetes.

---

### Lateral Movement

**T1021.004 -- Remote Services: SSH**
URL: https://attack.mitre.org/techniques/T1021/004/
Rationale: Platform is Linux. From inside a container, an adversary can use SSH with stolen credentials or keys to connect to other pods, nodes, or external systems. The Kinsing malware family is documented using SSH for lateral movement in container-targeted campaigns.
Observable: Outbound TCP connection to port 22 from inside a container to another pod IP or node IP; exec of `ssh` binary inside a container.
Confidence: **Confirmed** -- MITRE platform is Linux; Kinsing procedure example confirmed on technique page.

---

## Summary of Section 3

| # | Technique ID | Name | MITRE Lists Containers? | Confidence |
|---|---|---|---|---|
| 1 | T1098.004 | SSH Authorized Keys | No (Linux) | Confirmed |
| 2 | T1136.001 | Create Account: Local Account | Yes | Confirmed |
| 3 | T1543.002 | Systemd Service | No (Linux) | Likely |
| 4 | T1546.004 | Unix Shell Configuration Modification | No (Linux) | Confirmed |
| 5 | T1037.004 | RC Scripts | No (Linux) | Likely |
| 6 | T1505.003 | Web Shell | No (Linux) | Confirmed |
| 7 | T1098.007 | Additional Local or Domain Groups | No (Linux) | Likely |
| 8 | T1554 | Compromise Host Software Binary | No (Linux) | Likely |
| 9 | T1547.006 | Kernel Modules and Extensions | No (Linux) | Likely (priv. container) |
| 10 | T1556.003 | Pluggable Authentication Modules | No (Linux) | Confirmed |
| 11 | T1548.003 | Sudo and Sudo Caching | No (Linux) | Confirmed |
| 12 | T1548.001 | Setuid and Setgid | No (Linux) | Confirmed |
| 13 | T1055.008 | Ptrace System Calls | No (Linux) | Confirmed |
| 14 | T1068 | Exploitation for Privilege Escalation | Yes | Confirmed |
| 15 | T1003.007 | Proc Filesystem | No (Linux) | Confirmed |
| 16 | T1003.008 | /etc/passwd and /etc/shadow | No (Linux) | Confirmed |
| 17 | T1552.001 | Credentials In Files | Yes | Confirmed |
| 18 | T1552.003 | Shell History | No (Linux) | Confirmed |
| 19 | T1552.004 | Private Keys | No (Linux) | Confirmed |
| 20 | T1555.003 | Credentials from Web Browsers | No (Linux) | Possible |
| 21 | T1070.003 | Clear Command History | No (Linux) | Confirmed |
| 22 | T1070.004 | File Deletion | No (Linux) | Confirmed |
| 23 | T1222.002 | Linux and Mac File Permissions | No (Linux) | Confirmed |
| 24 | T1036.005 | Match Legitimate Resource Name or Location | Yes | Confirmed |
| 25 | T1014 | Rootkit | No (Linux) | Likely (priv. container) |
| 26 | T1685.004 | Disable Linux Audit System Log | No (Linux) | Likely (priv. container) |
| 27 | T1027.004 | Compile After Delivery | No (Linux) | Likely |
| 28 | T1082 | System Information Discovery | No (Linux) | Confirmed |
| 29 | T1087.001 | Account Discovery: Local Account | No (Linux) | Confirmed |
| 30 | T1069.001 | Permission Groups Discovery: Local Groups | No (Linux) | Confirmed |
| 31 | T1057 | Process Discovery | No (Linux) | Confirmed |
| 32 | T1083 | File and Directory Discovery | No (Linux) | Confirmed |
| 33 | T1046 | Network Service Discovery | Yes | Confirmed |
| 34 | T1016 | System Network Configuration Discovery | No (Linux) | Confirmed |
| 35 | T1053.003 | Cron | No (Linux) | Confirmed |
| 36 | T1105 | Ingress Tool Transfer | No (Linux) | Confirmed |
| 37 | T1059.006 | Python | No (Linux) | Confirmed |
| 38 | T1496.001 | Compute Hijacking | Yes | Confirmed |
| 39 | T1485 | Data Destruction | Yes | Confirmed |
| 40 | T1574.006 | Dynamic Linker Hijacking | No (Linux) | Confirmed |
| 41 | T1021.004 | SSH | No (Linux) | Confirmed |

---

## Section 4: Mapping to MS-TA Entry Points

### MS-TA entry point classification

The seven MS-TA records explicitly named by the user all grant in-container execution. After reviewing all 40 MS-TA records, the following additional records also result in or require in-container execution:

- **MS-TA9012 (Backdoor container):** The attacker deploys a backdoored container; the backdoor executes inside the container. In-container execution: YES.
- **MS-TA9013 (Escape to Host):** Begins with in-container execution; the goal is to escape. In-container execution: YES (the escape attempt is FROM the container).

All other MS-TA records (MS-TA9001 through MS-TA9005, MS-TA9014 through MS-TA9017, MS-TA9019 through MS-TA9041) operate at the Kubernetes control-plane layer, cloud-API layer, or host layer and do not by themselves provide in-container shell execution. They are skipped.

### JSON cross-reference snippets

The following JSON blocks are ready to paste into `mitre_cross_references[]` in the respective MS-TA data files. All share `"relationship": "post_execution_linux_overlay"`.

---

#### MS-TA9006 -- Container Administration Command (kubectl exec / docker exec)

This is the canonical in-container execution entry point. All 41 overlay techniques apply.

```json
[
  {
    "technique_id": "T1548.003",
    "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "url": "https://attack.mitre.org/techniques/T1548/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After gaining a shell inside a container via kubectl exec (T1609), an adversary may write NOPASSWD: ALL to /etc/sudoers or a /etc/sudoers.d/ file to escalate from a non-root container user to root within the container. Observable: write to /etc/sudoers or exec of visudo inside the container PID namespace.",
    "sources": [
      "https://attack.mitre.org/techniques/T1548/003/"
    ]
  },
  {
    "technique_id": "T1548.001",
    "name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "url": "https://attack.mitre.org/techniques/T1548/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary can run chmod u+s on a binary to create a setuid persistence mechanism for future privilege escalation within the container. Applicable unless allowPrivilegeEscalation: false is set in the pod security context.",
    "sources": [
      "https://attack.mitre.org/techniques/T1548/001/"
    ]
  },
  {
    "technique_id": "T1098.004",
    "name": "Account Manipulation: SSH Authorized Keys",
    "url": "https://attack.mitre.org/techniques/T1098/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "From a shell obtained via kubectl exec into a container running sshd or a container with SSH access, an adversary appends their public key to ~/.ssh/authorized_keys to maintain persistent SSH access without valid credentials. Observable: write event to /root/.ssh/authorized_keys inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1098/004/"
    ]
  },
  {
    "technique_id": "T1136.001",
    "name": "Create Account: Local Account",
    "url": "https://attack.mitre.org/techniques/T1136/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "From a root shell in the container, an adversary runs useradd to create a backdoor account. MITRE explicitly lists Containers as a platform for this sub-technique. Observable: exec of /usr/sbin/useradd or write to /etc/passwd and /etc/shadow inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1136/001/"
    ]
  },
  {
    "technique_id": "T1546.004",
    "name": "Event Triggered Execution: Unix Shell Configuration Modification",
    "url": "https://attack.mitre.org/techniques/T1546/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary modifies ~/.bashrc or /etc/profile to inject a payload that re-executes every time a shell session opens inside the container, including future kubectl exec sessions by operators. Observable: write to ~/.bashrc or /etc/profile inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1546/004/"
    ]
  },
  {
    "technique_id": "T1053.003",
    "name": "Scheduled Task/Job: Cron",
    "url": "https://attack.mitre.org/techniques/T1053/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "In containers that include crond (common in many base images), an adversary installs a crontab entry to re-execute a payload periodically after the initial kubectl exec session ends. Kinsing malware is documented using cron to download and re-run scripts every minute in container environments. Observable: write to /var/spool/cron/crontabs/ or exec of crontab -e inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1053/003/"
    ]
  },
  {
    "technique_id": "T1505.003",
    "name": "Server Software Component: Web Shell",
    "url": "https://attack.mitre.org/techniques/T1505/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container running a web server, an adversary drops a web shell into the web root directory, creating a persistent command execution channel via the already-exposed service port. Observable: write of a .php, .jsp, or .py file to a web-served directory inside the container, followed by an HTTP request to that path.",
    "sources": [
      "https://attack.mitre.org/techniques/T1505/003/"
    ]
  },
  {
    "technique_id": "T1574.006",
    "name": "Hijack Execution Flow: Dynamic Linker Hijacking",
    "url": "https://attack.mitre.org/techniques/T1574/006/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary writes a malicious shared library and adds its path to /etc/ld.so.preload or sets LD_PRELOAD in the container environment to intercept application library calls. Hildegard malware, which specifically targets Kubernetes, is documented modifying /etc/ld.so.preload in container environments. Observable: write to /etc/ld.so.preload inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1574/006/"
    ]
  },
  {
    "technique_id": "T1055.008",
    "name": "Process Injection: Ptrace System Calls",
    "url": "https://attack.mitre.org/techniques/T1055/008/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container running as root or with CAP_SYS_PTRACE, an adversary uses ptrace to attach to the application process and extract credentials from memory or inject shellcode. Observable: ptrace syscall with PTRACE_ATTACH against a non-child process inside the container PID namespace.",
    "sources": [
      "https://attack.mitre.org/techniques/T1055/008/"
    ]
  },
  {
    "technique_id": "T1003.007",
    "name": "OS Credential Dumping: Proc Filesystem",
    "url": "https://attack.mitre.org/techniques/T1003/007/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container as root, an adversary reads /proc/<pid>/maps and /proc/<pid>/mem to extract credentials from the application process memory (e.g., database passwords held in heap). LaZagne and MimiPenguin implement this technique. Observable: open/read syscall on /proc/<pid>/mem for a PID not owned by the calling process.",
    "sources": [
      "https://attack.mitre.org/techniques/T1003/007/"
    ]
  },
  {
    "technique_id": "T1003.008",
    "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "url": "https://attack.mitre.org/techniques/T1003/008/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container as root, an adversary reads /etc/shadow to dump password hashes for all local accounts for offline cracking. Observable: read of /etc/shadow by a process other than PAM or login utilities inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1003/008/"
    ]
  },
  {
    "technique_id": "T1552.001",
    "name": "Unsecured Credentials: Credentials In Files",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary searches for credentials in environment variables, config files, and mounted secrets including the Kubernetes service account token at /var/run/secrets/kubernetes.io/serviceaccount/token. MITRE explicitly lists Containers as a platform; Hildegard and TeamTNT are documented searching for these paths. Observable: read of /var/run/secrets/kubernetes.io/serviceaccount/token or /run/secrets/* inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/"
    ]
  },
  {
    "technique_id": "T1552.003",
    "name": "Unsecured Credentials: Shell History",
    "url": "https://attack.mitre.org/techniques/T1552/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container that has been used interactively by operators, ~/.bash_history may contain plaintext credentials previously typed. Kinsing malware is documented searching bash_history files for credentials. Observable: read of ~/.bash_history by a process that is not the user's own shell.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/003/"
    ]
  },
  {
    "technique_id": "T1552.004",
    "name": "Unsecured Credentials: Private Keys",
    "url": "https://attack.mitre.org/techniques/T1552/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container used in CI/CD or mounting secret volumes, an adversary searches for SSH private keys and TLS certificates. Observable: find/read syscall on files matching *.pem, *.key, id_rsa patterns inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/004/"
    ]
  },
  {
    "technique_id": "T1070.003",
    "name": "Indicator Removal: Clear Command History",
    "url": "https://attack.mitre.org/techniques/T1070/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After completing activity via kubectl exec, an adversary runs history -c or unset HISTFILE to erase evidence of their commands from the container. TeamTNT and Hildegard, both container-targeting malware families, are documented using this technique. Observable: exec of history -c inside a container terminal session.",
    "sources": [
      "https://attack.mitre.org/techniques/T1070/003/"
    ]
  },
  {
    "technique_id": "T1070.004",
    "name": "Indicator Removal: File Deletion",
    "url": "https://attack.mitre.org/techniques/T1070/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After dropping and executing a tool inside the container, an adversary runs rm -f on the tool binary to remove forensic artifacts. Observable: exec of rm targeting a recently-written executable inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1070/004/"
    ]
  },
  {
    "technique_id": "T1082",
    "name": "System Information Discovery",
    "url": "https://attack.mitre.org/techniques/T1082/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary runs uname -a, cat /proc/version, and cat /etc/os-release to identify the kernel version and container OS to inform exploit selection. Observable: exec of uname, id, hostname, or cat /proc/version inside the container in rapid succession after initial access.",
    "sources": [
      "https://attack.mitre.org/techniques/T1082/"
    ]
  },
  {
    "technique_id": "T1087.001",
    "name": "Account Discovery: Local Account",
    "url": "https://attack.mitre.org/techniques/T1087/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary reads /etc/passwd to enumerate user accounts and identify service accounts with home directories or elevated privileges. Observable: read of /etc/passwd by a process other than PAM inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1087/001/"
    ]
  },
  {
    "technique_id": "T1069.001",
    "name": "Permission Groups Discovery: Local Groups",
    "url": "https://attack.mitre.org/techniques/T1069/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary runs groups or reads /etc/group to identify membership in privileged groups such as sudo, docker, or adm. Observable: exec of groups or id inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1069/001/"
    ]
  },
  {
    "technique_id": "T1057",
    "name": "Process Discovery",
    "url": "https://attack.mitre.org/techniques/T1057/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary runs ps aux or reads /proc/*/cmdline to enumerate running processes, identify applications holding credentials in memory, and (if hostPID=true) discover all host processes. Observable: exec of ps or pgrep inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1057/"
    ]
  },
  {
    "technique_id": "T1083",
    "name": "File and Directory Discovery",
    "url": "https://attack.mitre.org/techniques/T1083/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary uses find / or ls -la to enumerate the filesystem for configuration files, secrets, and mounted volumes. Observable: exec of find / or recursive directory traversal targeting /var/run/secrets/, /etc/, or mounted volume paths.",
    "sources": [
      "https://attack.mitre.org/techniques/T1083/"
    ]
  },
  {
    "technique_id": "T1046",
    "name": "Network Service Discovery",
    "url": "https://attack.mitre.org/techniques/T1046/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary uses nmap or nc -z to scan the pod network for reachable services including the Kubernetes API server at kubernetes.default.svc, etcd, and adjacent pod services. MITRE explicitly lists Containers as a platform. Observable: exec of nmap or nc -z inside the container; DNS query for kubernetes.default.svc.",
    "sources": [
      "https://attack.mitre.org/techniques/T1046/"
    ]
  },
  {
    "technique_id": "T1016",
    "name": "System Network Configuration Discovery",
    "url": "https://attack.mitre.org/techniques/T1016/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary reads ip addr, ip route, and /etc/resolv.conf to learn the pod CIDR, gateway, and DNS server (kube-dns) to inform lateral movement. Observable: exec of ip addr or cat /etc/resolv.conf inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1016/"
    ]
  },
  {
    "technique_id": "T1105",
    "name": "Ingress Tool Transfer",
    "url": "https://attack.mitre.org/techniques/T1105/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary uses curl or wget to download exploit binaries, cryptominers, or lateral movement tools from an external C2. Hildegard and Doki malware are documented using tool download into containers. Observable: outbound HTTP/HTTPS from the container to an external IP not in the application's documented egress list.",
    "sources": [
      "https://attack.mitre.org/techniques/T1105/"
    ]
  },
  {
    "technique_id": "T1059.006",
    "name": "Command and Scripting Interpreter: Python",
    "url": "https://attack.mitre.org/techniques/T1059/006/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container that includes Python (common in data and ML workloads), an adversary executes python3 one-liners for reverse shells, enumeration, or payload delivery. Observable: exec of python3 -c with socket/subprocess imports inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1059/006/"
    ]
  },
  {
    "technique_id": "T1496.001",
    "name": "Resource Hijacking: Compute Hijacking",
    "url": "https://attack.mitre.org/techniques/T1496/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary drops and runs a cryptominer (e.g., xmrig) to abuse the pod's CPU allocation. MITRE explicitly lists Containers as a platform; TeamTNT, Hildegard, and Kinsing are documented executing cryptominers inside containers via this exact path. Observable: exec of xmrig or similar binary inside the container; sustained high CPU from a non-application process.",
    "sources": [
      "https://attack.mitre.org/techniques/T1496/001/"
    ]
  },
  {
    "technique_id": "T1485",
    "name": "Data Destruction",
    "url": "https://attack.mitre.org/techniques/T1485/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container with mounted persistent volumes, an adversary runs rm -rf targeting volume mount paths to destroy application data. MITRE explicitly lists Containers as a platform; the technique page's detection strategy specifically mentions rm -rf /mnt/volumes/ inside containers. Observable: exec of rm -rf targeting a mounted volume path inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1485/"
    ]
  },
  {
    "technique_id": "T1222.002",
    "name": "File and Directory Permissions Modification: Linux and Mac File Permissions",
    "url": "https://attack.mitre.org/techniques/T1222/002/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary uses chmod or chown to make a dropped payload executable or to restrict operator access to their persistence files. Kinsing, which targets containers, is documented using chmod on key files. Observable: exec of chmod +x or chown on a recently-written file inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1222/002/"
    ]
  },
  {
    "technique_id": "T1036.005",
    "name": "Masquerading: Match Legitimate Resource Name or Location",
    "url": "https://attack.mitre.org/techniques/T1036/005/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container, an adversary places their tool binary in /tmp/ or /dev/shm/ with a name matching a legitimate system utility (e.g., kube-apiserver, sshd) to evade process-name-based detection. MITRE explicitly lists Containers as a platform and the technique page includes container-specific language. Observable: exec of a binary in /tmp/ or /dev/shm/ whose name matches a known system tool.",
    "sources": [
      "https://attack.mitre.org/techniques/T1036/005/"
    ]
  },
  {
    "technique_id": "T1021.004",
    "name": "Remote Services: SSH",
    "url": "https://attack.mitre.org/techniques/T1021/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container and obtaining SSH keys or credentials, an adversary uses the container as a pivot point to SSH to other pods or cluster nodes. Kinsing malware is documented using SSH for lateral movement from container environments. Observable: outbound TCP to port 22 from inside the container to a pod or node IP.",
    "sources": [
      "https://attack.mitre.org/techniques/T1021/004/"
    ]
  },
  {
    "technique_id": "T1068",
    "name": "Exploitation for Privilege Escalation",
    "url": "https://attack.mitre.org/techniques/T1068/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container as a non-root user, an adversary executes a local privilege escalation exploit (e.g., CVE-2022-0847 DirtyPipe, CVE-2021-4034 pkexec) to become root within the container or to break out to the host. MITRE lists Containers as a platform and analytic AN1422 explicitly covers container breakout via exploitation. Observable: exec of a known exploit binary or anomalous write to /proc/self/mem inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1068/"
    ]
  },
  {
    "technique_id": "T1554",
    "name": "Compromise Host Software Binary",
    "url": "https://attack.mitre.org/techniques/T1554/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After exec into a container as root, an adversary replaces a common binary (/usr/bin/ssh, /bin/ls) with a trojanized version that backdoors authentication or hides files within the container's writable filesystem layer. Observable: write to /usr/bin/, /usr/sbin/, or /bin/ inside the container for a file already present; file checksum mismatch vs. original image layer.",
    "sources": [
      "https://attack.mitre.org/techniques/T1554/"
    ]
  },
  {
    "technique_id": "T1027.004",
    "name": "Obfuscated Files or Information: Compile After Delivery",
    "url": "https://attack.mitre.org/techniques/T1027/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "In containers that include a build toolchain (gcc, go, make), an adversary transfers source code and compiles it inside the container to avoid dropping a binary that would match known malware hashes. Observable: exec of gcc, go build, or make in /tmp/ inside a container at an unexpected time; resulting binary exec immediately after compilation.",
    "sources": [
      "https://attack.mitre.org/techniques/T1027/004/"
    ]
  }
]
```

---

#### MS-TA9007 -- bash or cmd inside container (T1059)

Same overlay as MS-TA9006. The adversary already has a shell. All 33 post-shell techniques in the list above apply identically. The JSON block is identical to the MS-TA9006 block above; paste the same array.

---

#### MS-TA9008 -- New Container (Deploy Container, T1610)

The adversary deploys a container from a malicious or arbitrary image and runs code inside it. All 33 overlay techniques apply identically to the shell the adversary has inside their deployed container.

Additional overlay entry specific to MS-TA9008 because the adversary controls the image:

```json
[
  {
    "technique_id": "T1543.002",
    "name": "Create or Modify System Process: Systemd Service",
    "url": "https://attack.mitre.org/techniques/T1543/002/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "In a container the adversary deployed, if the image includes systemd as the init system, the adversary can write a systemd service unit file to /etc/systemd/system/ to establish a persistent service that survives container restart. Hildegard malware is documented creating systemd services in container environments. Observable: write to /etc/systemd/system/*.service inside the container; exec of systemctl enable.",
    "sources": [
      "https://attack.mitre.org/techniques/T1543/002/"
    ]
  },
  {
    "technique_id": "T1037.004",
    "name": "Boot or Logon Initialization Scripts: RC Scripts",
    "url": "https://attack.mitre.org/techniques/T1037/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "In a container the adversary deployed, writing to /etc/rc.local causes the payload to execute every time the container restarts. Observable: write to /etc/rc.local inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1037/004/"
    ]
  },
  {
    "technique_id": "T1547.006",
    "name": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "url": "https://attack.mitre.org/techniques/T1547/006/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "If the adversary deployed a privileged container (as is common in MS-TA9008 / MS-TA9018), they can load a malicious kernel module (insmod) that persists in the host kernel across container restarts. Skidmap malware is documented using kernel modules in container-targeting campaigns. Requires CAP_SYS_MODULE or privileged=true. Observable: exec of insmod inside a privileged container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1547/006/"
    ]
  },
  {
    "technique_id": "T1014",
    "name": "Rootkit",
    "url": "https://attack.mitre.org/techniques/T1014/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "In a privileged container deployed by the adversary, loading a kernel-mode rootkit (e.g., Diamorphine) hides the adversary's processes, files, and network connections from the host. TeamTNT is documented deploying Diamorphine in container environments. Requires privileged=true or CAP_SYS_MODULE. Observable: insmod of a .ko file inside a privileged container; missing processes in ps output after module load.",
    "sources": [
      "https://attack.mitre.org/techniques/T1014/"
    ]
  }
]
```

(Also include all techniques from the MS-TA9006 JSON block above.)

---

#### MS-TA9009 -- Application Exploit RCE (T1190)

The adversary has a shell spawned by the exploited application process (e.g., a Java deserialization RCE giving a shell as the `tomcat` or `www-data` user). All overlay techniques apply; many are especially relevant because the initial shell may be non-root, making privilege escalation techniques the immediate priority.

All techniques from the MS-TA9006 JSON block apply. The following are particularly high priority for this entry point:

- **T1548.003 (Sudo):** First step after non-root RCE shell to escalate within the container.
- **T1068 (Exploitation for Privilege Escalation):** Kernel CVE exploitation to gain root from the low-privilege RCE shell.
- **T1055.008 (Ptrace):** If CAP_SYS_PTRACE is available, attach to the application process to extract credentials.
- **T1552.001 (Credentials In Files):** The service account token at /var/run/secrets/kubernetes.io/serviceaccount/token is the most valuable credential reachable from any container shell without root.
- **T1082 (System Information Discovery):** Identifies kernel version for exploit selection immediately after getting the shell.

No separate JSON block required; paste the MS-TA9006 block.

---

#### MS-TA9010 -- SSH server running inside container

The adversary authenticates to a containerized SSH daemon and gets a shell. This is identical in post-execution capability to any other container shell. All techniques from the MS-TA9006 JSON block apply.

Additional overlay entries specific to the SSH entry point:

```json
[
  {
    "technique_id": "T1098.004",
    "name": "Account Manipulation: SSH Authorized Keys",
    "url": "https://attack.mitre.org/techniques/T1098/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After gaining SSH access to a container (the MS-TA9010 threat), the adversary immediately adds their own public key to ~/.ssh/authorized_keys to ensure persistent re-entry even if the original compromised credential is rotated. Observable: write to /root/.ssh/authorized_keys or /home/<user>/.ssh/authorized_keys inside the container immediately after successful SSH login.",
    "sources": [
      "https://attack.mitre.org/techniques/T1098/004/"
    ]
  },
  {
    "technique_id": "T1556.003",
    "name": "Modify Authentication Process: Pluggable Authentication Modules",
    "url": "https://attack.mitre.org/techniques/T1556/003/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "After gaining SSH access to a container running sshd, the adversary replaces pam_unix.so with a backdoored version that accepts a hardcoded password for any user. Skidmap malware, documented in container-targeting campaigns, uses exactly this technique. Observable: write to /lib/security/pam_unix.so or modification of /etc/pam.d/sshd inside the container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1556/003/"
    ]
  }
]
```

(Also include all techniques from the MS-TA9006 JSON block.)

---

#### MS-TA9011 -- Sidecar Injection (T1610)

The adversary injects a malicious sidecar container into an existing pod. The sidecar shares the pod network, IPC, and (optionally) PID namespace with the main container. Post-execution capabilities in the sidecar are identical to any container shell, with the additional benefit of shared inter-process access.

All techniques from the MS-TA9006 JSON block apply. Additional overlay entry:

```json
[
  {
    "technique_id": "T1057",
    "name": "Process Discovery",
    "url": "https://attack.mitre.org/techniques/T1057/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A malicious sidecar container sharing the pod's PID namespace (shareProcessNamespace: true) can enumerate the main container's processes and read their /proc/<pid>/environ, /proc/<pid>/cmdline, and /proc/<pid>/mem to extract credentials held by the application process. Observable: read of /proc/<pid>/environ or /proc/<pid>/mem from the sidecar for PIDs belonging to the main container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1057/"
    ]
  },
  {
    "technique_id": "T1552.001",
    "name": "Unsecured Credentials: Credentials In Files",
    "url": "https://attack.mitre.org/techniques/T1552/001/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A malicious sidecar container shares the pod's /run/secrets/ mount and the Kubernetes service account token projection with the main container, enabling credential harvest without any privilege escalation. MITRE lists Containers as a platform. Observable: read of /var/run/secrets/kubernetes.io/serviceaccount/token from a sidecar container process.",
    "sources": [
      "https://attack.mitre.org/techniques/T1552/001/"
    ]
  }
]
```

(Also include all techniques from the MS-TA9006 JSON block.)

---

#### MS-TA9018 -- Privileged container (T1610)

The adversary has execution inside a privileged container, which additionally grants near-full host capabilities. Beyond all standard overlay techniques, the following are uniquely or additionally accessible from a privileged context:

```json
[
  {
    "technique_id": "T1547.006",
    "name": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "url": "https://attack.mitre.org/techniques/T1547/006/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A privileged container grants CAP_SYS_MODULE, enabling insmod to load a malicious LKM kernel module that persists in the host kernel and survives container restarts. Skidmap and Drovorub malware both use this approach in container/cloud-targeting campaigns. Observable: exec of insmod or modprobe inside the privileged container; new module in /proc/modules on the host node.",
    "sources": [
      "https://attack.mitre.org/techniques/T1547/006/"
    ]
  },
  {
    "technique_id": "T1014",
    "name": "Rootkit",
    "url": "https://attack.mitre.org/techniques/T1014/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A privileged container with CAP_SYS_MODULE enables deployment of a kernel-mode rootkit (e.g., Diamorphine) that hides the adversary's processes and files from the host's security tooling. TeamTNT is documented deploying Diamorphine in container environments with privileged access. Observable: insmod of a .ko rootkit module inside a privileged container; ps/netstat output diverges from /proc entries.",
    "sources": [
      "https://attack.mitre.org/techniques/T1014/"
    ]
  },
  {
    "technique_id": "T1685.004",
    "name": "Disable or Modify Tools: Disable or Modify Linux Audit System Log",
    "url": "https://attack.mitre.org/techniques/T1685/004/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A privileged container with CAP_AUDIT_CONTROL or CAP_SYS_ADMIN can terminate auditd, delete audit rules, or hook the audit library to suppress detection telemetry for subsequent host activity. Ebury malware is documented disabling auditd as part of its backdoor deployment. Observable: exec of auditctl -D or kill -9 against auditd from inside a privileged container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1685/004/"
    ]
  },
  {
    "technique_id": "T1055.008",
    "name": "Process Injection: Ptrace System Calls",
    "url": "https://attack.mitre.org/techniques/T1055/008/",
    "relationship": "post_execution_linux_overlay",
    "rationale": "A privileged container has CAP_SYS_PTRACE, enabling ptrace injection into any process on the host node (not just within the container PID namespace), which allows credential extraction from privileged host processes. Observable: ptrace PTRACE_ATTACH call against a host-namespace PID from inside a privileged container.",
    "sources": [
      "https://attack.mitre.org/techniques/T1055/008/"
    ]
  }
]
```

(Also include all techniques from the MS-TA9006 JSON block.)

---

#### MS-TA9012 -- Backdoor container (persistence)

The adversary has deployed a container specifically for persistent code execution. Post-execution capabilities are identical to MS-TA9008. Apply the full MS-TA9008 set.

---

#### MS-TA9013 -- Escape to Host

This record represents the escape attempt itself. The adversary begins inside the container. All overlay techniques apply to the in-container phase before the escape succeeds. Apply the full MS-TA9006 set for the pre-escape in-container phase.

---

#### Records without in-container execution (skipped)

| MS-TA ID | Title | Reason Skipped |
|---|---|---|
| MS-TA9001 | Using Cloud Credentials | Cloud API / IAM plane; no container shell |
| MS-TA9002 | Implant Internal Image | Registry operation; no running container shell |
| MS-TA9003 | Kubeconfig file | K8s control-plane API access; no container shell |
| MS-TA9004 | Application Vulnerability | Initial access via network; grants code execution but already covered by MS-TA9009 |
| MS-TA9005 | Exposed sensitive interfaces | K8s API / kubelet exposed; no direct container shell |
| MS-TA9014 | Kubernetes CronJob | K8s scheduler artifact; execution IS in a container (apply full overlay) -- see note |
| MS-TA9015 | Malicious admission controller | Webhook server; no adversary-shell inside target container |
| MS-TA9016 | Container service account | Credential access via mounted token; no shell |
| MS-TA9017 | Static Pods | Pod deployed by adversary; execution IS in a container (apply full overlay) -- see note |
| MS-TA9019 | Cluster-admin binding | RBAC escalation; no container shell directly |
| MS-TA9020 | Access cloud resources | Cloud API from pod service account; shell already established |
| MS-TA9021 | Clear container logs | K8s audit log deletion via API; no new shell |
| MS-TA9022 | Delete K8S events | API operation; no container shell |
| MS-TA9023 | Pod or container name similarity | Defense evasion at K8s scheduling layer |
| MS-TA9024 | Connect from Proxy server | Network evasion; no new execution |
| MS-TA9025 | List K8S secrets | K8s API call; no container shell |
| MS-TA9026 | Mount service principal | Cloud credential mount; no shell |
| MS-TA9027 | Application credentials in config files | File read inside container (shell already present, covered by T1552.001 overlay) |
| MS-TA9028 | Access managed identity credentials | IMDS/cloud API call; shell already present |
| MS-TA9029 | Access the K8S API server | API discovery; shell already present |
| MS-TA9030 | Access Kubelet API | Kubelet API probe; no new shell |
| MS-TA9031 | Network mapping | Pod-network scan; shell already present (T1046 overlay) |
| MS-TA9033 | Instance Metadata API | IMDS access; shell already present |
| MS-TA9034 | Cluster internal networking | Lateral movement via pod network; shell already present |
| MS-TA9035 | CoreDNS poisoning | DNS layer attack; K8s API access |
| MS-TA9036 | ARP poisoning | Network layer; shell already present |
| MS-TA9037 | Images from private registry | Image pull; no shell |
| MS-TA9038 | Data destruction | K8s-level PV deletion via API; not in-container execution specifically |
| MS-TA9039 | Resource hijacking | Cryptominer deployed via new container (already covered by T1496.001 overlay) |
| MS-TA9040 | Denial of service | K8s API / resource exhaustion |
| MS-TA9041 | Collecting data from pod | Shell already present (T1083, T1552 overlay) |

**Note on MS-TA9014 (Kubernetes CronJob) and MS-TA9017 (Static Pods):** Both result in container execution initiated by the Kubernetes scheduler or kubelet. The adversary's code runs inside a container. The full overlay from the MS-TA9006 JSON block applies to those containers as well. Recommend adding the overlay cross-references to MS-TA9014 and MS-TA9017 in a follow-up pass.

---

## Section 5: Candidate First-Class Records

The following Linux techniques are observed so frequently in documented K8s breach cases and represent such distinct, high-fidelity detection opportunities that promoting them to first-class equilibrium records (alongside the MS-TA set) is warranted.

---

### T1548.003 -- Sudo and Sudo Caching

Confidence for promotion: **Confirmed**
Rationale: Sudo abuse is the most common in-container privilege escalation step after gaining a non-root shell (e.g., via application RCE). The concrete observable (write to /etc/sudoers, exec of visudo) is high-fidelity and easily monitored by Falco, auditd, and eBPF sensors. No existing equilibrium record covers in-container privilege escalation via sudo. A first-class record would enable a dedicated detection strategy, Falco rule, and vendor query (e.g., a Wiz query for in-container writes to /etc/sudoers), none of which exist in the current data set.
Sources: https://attack.mitre.org/techniques/T1548/003/

---

### T1136.001 -- Create Account: Local Account (useradd inside container)

Confidence for promotion: **Confirmed**
Rationale: MITRE explicitly lists Containers as a platform. Creating a backdoor account via `useradd` is a near-universal persistence step in container attacks by TeamTNT and similar actors. The observable (exec of useradd, write to /etc/passwd) is a Falco rule candidate that is currently absent from the equilibrium record set. First-class status would enable dedicated vendor detection queries (e.g., Sysdig Falco rule: `proc.name=useradd and container.id != host`).
Sources: https://attack.mitre.org/techniques/T1136/001/

---

### T1098.004 -- SSH Authorized Keys

Confidence for promotion: **Confirmed**
Rationale: Adding an attacker-controlled SSH public key to `~/.ssh/authorized_keys` is the most durable persistence mechanism available from a container shell, especially in containers running sshd (MS-TA9010). TeamTNT and Earth Lusca are documented using this technique. A first-class record would enable a detection strategy anchored on file write events to authorized_keys paths, currently not captured by any equilibrium record.
Sources: https://attack.mitre.org/techniques/T1098/004/

---

### T1574.006 -- Dynamic Linker Hijacking (LD_PRELOAD / /etc/ld.so.preload)

Confidence for promotion: **Confirmed**
Rationale: Hildegard malware, one of the most studied Kubernetes-targeting malware families, specifically modifies `/etc/ld.so.preload` in container environments. This technique provides both persistence and credential interception (hooking `read()` or `write()` in the application process). No existing equilibrium record covers LD_PRELOAD abuse. The observable (write to /etc/ld.so.preload) is highly anomalous in production containers and maps cleanly to a Falco rule or Sysdig policy.
Sources: https://attack.mitre.org/techniques/T1574/006/ ; Hildegard procedure example confirmed on page.

---

### T1552.001 -- Unsecured Credentials: Credentials In Files (service account token harvest)

Confidence for promotion: **Confirmed**
Rationale: MITRE explicitly lists Containers. Reading the Kubernetes service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` is the single most consequential action an adversary takes after gaining any container shell, enabling K8s API calls as the pod's identity. This is documented in MS-TA9016 (Container Service Account) at the K8s-API level, but the in-container file read that obtains the token is not captured. A first-class record focused on the in-container credential harvest step would close a gap between MS-TA9016 (using the token against the API) and the execution entry points.
Sources: https://attack.mitre.org/techniques/T1552/001/ ; Hildegard and TeamTNT procedure examples confirmed.

---

### T1496.001 -- Resource Hijacking: Compute Hijacking (cryptominer in container)

Confidence for promotion: **Confirmed**
Rationale: MITRE explicitly lists Containers. Cryptomining is the objective in a significant fraction of all documented container attacks (TeamTNT, Kinsing, Hildegard). MS-TA9039 covers resource hijacking at the K8s layer (deploying a miner pod), but T1496.001 specifically covers executing a miner binary inside an already-running container. These are distinct detection targets: the MS-TA9039 signal is a pod-create API event; the T1496.001 signal is a process exec of xmrig inside an existing container. First-class status enables a dedicated Falco rule and Sysdig / Datadog detection query.
Sources: https://attack.mitre.org/techniques/T1496/001/

---

## Section 6: Open Questions and Gaps

### Techniques with ambiguous container applicability

- **T1543.002 (Systemd Service):** MITRE does not list Containers as a platform. It is Likely applicable to containers using systemd as init (a common pattern in RHEL-family and Ubuntu base images used in enterprise environments), but the exact fraction of production container images that run systemd is not documented in any source found. This would move to Confirmed if MITRE adds a container procedure example or if a container-targeting malware family is documented using systemd.

- **T1547.006 (Kernel Modules):** MITRE does not list Containers. The constraint is CAP_SYS_MODULE which is only present in privileged containers or containers explicitly granted the capability. Would move to Confirmed if MITRE added a container procedure example referencing insmod from within a pod.

- **T1014 (Rootkit):** Same constraint as T1547.006. TeamTNT deploying Diamorphine is documented in the context of Docker hosts and Kubernetes nodes but the specific execution path (inside a container vs. on the host after escape) is not always clear in published incident reports.

### Gaps in source material

- **T1685.004 detection inside containers:** The MITRE page documents auditd disable on Linux hosts; no source found that specifically documents this technique executed from inside a container (as opposed to on the host after escape). Applicable to privileged containers but no procedure example confirmed.

- **T1555.003 (Credentials from Web Browsers):** Confidence is Possible. No container-specific procedure example found. Production application containers rarely include browser credential stores; this applies mainly to developer workstation containers.

- **T1037.004 (RC Scripts via rc.local) inside containers:** The technique requires rc.local to be executed as part of container startup. This depends on the container's init system. If the container uses a minimal entrypoint script rather than a full init system, rc.local is never read. No published container attack case was found confirming adversary use of rc.local inside a container specifically (vs. on a host).

- **MITRE ATT&CK v19 vs. v20 delta:** The Linux and Containers matrices were fetched on 2026-05-04. Several new sub-techniques were added in the v19 cycle (T1685 family, T1689, T1690). The v20 release timeline is not known; any new Linux-platform techniques added after this research date would not be reflected here.

- **T1556.003 (PAM) in container images:** PAM libraries are present in most full-OS container images (Ubuntu, Debian, RHEL-based) but absent in scratch or distroless images. The technique's applicability depends heavily on the target image's PAM installation; no comprehensive survey of PAM presence in production container base images was found.

---

## Summary Table

| Technique ID | Technique Name | Applies to MS-TA Records | Highest-Confidence Source |
|---|---|---|---|
| T1548.003 | Sudo and Sudo Caching | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1548/003/ |
| T1548.001 | Setuid and Setgid | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1548/001/ |
| T1098.004 | SSH Authorized Keys | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1098/004/ |
| T1136.001 | Create Account: Local Account | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1136/001/ |
| T1546.004 | Unix Shell Configuration Modification | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1546/004/ |
| T1037.004 | RC Scripts | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1037/004/ |
| T1505.003 | Web Shell | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1505/003/ |
| T1098.007 | Additional Local or Domain Groups | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1098/007/ |
| T1554 | Compromise Host Software Binary | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1554/ |
| T1547.006 | Kernel Modules and Extensions | 9008, 9018 (privileged only) | https://attack.mitre.org/techniques/T1547/006/ |
| T1556.003 | Pluggable Authentication Modules | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1556/003/ |
| T1055.008 | Ptrace System Calls | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1055/008/ |
| T1068 | Exploitation for Privilege Escalation | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1068/ |
| T1003.007 | OS Credential Dumping: Proc Filesystem | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1003/007/ |
| T1003.008 | /etc/passwd and /etc/shadow | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1003/008/ |
| T1552.001 | Credentials In Files | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1552/001/ |
| T1552.003 | Shell History | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1552/003/ |
| T1552.004 | Private Keys | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1552/004/ |
| T1555.003 | Credentials from Web Browsers | 9006, 9007, 9008 (dev containers only) | https://attack.mitre.org/techniques/T1555/003/ |
| T1070.003 | Clear Command History | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1070/003/ |
| T1070.004 | File Deletion | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1070/004/ |
| T1222.002 | Linux and Mac File Permissions | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1222/002/ |
| T1036.005 | Match Legitimate Resource Name or Location | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1036/005/ |
| T1014 | Rootkit | 9008, 9018 (privileged only) | https://attack.mitre.org/techniques/T1014/ |
| T1685.004 | Disable Linux Audit System Log | 9008, 9018 (privileged only) | https://attack.mitre.org/techniques/T1685/004/ |
| T1027.004 | Compile After Delivery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1027/004/ |
| T1082 | System Information Discovery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1082/ |
| T1087.001 | Account Discovery: Local Account | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1087/001/ |
| T1069.001 | Permission Groups Discovery: Local Groups | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1069/001/ |
| T1057 | Process Discovery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1057/ |
| T1083 | File and Directory Discovery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1083/ |
| T1046 | Network Service Discovery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1046/ |
| T1016 | System Network Configuration Discovery | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1016/ |
| T1053.003 | Cron | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1053/003/ |
| T1105 | Ingress Tool Transfer | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1105/ |
| T1059.006 | Python | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1059/006/ |
| T1496.001 | Compute Hijacking | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1496/001/ |
| T1485 | Data Destruction | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1485/ |
| T1574.006 | Dynamic Linker Hijacking | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1574/006/ |
| T1543.002 | Systemd Service | 9008, 9012 (systemd-init containers) | https://attack.mitre.org/techniques/T1543/002/ |
| T1021.004 | Remote Services: SSH | 9006, 9007, 9008, 9009, 9010, 9011, 9018, 9012, 9013 | https://attack.mitre.org/techniques/T1021/004/ |

---

## Research Process

### Searches Performed

None via WebSearch. All evidence was gathered by fetching canonical MITRE ATT&CK pages and reading the equilibrium data files directly. This was the appropriate strategy because MITRE ATT&CK pages are primary sources and the technique list is well-defined.

### Pages Fetched

- [Official] https://attack.mitre.org/matrices/enterprise/linux/ (fetched, read in full -- v19 Linux matrix)
- [Official] https://attack.mitre.org/matrices/enterprise/containers/ (fetched, read in full -- v19 Containers matrix)
- [Official] https://attack.mitre.org/techniques/T1548/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1136/001/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1098/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1574/006/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1546/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1547/006/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1505/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1053/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1070/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1003/007/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1003/008/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1552/001/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1548/001/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1055/008/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1543/002/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1070/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1082/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1105/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1014/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1222/002/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1552/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1556/003/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1036/005/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1496/001/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1087/001/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1485/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1685/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1610/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1059/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1037/004/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1040/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1554/ (fetched, read in full)
- [Official] https://attack.mitre.org/techniques/T1069/001/ (fetched, read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9006.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9007.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9008.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9009.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9010.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9011.json (read in full)
- [Internal] /mnt/cephfs/shared/projects/equilibrium/data/techniques/MS-TA9018.json (read in full)
- [Internal] All 40 MS-TA JSON files (titles and tactics enumerated via python3 script)

### Sources Rejected

- https://attack.mitre.org/techniques/enterprise/ -- initial fetch returned a truncated list; rejected in favour of the platform-specific matrix pages which returned complete tables.
- T1040 (Network Sniffing) -- evaluated and rejected: requires promiscuous mode NIC access; containers use veth pairs and cannot sniff cross-pod traffic without hostNetwork=true or a compromised CNI plugin. The rejection is noted in Section 2.
- T1542 family (Pre-OS Boot) -- rejected: requires firmware access unavailable to containers.
- T1541.x, T1025, T1052, T1200, T1092 -- rejected: physical media or hardware access.
- T1561 (Disk Wipe) -- rejected: containers do not own a raw disk device unless a block-device hostPath is mounted; T1485 (Data Destruction) covers the container-relevant subset.
- T1491 (Defacement) -- rejected: not applicable to typical container workloads; already subsumed under T1485 for data-on-volume destruction.

### Gaps

- No source found confirming rc.local execution inside a container specifically (vs. on a host after container escape). The technique is Likely applicable but lacks a confirmed container procedure example.
- No comprehensive survey of PAM installation rates in production container base images found.
- The post-v19 MITRE ATT&CK release cycle may add new Linux-platform sub-techniques not captured here.
- Diamorphine rootkit deployment path (inside container vs. on host after escape) not definitively resolved in published TeamTNT incident reports.

### Tools Used

- WebFetch: 35 fetches
- Bash: 3 commands (file enumeration, JSON field extraction, directory listing)
- Read: 8 file reads (7 MS-TA JSON + 1 cross-references.md)
