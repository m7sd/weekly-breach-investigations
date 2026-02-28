# Weekly Breach Investigation – Week 01
Malicious Go Module Delivering Rekoobe Backdoor  
Date: 28 February 2026

---

## 1. Executive Summary

A malicious Go module impersonating the legitimate `golang.org/x/crypto` library was identified as part of a software supply chain attack. The rogue package embedded backdoored functionality inside the `ReadPassword()` function, enabling the capture and exfiltration of terminal-entered credentials. After harvesting secrets, the malware retrieved and executed a remote shell script that established SSH persistence and weakened firewall configurations. Additional payloads were downloaded, including the Rekoobe Linux backdoor, which provides remote command execution capabilities. This incident highlights the risks associated with dependency confusion and namespace impersonation in open-source ecosystems.

---

## 2. Attack Timeline

**Initial Access:**  
Developers unknowingly imported a malicious Go dependency (`github.com/xinfeisoft/crypto`) that closely resembled a trusted cryptographic package.

**Credential Interception:**  
The malicious module modified the behavior of the `ReadPassword()` function to capture secrets entered via terminal prompts and transmit them to an external server.

**Staging & Execution:**  
A remote script was fetched and executed using a shell pipeline (`curl | sh`), enabling further compromise.

**Persistence & Defense Evasion:**  
The attacker’s SSH key was appended to `/home/ubuntu/.ssh/authorized_keys`, granting persistent access.  
Firewall rules were altered by setting iptables default policies to ACCEPT.

**Payload Deployment:**  
Two additional files disguised with a `.mp5` extension were downloaded. One acted as a loader, while the second deployed the Rekoobe Linux backdoor.

---

## 3. MITRE ATT&CK Mapping

| Tactic             | Technique                                      | ID          |
|--------------------|-----------------------------------------------|------------|
| Initial Access     | Supply Chain Compromise (Software)            | T1195.001  |
| Defense Evasion    | Masquerading                                  | T1036      |
| Credential Access  | Unsecured Credentials                         | T1552      |
| Execution          | Command and Scripting Interpreter (Unix)      | T1059.004  |
| Persistence        | SSH Authorized Keys                           | T1547.004  |
| Defense Evasion    | Impair Defenses (Modify Firewall)             | T1562.004  |
| Command & Control  | Ingress Tool Transfer                         | T1105      |

---

## 4. Detection Opportunities

**Log Sources:**
- Linux audit logs
- Endpoint detection telemetry
- SSH authentication logs
- Firewall / iptables logs
- Network traffic monitoring
- CI/CD dependency scanning tools

**Detection Ideas:**
- Alert on modification of `~/.ssh/authorized_keys`
- Detect execution patterns matching `curl | sh`
- Monitor changes to iptables default policies
- Flag outbound connections to suspicious IP addresses (e.g., 154.84.63.184:443)
- Detect execution of files with non-standard extensions such as `.mp5`
- Monitor unexpected third-party dependency imports in repositories

**Indicators of Compromise (IOCs):**
- Suspicious module path resembling legitimate crypto libraries
- External IP: 154.84.63.184
- Unauthorized SSH key insertion
- Unexpected outbound connections following password prompt execution

---

## 5. Recommended Mitigations

1. Implement Software Composition Analysis (SCA) to validate third-party dependencies.
2. Enforce dependency allowlisting and checksum verification in CI/CD pipelines.
3. Deploy file integrity monitoring for sensitive paths such as `~/.ssh/authorized_keys`.
4. Restrict outbound network traffic through strict egress filtering.
5. Monitor and restrict shell-based execution patterns in production environments.
6. Establish approval workflows for introducing new external dependencies.

---

## 6. Analyst Notes

This campaign demonstrates how targeting high-value credential boundaries within trusted libraries can yield significant impact with minimal visibility. By exploiting namespace similarity, attackers leveraged developer trust to distribute malicious code through standard dependency mechanisms. The staged execution model and use of disguised payloads show layered compromise techniques. If conducting an internal investigation, priority would include identifying affected build environments, auditing dependency trees across repositories, and scanning Linux hosts for unauthorized SSH key modifications.

---

## References
https://thehackernews.com/2026/02/malicious-go-crypto-module-steals.html
https://youtu.be/Yxv1suJYMI8?si=Mcs8tCiXmsjxQoiG
https://youtu.be/II91fiUax2g?si=SpTQq9kLzku_k3wl

- Public reporting on malicious Go module campaign
- MITRE ATT&CK Framework – https://attack.mitre.org
