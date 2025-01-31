---
description: Critical Logon Events, Threat Detection Tactics, and OPSEC Best Practices
---

# Active Directory Security Logging

### **Key Logon Types & Associated Risks**

1. Logon Type 1 (Interactive)

* When: Local keyboard/console logon
* Location: Security Log Event ID 4624
* Risk: High - indicates physical or RDP access
* Important for: Detecting unauthorized local access

2. Logon Type 2 (Network)

* When: Network access to resources (file shares, printers)
* Location: Security Log Event ID 4624/4625
* Risk: High - common in lateral movement
* Critical for: Detecting unauthorized network access attempts
* **Event ID 4624 (Successful Logon)**
  * Tracks successful authentication attempts. Look for logons from unexpected locations, devices, or non-standard accounts (e.g., Domain Admins on workstations).
* **Event ID 4625 (Failed Logon)**
  * Indicates brute-force attacks or credential-stuffing attempts. Excessive failures from a single source may signal reconnaissance or lateral movement.
* **Event ID 4672 (Special Privileges Assigned)**
  * Flags use of highly privileged accounts (e.g., **Administrator**). Hackers often exploit these for persistence or privilege escalation.
* **Event ID 4768/4769 (Kerberos TGT/Service Ticket Requests)**
  * Detects forged Golden/Silver Ticket attacks. Anomalies in encryption types (e.g., weak RC4 instead of AES) or non-standard service principals (SPNs) are red flags.
  *   **Golden/Silver Ticket Detection**

      In addition to **4768/4769**:

      * **Mismatched IPs** between Kerberos requests (4768) and logon events (4624).
      * **Encryption downgrades** (e.g., AES ➔ RC4) in **4769** (Kerberos service ticket).
* **Event ID 4776 (NTLM Authentication)**
  * Monitors legacy NTLM usage. Adversaries may force NTLM downgrades for relay attacks.
* **Event ID 4648 (Explicit Credential Use)**
  * Logs **RunAs** or scheduled task executions with alternate credentials. Common in lateral movement using tools like Mimikatz.
* **Event ID 4740 (Account Lockout)**
  * Indicates potential brute-force attacks against user accounts. Correlate with 4625 for targeted account identification.
* **Event ID 4673 (Sensitive Privilege Use)**
  * Alerts on critical privileges like **SeDebugPrivilege** or **SeBackupPrivilege**, often abused to dump credentials or bypass security.

3. Logon Type 3 (Batch)&#x20;

* When: Scheduled tasks execution
* Location: Security Log Event ID 4624
* Risk: Medium - could indicate persistence mechanisms
* Monitor for: Unexpected scheduled task creations

4. Logon Type 4 (Service)&#x20;

* When: Service startup/operations
* Location: Security Log Event ID 4624
* Risk: High - often targeted for privilege escalation
* Watch for: New service creations (Event ID 7045)
  * **NOTE: Event ID 7045** (New service installation) resides in the **System log**, not Security. \
    So, pair with **4697** (Security log) for full context.

### Key Security Events to Monitor&#x20;

1. Account Management:

* 4624, 4625 (Successful/Failed logons)
* Event ID **4688** logs process creation (e.g., _Process Name_, _Command Line_).&#x20;
* **4689 logs process termination**.&#x20;
* Credential usage is tracked in **4648** (_Subject: ... Account: DOMAIN\user_).

2. Service Operations:

* 7045 (New service installation)
* 4697 (Service installation)

3. PowerShell Activities:

* 4104 (PowerShell script block logging)
  * **Event ID 4104** requires **Module Logging** or **Script Block Logging** to be enabled (via GPO). Adversaries often bypass with `-NoProfile -NonInteractive`.

4. Privilege Usage:

* 4672 (Admin privilege assignments)
* 4673 (Privileged service operations)

### Critical Monitoring Points

1. Domain Controllers:

* Monitor all logon activities
* Track privilege escalations
* Watch service account usage

2. Administrative Actions:

* Track all privileged account usage
* Monitor security policy changes
* Watch for unusual administrative tool usage

3. Authentication Patterns:

* Look for off-hours access
* Monitor for geographically impossible logons
* Track failed authentication attempts

4. Service Account Activity:

* Monitor service account logons
* Track credential usage patterns
* Watch for unusual service operations

### **Additional High-Value Events**

1. **Event ID 4701**:
   * _Scheduled Task Disabled_. Adversaries may disable legitimate tasks to avoid detection.
2. **Event ID 4738**:
   * _User Account Changed_ (e.g., password reset). Used for persistence via service account compromise.
3. **Event ID 5136**:
   * _Directory Service Object Modification_. Monitor for changes to **AdminSDHolder** or **Group Policy Objects** (GPOs).
4. **Event ID 8003**:
   * _NTLM Audit_ (Enabled via "Audit NTLM ..." policies). Detects NTLM relay attempts.
5.  **SACL Auditing Best Practices**

    Enable **Audit Directory Service Changes** to log:

    1. Group membership modifications (**Event ID 4732**/4733).
    2. Sensitive attribute changes (e.g., _UserAccountControl_ flags for "Password Never Expires").

### **High-Confidence Alerting Rules**

* **Impossible Travel**: Auth from New York ➔ London in <1 hour.
* **DC Shadow Attacks**: Look for **Event ID 4662** (AD object restore) from non-DC hosts.
* **Pass-the-Hash**: **NTLMv1** use in **4624** paired with **NetNTLMv1** relay in logs.

### **Some Recommendations (BLUE TEAM)**

* Deploy **Windows Event Forwarding (WEF)** to centralize logs.
* Use **Sigma Rules** (e.g., "Admin Login Remote") to filter noise.
