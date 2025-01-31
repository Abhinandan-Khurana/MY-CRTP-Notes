---
description: ez
---

# Persistence Attacks Explained!

### Attacks

1. **GOLDEN TICKET ATTACK**

**Analogy**: Imagine a theme park where:

* There's a central security office (Domain Controller)
* They issue special golden wristbands (TGTs) that give access to all rides
* Security guards (services) trust these wristbands completely
* One security officer (KRBTGT account) has the special stamp to make these bands

The attack is like:

* A hacker steals the special stamp (KRBTGT hash)
* They can now make unlimited golden wristbands
* These fake bands work everywhere in the park
* Security can't tell they're fake because they have the real stamp

**Technical Details:**

```
Components:
- KRBTGT account hash (master key)
- Domain name and SID
- Target user/group claims

Attack Flow:
1. Compromise domain controller
2. Extract KRBTGT hash
3. Create forged TGT tickets
4. Access any service/resource
5. Persist for up to 10 years
```

* **Example**: Attackers use the krbtgt hash to create a TGT → access fileshares, email, etc., as any user.
* **Detection**: Look for **TGT lifetimes > 10 hours** or logon events from disabled/deleted accounts.

2. **SILVER TICKET ATTACK**

**Analogy**: Using the same theme park scenario:

* Each ride has its own operator (service account)
* Operators have special stamps for their specific ride
* If you steal one operator's stamp, you can only access that ride
* Less powerful but harder to detect than golden tickets

**Technical Details:**

```
Components needed:
- Service account hash
- Service SPN
- Domain SID

Attack Process:
1. Compromise service account
2. Extract password hash
3. Forge service ticket (TGS)
4. Access specific service
5. Bypass DC validation
```

* **Example**: `Mimikatz` extracts the SQL service account hash → attacker forges a TGS to dump databases. \
  Use it to access the service without touching the Domain Controller (DC).
* **Detection**: Monitor **Encryption Type** mismatches in **Event ID 4769** (e.g., RC4 instead of AES).

3. **DELEGATION ATTACKS**

**Analogy**: Think of a hotel where:

* Front desk can make reservations on behalf of guests (delegation)
* Some staff can "act as" guests for certain services
* If compromised, they can abuse these permissions

**Types of Delegation:**

**A. Unconstrained Delegation:**

```
- Like giving a valet complete access to your car
- Can access any service on behalf of user
- High-risk if compromised
```

**B. Constrained Delegation:**

```
- Like limiting valet to parking only
- Restricted to specific services
- Still risky if compromised
```

C. Resource-Based Constrained Delegation:

```
- Service controls who can delegate to it
- More granular control
- Modern and preferred approach
```

**Technical Implementation:**

```
Unconstrained:
1. Service receives user's TGT
2. Can request any service ticket
3. Full impersonation rights

Constrained:
1. Service receives S4U2Self ticket
2. Limited to specified services
3. *Uses msDS-AllowedToDelegateTo
```

* **Constrained Delegation**: A service (e.g., web server) can impersonate users to _specific_ services (e.g., SQL). Attackers abuse this to escalate access.
* **Unconstrained Delegation**: The service can impersonate users to _any_ service. If compromised, attackers dump TGTs from memory.
* **Example**: Compromise a web server with unconstrained delegation → steal Domain Admin’s TGT → take over the DC.
* **Detection**: Audit **Event ID 4624** (Logons) with **Logon Type 3** (Delegation) to sensitive services.

### **Detection & Prevention:**

1. Golden Ticket:

* Monitor TGT lifetimes
* Watch for encryption downgrades
* Regular KRBTGT password changes (Rotate the krbtgt account password **twice** (old + new) to invalidate all tickets)

2. Silver Ticket:

* Monitor service account activity
* Look for missing TGT requests
* Implement strong service account passwords
* Use **Managed Service Accounts (MSAs)** with auto-rotating passwords.

3. Delegation:

* Limit delegation permissions
* Use least-privilege principle
* Monitor delegation changes
* Disable **unconstrained delegation**; use **Resource-Based Constrained Delegation** (RBAC) instead.

4. Kerberos Monitoring:

* Alert on **Event ID 4769** with non-AES encryption or unusual Service Principal Names (SPNs).

\
