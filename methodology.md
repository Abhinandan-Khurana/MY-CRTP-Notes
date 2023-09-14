---
description: a simple walkthrough
---

# Methodology

## Starting Point

1. Remember to bypass AMSI
2. Check for the Execution Policy Language
3. Check the commands you are allowed to execute
4. Use RunWithRegistryNonAdmin.bat
5. Use PowerUp and discover priv-esc vectors.
   1. Unquoted Service
   2. &#x20;Modifiable Service File
   3. Modifiable Service
   4. DLL injection, etc
6. AFTER THAT, you get the local admin access, now start with the enumeration.
7. Also, add the current user to the localgroup administrators to maintain the local admin access.

## Enumeration

1. Enumerate Users
2. Enumerate Computers
3. Enumerate Domain Administrators
4. Enumerate Enterprise Administrators
5. Enumerate all OUs
6. Enumerate all GPOs
7. Enumerate ACLs for Domain Admin Group
8. Enumerate interesting ACLs (important to take note of)
9. Enumerate all modify rights/permissions for the user you are using
10. Enumerate Trusts and Map em for the domain (internal and external)
11. Enumerate Forests and all domains in the forests
12. Enumerate interesting SPNs
13. Use BloodHound to analyse the Infrastructure

MOST IMPORTANT TAKE YOUR TIME DOING ENUMERATION, BECAUSE AFTER AN EFFECTIVE ENUMERATION THE EXPLOITATION IS JUST A WALK IN THE GARDEN.

### Privilege Escalation

1. Identify a machine on which you have local admin access.
2. You can perform a local port scan as well to know about the services running and may find Jenkins, which may possess a potential attack vector. Or just go with the machine on which you are having the local admin access. (LOOK FOR DERVIATIVE LOCAL ADMIN ACCESS IN BLOODHOUND WHILE ENUMERATION, YOU CAN EXPLOIT THAT HERE AND GET A LEAD IN HACKING THE DOMAIN ADMIN'S ACCOUNT | make sure to check the AppLocker Registry key here for advantage over Language Constraint setup)
3. **DOMAIN ADMIN PRIV-ESC**
   1. Hunt for Local Admin Users&#x20;
   2. Check The local Admin Access&#x20;
   3. If yes, Use Invoke-Command or Enter-PSSession
4. (In case of Language Constraint) Checking AppLockerPolicy and note the paths available for us
5. Disable Defender protections
6. Modify Invoke-Mimikatz.ps1 script to call the function in the script itself because we can't dot source files if in constrained language mode
7. Dump the hases
8. Get the ekeys
9. Get Credentials from the credential vault
10. After we get a DA user with Administrator access we can connect to the DC using **Enter-PSSession**
11. Forge inter-forest ticket by trust keys for forest Priv-Esc

### Persistence

1. Golden Ticket&#x20;
2. Silver Ticket&#x20;
3. DSRM&#x20;
4. ACL AdminSDHolder&#x20;
5. ACL DCSync&#x20;
6. ACL security Descriptors
