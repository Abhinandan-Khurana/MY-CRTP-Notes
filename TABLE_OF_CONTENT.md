# Table of Contents

## What is Active Directory?
- Domains
- Domain name
- Forests
- Functional Modes

## Trusts
- Trust direction
- Trust transitivity
- Trust types
- Trust key
- More on trusts

## Users
- User properties
- User Identiiers
- User Secrets
  - LM/NT hashes
  - Kerberos keys
- UserAccountControl
- Other user properties
- Important Users

## Computer accounts
- Trust accounts

## Groups
- Important groups
- Administrative groups
- Other important groups
- Group Scope

## Computers
- Domain Controllers
  - Domain Controllers discovery
  - Domain database dumping
- Windows computers
  - Windows computers discovery
  - Windows computers connection
    - Connecting with RPC/SMB
    - Connecting with Powershell Remoting
    - Connecting with RDP
  - Windows computers credentials
    - LSASS credentials
    - Registry credentials
	- LSA secrets
	- SAM
	- Dumping registry credentials
    - Powershell history
    - Other places to find credentials in Windows
- Linux computers
  - Linux computers discovery
  - Linux computers connection
  - Linux computers credentials
    - Linux Kerberos tickets
    - Linux user files
    - SSH keys
    - Bash history
    - Other places to find credentials in Linux

## Services
- Host service
- Database

## Classes
- Properties
- Principals
  - SID
- Distinguished Names
- Partitions
- Global Catalog
- How to query the database?
  - LDAP
  - ADWS
  - Other protocols

## Security
- Address resolution
  - ARP
  - ARP spoof
  - ARP Scan
- DHCP
  - Rogue DHCP server
  - DHCP Starvation
  - DHCP Discovery
  - DHCP Dynamic DNS
- DNS
  - DNS Basics
  - DNS zones
  - DNS exfiltration
  - Fake DNS server
  - DNS Zone Transfer
  - Dump DNS records
  - ADIDNS
  - DNS dynamic updates
- NetBIOS
  - NetBIOS Datagram Service
  - NetBIOS Session Service
  - NetBIOS Name Service
- LLMNR
- mDNS
- WPAD

## Authentication
- GSS-API/SSPI
  - Windows SSPs
  - Kerberos SSP
  - NTLM SSP
  - Negotiate SSP
  - Digest SSP
  - Secure Channel SSP
  - Cred SSP
  - Custom SSPs
  - SPNEGO
- NTLM
  - NTLM Basics
  - NTLMv1
  - NTLMv2
  - MIC
  - NTLM in Active Directory
  - NTLM Attacks
  - NTLM Recon
  - NTLM brute-force
  - Pass the hash
  - NTLM Relay
    - NTLM Relay Protections
  - NTLM hashes cracking
- Kerberos
  - Kerberos Basics
  - Kerberos principals
  - Tickets
    - PAC
  - Kerberos actors
  - Ticket types
    - ST
    - TGT
  - Ticket acquisition
  - Kerberos services
  - Kerberos keys
  - Kerberos basic attacks
    - Kerberos brute-force
    - Kerberoast
    - ASREProast
    - Pass the Key/Over Pass the Hash
    - Pass the Ticket
    - Golden/Silver ticket
    - Kerberos Across domains
    - SID History attack
    - Inter-realm TGT
    - Kerberos Delegation
    - Kerberos Anti Delegation Measures
    - Kerberos Unconstrained Delegation
	- Kerberos Unconstrained Delegation across forests
    - Kerberos Constrained Delegation
	- S4U2proxy
	- S4U2self
	- S4U2self and S4U2proxy
	- S4U attacks
- Logon types
  - Interactive logon
  - Network logon
  - Batch logon
  - Service logon
  - NetworkCleartext logon
  - NewCredentials logon
  - RemoteInteractive logon

## Authorization
- ACLs
  - Security descriptor
  - ACEs
  - Rights
  - ACL attacks
    - AdminSDHolder
  - Privileges

## Group Policy
- GPO Scope
- Group Policy template
- Group Policy container

## Communication Protocols
- SMB
- Shares
  - Default shares
  - Default domain shares
- Named pipes
- HTTP
- RPC
  - RPC over SMB
  - RPC over TCP
- WinRM
- Powershell remoting
  - Trusted Hosts
- SSH
  - SSH tunneling
- RDP

## Microsoft extras
- ADCS
- LAPS
- Exchange
- SQL Server

## Recommended resources

