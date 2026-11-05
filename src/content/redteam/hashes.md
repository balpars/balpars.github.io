---
title: "9. Password Formats and Hashes"
order: 9
part: "Password & Hash Attacks"
description: "Hash, salt and formats; Windows and Linux hashes; recognizing a hash and its matching hashcat mode."
---

## 9.1 Hash, salt and why

A **hash** is a one-way function: it produces a fixed-length digest from a password and is mathematically irreversible. Verification works like this: when you enter the password, the system hashes it with the same algorithm and **compares it against the stored hash**; if they match, login is accepted. The system never stores your plaintext password (in a good design). Once an attacker obtains the hash, they crack the password **by guessing and hashing and comparing** (offline), because "unlocking" the hash itself is impossible; the only way is to try candidates until the right password is found.

**Why not just a hash, but a strong hash?** Fast hashes like MD5/SHA1 can be tried billions of times per second on a GPU -> a weak password falls in seconds. That is why password storage uses **slow, iterated, memory-hard** functions (bcrypt, scrypt, yescrypt, Argon2, sha512crypt): deliberate slowness makes offline cracking costly.

**Salt:** a random value added to each password and stored together with the hash. The same password with a different salt produces a completely different hash. Two benefits:

1. Makes precomputed **rainbow tables** useless (the table must be recomputed for a specific salt -> not economical).
2. Two users with the same password do not get the same hash -> it breaks the "same hash = same password" inference and bulk cracking.

**Rainbow table:** a huge precomputed table of password->hash mappings with a space-time trade-off (chains). For unsalted, fast hashes (LM, unsalted NTLM/MD5) it lets you look up a hash in the table and find the password instantly. **Salt kills the rainbow table**; an unsalted hash makes it possible.

**Critical point:** The Windows **NT hash is unsalted** -> which is why (a) the same password is the same NT hash everywhere, (b) Pass-the-Hash (using the hash in place of the password) is possible, (c) in theory a rainbow table/bulk cracking is applicable. Linux `crypt` hashes (`$1$`...`$6$`...`$y$`) are **salted**.

**Note:** Salt does *not* slow down cracking (brute/dictionary): you still try each hash one by one. The job of salt is to prevent **precomputation (rainbow table) and bulk/multiplexed attacks**. The statement "salt stops offline cracking" is wrong.

## 9.2 Windows hashes

**LM (LAN Manager) hash, why it is very weak:** The password storage form of very old Windows. The algorithm is deliberately weak:

1. The password is converted **entirely to UPPERCASE** (no case distinction -> the key space shrinks).
2. It is fixed at **14 characters** (the excess is discarded) and split into two parts, **7+7**.
3. Each 7-character half is used **separately** as a DES key -> it encrypts a fixed string.
4. The two 8-byte outputs are concatenated.

Weakness: each half is cracked independently (the 7-character space is small), the uppercase conversion narrows the space, and an 8+ character password drops into two easy parts. On modern Windows, LM is **disabled by default**. The empty/disabled LM value is fixed: `aad3b435b51404eeaad3b435b51404ee`. Hashcat mode **3000**.

**NT hash (NTLM hash):** `MD4(UTF-16LE(password))`: the password is first converted to UTF-16LE, then a single round of MD4. **Unsalted** and **fast** (single round -> cracked very quickly on a GPU). The real password storage form of Windows (SAM / NTDS.dit). Because it is unsalted, **Pass-the-Hash** (authenticating by using the hash like a plaintext password) is possible. Hashcat mode **1000**.

`pwdump` / secretsdump output format (the line you see in a hash dump):

```
username:RID:LMhash:NThash:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

- `500` = built-in Administrator RID; `501` = Guest.
- `aad3b4...` (the LM field) = **LM disabled/empty** (means there is no LM).
- `31d6cfe0d16ae931b73c59d7e0c089c0` = **the NT hash of an empty password** (when you see this value, the account has no/empty password).

To crack, take only the NT hash column from this file (mode 1000). For PtH you give the whole `LM:NT` pair to the tools (see Section 10/13).

**NetNTLMv1 / NetNTLMv2 (over-the-network challenge/response):** These are **NOT a stored hash**; they are the **challenge/response** values that pass over the network during NTLM authentication. The server sends a challenge (random), the client computes a response (HMAC) with the NT hash. Responder/Inveigh (LLMNR/NBT-NS poisoning) captures these. **Pass-the-Hash CANNOT be done** (the response depends on the challenge, it cannot be replayed/reused), but they **can be cracked offline** (until the plaintext password is found). Formats:

```
# NetNTLMv2 (mod 5600)
user::DOMAIN:serverchallenge:HMAC-MD5:blob
# NetNTLMv1 (mod 5500)
user::hostname:LMresp:NTresp:challenge
```

NetNTLMv1 is weak (DES-based); if captured, it can be reduced to an NT hash with services like `crack.sh` and then turned into PtH, which is why a downgrade attack from v1 to v2 is important.

| Windows type | Salted? | PtH? | Source | Hashcat mode |
| --- | --- | --- | --- | --- |
| LM | no | (partial) | SAM/NTDS | **3000** |
| NT (NTLM) | **no** | **yes** | SAM/NTDS | **1000** |
| NetNTLMv1 | challenge | **no** | network (Responder) | **5500** |
| NetNTLMv2 | challenge | **no** | network (Responder) | **5600** |
| DCC (MS Cache v1) | yes | no | local registry | **1100** |
| DCC2 (MS Cache v2) | yes | no | local registry | **2100** |

**Cached domain credentials (DCC / DCC2, MSCache v1/v2):** The cached verifier of the last successful domain logon, kept to allow local logon when the Domain Controller cannot be reached (e.g. a laptop at home) (`HKLM\SECURITY\Cache`). It is **offline**, **cannot be PtH'd** (it is not an NT hash but a derived value), and deliberately **slow** (DCC2 = PBKDF2-SHA1, 10240 iterations) -> very slow to crack. DCC v1 mode **1100**, DCC2 (modern) mode **2100**.

**Kerberos hash formats (AD):**

| Appearance | Attack | Hashcat mode |
| --- | --- | --- |
| `$krb5tgs$23$...` | Kerberoasting (RC4/etype 23) | **13100** |
| `$krb5tgs$17$...` | Kerberoasting (AES128/etype 17) | **19600** |
| `$krb5tgs$18$...` | Kerberoasting (AES256/etype 18) | **19700** |
| `$krb5asrep$23$...` | AS-REP roasting (etype 23) | **18200** |
| `$krb5pa$...` / AS-REQ | AS-REQ Pre-Auth (etype 23) | **7500** |

Kerberos attack details (Kerberoasting, AS-REP roasting, SPN logic) are in Section 13; here only **recognizing the hash format** and the mode mapping matter. The AES modes (19600/19700) are cracked **much more slowly** than RC4 (13100): request an RC4 ticket if possible.

**Detection/Defense:** NTLM/NetNTLM capture (Responder) happens via LLMNR/NBT-NS poisoning on the network -> defense: **disable LLMNR and NBT-NS**, **enforce SMB signing** (stops relay). Kerberoast detection: Event 4769 (TGS requested) + an anomaly in **RC4 (etype 0x17)** ticket requests. Give service accounts a **long, random password** (gMSA) -> offline cracking becomes practically impossible.

## 9.3 Linux hashes (`/etc/shadow`)

Format (modular crypt): `user:$id$[parameter]$salt$hash:lastchg:min:max:warn:...`. The leading `$id$` tells the algorithm:

| Prefix | Algorithm | Note | Hashcat mode |
| --- | --- | --- | --- |
| `$1$` | md5crypt | old, weak | **500** |
| `$2a$`,`$2b$`,`$2y$` | bcrypt (Blowfish) | slow, strong; `$2y$` has a cost | **3200** |
| `$5$` | sha256crypt | has a `rounds=` parameter | **7400** |
| `$6$` | sha512crypt | common default on modern Linux | **1800** |
| `$y$` | yescrypt | default on Debian 12 / Ubuntu 24.04; memory-hard | not in hashcat -> crack with **John the Ripper** |
| `$7$` | scrypt | memory-hard | **8900** |
| `$gy$` | gost-yescrypt | rare | John the Ripper |

If you see a `rounds=` like `$6$rounds=5000$salt$hash`, it is the iteration count (slows cracking). The `10` in `$2y$10$...` is the bcrypt cost factor (2^10 rounds).

**The two-file logic:** `/etc/passwd` lists the users but the password field is now `x` (i.e. "the real hash is in `/etc/shadow`"). `/etc/shadow` holds the hashes and **only root can read it**. Hashcat/John sometimes want both files; merge them:

```
unshadow /etc/passwd /etc/shadow > crack.txt
# -> john crack.txt  or  hashcat -m 1800 crack.txt ... (extract the hash from the line)
```

**Note:** `$6$` = sha512crypt (**mode 1800**), `$1$` = md5crypt (**500**), `$5$` = sha256crypt (**7400**), bcrypt `$2*$` (**3200**). Because `$y$` (yescrypt) is the default on modern distributions and is memory-hard, it cannot be cracked efficiently on a GPU; depending on the hashcat version it may not be supported -> use John the Ripper.

## 9.4 Common application / other hashes

| Appearance / example | Length / hint | Type | Hashcat mode |
| --- | --- | --- | --- |
| `8743b52063cd84097a65d1633f5c74f5` | 32 hex | MD5 **or** NTLM (distinguish by context) | **0** / **1000** |
| `b89eaac7e61417341b710b727768294d0e6a277b` | 40 hex | SHA1 | **100** |
| `a1b2...` (64 hex) | 64 hex | SHA256 | **1400** |
| 128 hex | 128 hex | SHA512 | **1700** |
| `$P$B...` / `$H$...` | `$P$`/`$H$` prefix | phpass (WordPress, Joomla, phpBB) | **400** |
| `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` | `*`+41 hex (UPPERCASE) | MySQL 4.1+/5 (double SHA1) | **300** |
| `606717...` (16 hex) | 16 hex | MySQL old (`<4.1`) | **200** |
| `$apr1$...` | `$apr1$` prefix | Apache md5 (htpasswd / .htaccess) | **1600** |
| `{SSHA}base64...` | `{SSHA}` + base64 | LDAP / OpenLDAP salted SHA1 | **111** |
| `{SHA}base64...` | `{SHA}` + base64 | LDAP SHA1 (unsalted) | **101** |
| `$2y$10$...` | bcrypt prefix | bcrypt (web framework password storage) | **3200** |
| `eyJhbGci...` three parts with dots | `eyJ` + 2x `.` | JWT (JSON Web Token) | **16500** |
| `WPA*02*...` / `.hc22000` | hashcat 22000 format | WPA/WPA2 (PMKID+EAPOL) | **22000** |
| `$krb5tgs$` / `$krb5asrep$` | `$krb5...` prefix | Kerberos (see 9.2) | 13100 / 18200 |
| `$1$`,`$5$`,`$6$`,`$2y$`,`$y$` | `$...$` crypt | Linux shadow (see 9.3) | 500/7400/1800/3200 |

Notes: `MD5` and unsalted `NTLM` are both **32 hex** -> telling them apart is done by **context** (is it a Windows SAM dump or a web DB dump). MySQL 4.1+ starts with `*` and is 41 characters. WPA is now cracked with the **22000** format (`hcxtools` -> `.hc22000`) instead of the old `hccapx`/2500.

## 9.5 Recognizing the hash type (automatic + by reasoning)

```
# Automatic recognition tools
hashid '$6$xyz$abc...'              # algorithm + likely hashcat mode (-m) from prefix/pattern
hashid -m '<hash>'                  # also suggests the hashcat mode number directly
hash-identifier                      # interactive (paste the hash, gives a guess list)
haiti '<hash>'                       # modern, accurate; shows hashcat/john mode
name-that-hash -t '<hash>'           # nth; colored, distinguishes most likely/least likely
nth --text '<hash>'                  # short form for name-that-hash
hashcat --identify '<hash>'          # hashcat's own identifier (depends on version)
```

**Recognizing by reasoning (if there is no tool / if it is ambiguous), length + prefix + character set:**

- **Is there a `$...$` prefix?** If so, it is almost certainly a crypt/application format -> match the prefix against the table (`$1$`,`$6$`,`$2y$`,`$P$`,`$apr1$`,`$krb5...`).
- **Is there `{...}`?** -> LDAP (`{SSHA}`, `{SHA}`).
- **Is it only hex, and what length?** 16->MySQL old/DES; 32->MD5/NTLM; 40->SHA1; 56->SHA224; 64->SHA256; 96->SHA384; 128->SHA512.
- **41 hex (uppercase) starting with `*`** -> MySQL 4.1+.
- **Starts with `eyJ` and has two dots** -> JWT.
- **`user:RID:LM:NT:::`** line pattern -> Windows pwdump (NT = mode 1000).
- **Separated by dots/colons, containing `::DOMAIN:`** -> NetNTLM (v2 = 5600).

**Common mistakes:**

- The NT hash is **unsalted** -> PtH and (in theory) a rainbow table are possible. NetNTLMv1/v2 **cannot be PtH'd**, only cracked.
- `aad3b435b51404eeaad3b435b51404ee` = empty/disabled **LM** hash (when you see it, it means "no LM").
- `31d6cfe0d16ae931b73c59d7e0c089c0` = **the NT hash of an empty password**.
- 32 hex on its own can be MD5 **or** NTLM: look at context (Windows dump -> NTLM/mode 1000, web DB -> MD5/mode 0).
- `$6$` = sha512crypt (**1800**), `$1$` = md5crypt (**500**), `$5$` = sha256crypt (**7400**), bcrypt `$2*$` (**3200**), `$y$` = yescrypt (may not be supported in hashcat -> John).
- Kerberoast = `$krb5tgs$` (RC4 **13100**, AES **19600/19700**), AS-REP = `$krb5asrep$` (**18200**).
- MySQL 4.1+ `*`+41 hex (**300**); phpass/WordPress `$P$`/`$H$` (**400**); LDAP `{SSHA}` (**111**); JWT `eyJ...` (**16500**); WPA2 (**22000**).
