---
title: "4. Scanning and Host Discovery"
order: 4
part: "Reconnaissance & Scanning"
description: "Host discovery, Nmap scan types and port states, service/OS detection, NSE, timing, firewall/IDS evasion and output formats."
---

The core logic of scanning: **the response (or lack of response) to a packet reveals the target's state.** In TCP, flag combinations (SYN, ACK, RST, FIN...) produce specific responses per RFC 793; nmap interprets those responses. So you should think of scan types as "which packet it sends, and how it decides based on which response."

## 4.1 Host discovery (ping sweep): who is alive?

Before you start port scanning, finding out which hosts are up both saves time and reduces noise. By default (when running as root) nmap sends four different discovery probes to each target: ICMP echo request, TCP SYN :443, TCP ACK :80 and ICMP timestamp. If a response comes back to any of these, the host is counted as "up". You can also choose the discovery method yourself with the `-P*` flags:

```
nmap -sn 10.10.10.0/24                 # ping sweep, does NOT port scan (only checks if hosts are alive)
nmap -sn -PE -PP -PM 10.10.10.0/24     # ICMP echo (-PE) + timestamp (-PP) + netmask (-PM)
nmap -sn -PS22,80,443 10.10.10.0/24    # TCP SYN ping belirtilen portlara
nmap -sn -PA80 10.10.10.0/24           # TCP ACK ping (can give a different result than SYN on a stateful firewall)
nmap -sn -PU53 10.10.10.0/24           # UDP ping (on a network with an open UDP port such as 53/DNS)
nmap -sn -PY132 10.10.10.0/24          # SCTP INIT ping
nmap -sn -PO 10.10.10.0/24             # IP protocol ping
nmap -sn -PR 10.10.10.0/24             # ARP ping (automatic on local segment; most reliable)
fping -a -g 10.10.10.0/24 2>/dev/null  # alternative fast ICMP ping sweep (-a: print only live hosts)
arp-scan -l                            # local network, Layer 2; most reliable on the same segment
netdiscover -r 10.10.10.0/24           # passive/active ARP discovery
```

Discovery probe types and why each is needed:

| Flag | Probe type | When it helps |
| --- | --- | --- |
| `-PE` | ICMP echo request (type 8) | Classic ping; many networks block ICMP echo |
| `-PP` | ICMP timestamp (type 13) | If echo is blocked, timestamp is sometimes left open |
| `-PM` | ICMP address mask (type 17) | Old devices; last resort on a network where echo/timestamp are blocked |
| `-PS<port>` | TCP SYN ping | If SYN/ACK or RST comes back, the host is alive (passes a stateful firewall) |
| `-PA<port>` | TCP ACK ping | A stateless firewall thinks it is an established connection and returns RST, meaning the host is alive |
| `-PU<port>` | UDP ping | ICMP port unreachable from a closed UDP port means the host is alive |
| `-PY<port>` | SCTP INIT ping | Telecom/signaling networks that use SCTP |
| `-PR` | ARP ping | On the same L2 segment; independent of ICMP, cannot be evaded |
| `-PO<proto>` | IP protocol ping | Looks for a response to specific protocols (ICMP, IGMP, IP-in-IP) |

Never confuse the two extreme flags:

- **`-sn`** = "no port scan": DO host discovery, but do NOT port scan. (formerly `-sP`).
- **`-Pn`** = "no ping": SKIP host discovery, assume every target is alive and port-scan directly. On a target where ICMP and all discovery probes are blocked it is **essential**; otherwise nmap thinks the host is "down" and never scans it.

**Why is ARP the most reliable?** To send a packet to an IP on the same local network (L2), the MAC address must first be resolved with ARP. Even if the host firewall blocks ICMP, it must respond to ARP (otherwise it cannot communicate on the network). So even if you pass `-sn` on a local segment, nmap uses ARP automatically; you can turn it off with `--disable-arp-ping`.

**Note:** `-sn` does host discovery but no port scan; `-Pn` is the opposite, it skips discovery. If no ports show up on an ICMP-blocked target, your first reflex should be to add `-Pn`. On the same segment the most reliable discovery is ARP (`-PR` / `arp-scan`).

**Detection/Defense:** Ping sweeps and ICMP scanning are easily caught by an IDS (Snort/Suricata ICMP sweep signatures). ARP scanning is detected with `arpwatch`/`arpalert`, and heavy ICMP with netflow/IDS. For defense, rate-limit ICMP echo, but blocking only ICMP does not stop scanning (TCP/ARP discovery still works).

## 4.2 TCP basics: the "why" of scan types

The TCP three-way handshake: the client sends **SYN**, the server returns **SYN/ACK** on an open port, and the client completes the connection with **ACK**. On a closed port the server returns **RST**. Nmap's TCP scan types exploit this behavior:

- **SYN** to an open port: SYN/ACK comes back.
- **SYN** to a closed port: RST comes back.
- **FIN/NULL/Xmas** (a packet without SYN) to an open port on a stack that follows RFC 793: no response comes back (the port is assumed open).
- **FIN/NULL/Xmas** to a closed port: RST comes back.
- **ACK** to any port: RST comes back as if there is no established connection (or nothing comes back if it is filtered). So an ACK scan shows not whether the port is open/closed, but whether the firewall lets the packet through.

These differences form the basis of the scan-type table in the next section.

## 4.3 Nmap scan types (ALL of them: memorize)

| Flag | Type | What it sends | Open-port response | Closed-port response | Note / when |
| --- | --- | --- | --- | --- | --- |
| `-sS` | TCP SYN (half-open) | SYN | SYN/ACK | RST | **Default** (when root). Fast, relatively quiet; does not complete the handshake (sends RST) |
| `-sT` | TCP Connect | full 3-way handshake | connection is established | RST | No root needed; uses the OS `connect()` call; noisy, logged on the target |
| `-sU` | UDP | empty UDP (or protocol-specific) | response or silence | ICMP port unreachable (type 3 code 3) | Slow; no response means `open\|filtered` |
| `-sA` | TCP ACK | ACK | RST (unfiltered) | RST (unfiltered) | Does NOT say whether the port is open/closed; maps the firewall rule (filtered or unfiltered) |
| `-sW` | TCP Window | ACK | RST (TCP window ≠ 0 → open) | RST (window = 0 → closed) | A more advanced ACK scan; on some systems it infers open/closed from the window field in the RST |
| `-sN` | TCP NULL | no flags at all | no response | RST | Stateless firewall evasion; reliable only on RFC-compliant stacks |
| `-sF` | TCP FIN | FIN | no response | RST | Same logic; FIN passes some packet filters |
| `-sX` | TCP Xmas | FIN+PSH+URG | no response | RST | "Christmas tree" (flags lit up); same stateless evasion |
| `-sM` | TCP Maimon | FIN/ACK | (on some BSD) no response | RST | Rare; reveals an open port on old BSD stacks |
| `-sY` | SCTP INIT | INIT chunk | INIT-ACK | ABORT | SCTP equivalent of the SYN scan (half-open) |
| `-sZ` | SCTP COOKIE-ECHO | COOKIE-ECHO | silence | ABORT | Quieter in SCTP; detects an open port from the silence |
| `-sO` | IP protocol | raw IP with no header | protocol response / silence | ICMP protocol unreachable | Finds not ports but which IP protocols (TCP/UDP/ICMP/SCTP...) are supported |
| `-sI <zombie>` | Idle (zombie) | spoofed SYN | (indirect) | (indirect) | Scans without ever revealing your source IP (see 4.9) |
| `-b <ftp>` | FTP bounce | FTP PORT command | n/a | n/a | Indirect scan through an old FTP server (disabled on most servers) |

**Windows/NULL/FIN/Xmas limitation:** These scans assume RST on a closed port and silence on an open one. However, Microsoft Windows (and Cisco IOS, many devices) does not follow the RFC and returns RST on an open port too, so these types show every port as "closed" on Windows targets. That is why you should prefer SYN/Connect on Windows networks.

**Note:** A "stealth / half-open" scan = **`-sS`**. Without root, nmap automatically falls back to **`-sT`** (it cannot craft raw packets). To understand the firewall rule (filtered vs unfiltered), use **`-sA`**. SCTP INIT = **`-sY`**. NULL/FIN/Xmas do not work on Windows (everything comes out closed). `-sO` scans protocols, not ports.

## 4.4 Port states (full definition)

Nmap places a port in one of six states. These states describe not the essence of the port but **how nmap sees it**:

| State | Meaning | How it arises |  |
| --- | --- | --- | --- |
| **open** | An application is listening for connections/packets on that port | SYN/ACK came back in a SYN scan |  |
| **closed** | The port is reachable but no application is listening (it could open at any moment) | RST came back |  |
| **filtered** | A firewall/filter is blocking the packet; nmap cannot tell whether it is open or closed | no response or ICMP unreachable (admin prohibited) |  |
| **unfiltered** | The port is reachable but open/closed is undetermined | **Only an ACK scan** produces this state (RST came back but the state did not resolve) |  |
| **open\ | filtered** | Cannot distinguish open from filtered (mostly no response) | Typical in UDP and NULL/FIN/Xmas: no response |
| **closed\ | filtered** | Cannot distinguish closed from filtered | **Only an idle (IP ID) scan** produces this state |

Memorize: `unfiltered` is seen only with `-sA`; `closed|filtered` only with `-sI` (idle). `open|filtered` is the classic output of UDP and flagless scans, where no response dominates.

**Note:** If a port is `filtered`, that means there is a firewall; the open/closed information is hidden. In UDP most ports come out `open|filtered` because an open UDP port often gives no response at all; do not read this as "the port is closed".

**Detection/Defense:** A default-deny firewall rule reduces information leakage by making scanned ports `filtered`. Silently dropping packets instead of sending RST (DROP, not REJECT) gives the attacker the least information.

## 4.5 Service, version and OS detection

```
nmap -sV 10.10.10.10                   # service/version detection (banner + probe database)
nmap -sV --version-intensity 9 IP      # most aggressive version detection (0=light, 9=all probes)
nmap -sV --version-light IP            # = --version-intensity 2 (fast, slightly less accurate)
nmap -sV --version-all IP              # = --version-intensity 9
nmap -O 10.10.10.10                    # OS fingerprinting (TCP/IP stack behavior)
nmap -O --osscan-guess IP              # force closest guesses when not certain (= --fuzzy)
nmap -O --osscan-limit IP              # only attempt OS detection on hosts with at least 1 open + 1 closed port
nmap -A 10.10.10.10                    # agresif: -sV + -O + -sC (default script) + traceroute
nmap -sV -O --script banner IP         # grab the banner separately
```

- **`-sV` intensity:** 0 to 9, **default 7**. Nmap sends the probes in the `nmap-service-probes` file according to the "rarity" level up to the intensity value. Higher intensity = more probes = more definitive detection but slower and noisier. `--version-light` (2) is for a fast scan; `--version-all` (9) for stubborn services.
- **`-O` accuracy:** Nmap sends a series of TCP/IP probes and matches the responses against `nmap-os-db` signatures. For an accurate guess it needs at least **one open and one closed TCP port**. If there is no exact match, it gives "Aggressive OS guesses" and a percentage; `--osscan-guess` forces these guesses. NAT, firewalls and virtualization can mislead OS detection.

**Note:** The `-sV` intensity default is **7**; `--version-all` = 9, `--version-light` = 2. `-A` alone means `-sV + -O + -sC + traceroute`, so you do not need to write them separately, but it is very noisy.

**Detection/Defense:** Version detection sends many connections/probes to the target, so an IDS catches the "version probe" pattern. Hiding the banner (e.g. `ServerTokens Prod` in Apache) and concealing service versions makes version detection harder (but the port still appears open).

## 4.6 NSE (Nmap Scripting Engine)

NSE turns nmap into a discovery/vulnerability/exploit tool through Lua scripts. The scripts live under `/usr/share/nmap/scripts/`; each belongs to one or more **categories**.

```
nmap -sC 10.10.10.10                   # default script set (= --script=default)
nmap --script=vuln 10.10.10.10         # all vulnerability category scripts
nmap --script=smb-vuln* -p445 IP       # check for MS17-010 (EternalBlue), MS08-067, etc.
nmap --script "http-enum" -p80 IP      # web directory/application discovery
nmap --script "default and safe" IP    # boolean selection (intersection of two categories)
nmap --script "(discovery or safe) and not broadcast" IP
nmap --script smb-os-discovery -p445 IP
nmap --script ssl-enum-ciphers -p443 IP   # TLS cipher/version check
nmap --script-help smb-vuln-ms17-010      # read what the script does
nmap --script-updatedb                     # update the script database
nmap --script=exploit --script-args=... IP
```

NSE categories (the official 15 categories):

| Category | What it does |
| --- | --- |
| `auth` | Authentication bypass / information (e.g. anonymous FTP) |
| `broadcast` | Discovers hosts on the network via broadcast |
| `brute` | Brute-force credential attempts (noisy) |
| `default` | The safe/fast/useful default set that runs with `-sC` |
| `discovery` | Gathers more information about the service/network |
| `dos` | Denial-of-service test (caution: can take the target down) |
| `exploit` | Actively exploits the vulnerability |
| `external` | Sends data to a third-party service (e.g. whois); privacy risk |
| `fuzzer` | Service fuzzing with unexpected inputs |
| `info` | Informational output |
| `intrusive` | Aggressive; can disrupt the target or raise alarms |
| `malware` | Looks for backdoors / traces of malware |
| `safe` | Scripts that do not harm or exploit the target |
| `version` | Version-detection scripts that extend `-sV` |
| `vuln` | Checks for known vulnerabilities (without exploiting) |

**Note:** `-sC` = `--script=default`, exactly the same thing. `vuln` checks for a vulnerability but (mostly) does not exploit it; `exploit` exploits. The `intrusive`/`dos`/`brute` categories can harm the target; do not run them on an out-of-scope system.

## 4.7 Practical scanning workflow

If time is limited, memorize this flow: **first a fast all-port scan, then a deep scan of only the open ports.**

```
# 0) Who is alive on the network?
nmap -sn 10.10.10.0/24 -oA hosts

# 1) FAST: quickly scan all 65535 TCP ports (just which are open?)
nmap -p- --min-rate 1000 -T4 -Pn -oA allports 10.10.10.10

# 2) DEEP: version + default scripts + OS only on the open ports found in step 1
nmap -p 22,80,445 -sV -sC -O -oA deep 10.10.10.10

# 3) UDP (slow) - only the most common ports
nmap -sU --top-ports 100 -T4 -oA udp 10.10.10.10

# 4) Targeted vulnerability script
nmap --script vuln -p 80,445 -oA vuln 10.10.10.10

# Masscan - very large networks / all ports, very fast pre-scan
masscan -p1-65535 10.10.10.0/24 --rate 10000 -oL masscan.out
# a typical flow is to find open ports with masscan, feed the output to nmap, and do version detection
```

**masscan** differs from nmap in that it uses its own TCP/IP stack (asynchronous), so it can send millions of packets per second. The default rate is only **100 packets/sec**; you increase it with `--rate`. Important flags:

| Flag | Meaning |
| --- | --- |
| `-p1-65535` / `-p80,443,U:53` | Port range; the `U:` prefix means UDP |
| `--rate 10000` | Packets per second (a high value triggers an IDS / can saturate the network) |
| `--banners` | Grab banners (limited protocols) |
| `--excludefile ex.txt` | Exclude out-of-scope IPs (overrides targets; critical for safety) |
| `-oL / -oJ / -oX / -oG` | List / JSON / XML / grepable output |
| `--open` | Print only open ports |
| `-e <iface>` / `--router-ip` | Interface / gateway (may be needed since it uses its own stack) |

**Note:** `-oA basename` writes all three formats at once: `.nmap` (human-readable), `.gnmap` (grepable, `grep open`), `.xml` (for tools: Metasploit `db_import`, searchsploit `--nmap`). masscan is for sweeping huge networks within seconds; then run a second pass with nmap for precise version/script detection.

**Detection/Defense:** A high-`--rate` masscan scan instantly triggers network IDS/IPS and rate-based alarms. The blue team sees a sudden burst of connections in netflow, a large number of SYNs, and sequential port attempts from the same source (Snort `sfportscan`, Suricata, Zeek `scan.log`).

## 4.8 Timing (-T) and speed control

Scan speed determines both the duration and the risk of being caught. There are six templates:

| Template | Name | Behavior | When |
| --- | --- | --- | --- |
| `-T0` | Paranoid | Serial (one probe at a time), ~5 min delay between probes | IDS avoidance, extremely slow |
| `-T1` | Sneaky | ~15 sec between probes | Low profile |
| `-T2` | Polite | ~0.4 sec between probes, bandwidth-friendly | Sensitive network |
| `-T3` | Normal | **Default**, balanced, no delay | Standard |
| `-T4` | Aggressive | Fast; dynamic TCP scan delay ≤10 ms | Internal network (typical lab/pentest) |
| `-T5` | Insane | Fastest; delay ≤5 ms, max-retries drops to 2 | Fast, risk of packet loss/accuracy loss |

Fine-tuning flags (override the template):

```
nmap --min-rate 1000 IP        # at least 1000 packets per second (forces the rate floor)
nmap --max-rate 100 IP         # set a ceiling (limits noise/network load)
nmap --min-parallelism 100 IP  # at least 100 probes at once
nmap --max-retries 2 IP        # at most 2 retries on an unanswered port (faster, lower accuracy)
nmap --scan-delay 5s IP        # fixed delay between each probe (evade rate-based IDS)
nmap --host-timeout 30m IP     # give up on a slow host after a set time
```

**Note:** The default timing is **-T3** (some sources wrongly say T2; do not trust that). `-T0/-T1` are for IDS evasion and take hours. The typical choice on an internal network is `-T4`. Do not rely on `-T` alone to evade an IDS; `--scan-delay` gives more targeted slowdown.

## 4.9 Firewall / IDS evasion

```
nmap -Pn IP                    # skip host discovery (avoids marking an ICMP-blocking target as "down")
nmap -f IP                     # split packets into 8-byte fragments (fragment; signature/filter evasion)
nmap --mtu 16 IP               # custom fragment size (must be a multiple of 8)
nmap -D RND:10 IP              # hide your real IP in the crowd with 10 random decoys (fake sources)
nmap -D 10.0.0.5,ME,10.0.0.9 IP  # manual decoys; ME = position of your real IP
nmap -S <spoofed_ip> -e eth0 IP  # spoof source IP (you won't see the response; -e interface required)
nmap -g 53 IP / --source-port 53 # scan from a trusted source port (53/DNS, 20/FTP-data can bypass FW rules)
nmap --data-length 25 IP       # add random padding to packets (break the fixed-size signature)
nmap --scan-delay 5s -T2 IP    # slow down (evade threshold/rate-based IDS)
nmap --badsum IP               # bozuk TCP/UDP checksum: cevap veren cihaz IDS/IPS'tir (stack atar)
nmap --spoof-mac 0 IP          # spoof MAC address with random/specific vendor (L2)
nmap -sI <zombie>:port IP      # idle (zombie) scan - scan without EVER revealing your source IP
```

**Decoy (-D) mechanism:** Nmap sends the scan packets so they appear to come from many fake source IPs along with your real IP. In the target's log 11 different "scanners" appear, and which one is real becomes unclear. But **even with a decoy, packets go out from your real IP** (so you can receive the responses); it is not full concealment.

**Idle / zombie scan (-sI), the only scan that never reveals your source:** The mechanism uses a "quiet" third host (the zombie) that assigns a global **IP ID** (a single counter for all traffic):

1. The attacker sends SYN/ACK to the zombie; since the zombie did not expect it, it returns RST, and the **IP ID** value of that RST is read (e.g. 1000).
2. The attacker sends the target a SYN whose **source appears to be the zombie (spoofed)**.

- If the target port is **open**: the target returns SYN/ACK to the zombie; since the zombie did not expect this, it sends RST to the target, so the zombie's IP ID **increases by 1**.
- If the target port is **closed/filtered**: the target returns RST to the zombie (or gives no response at all); the zombie sends nothing, so the IP ID **does not increase**.

1. The attacker sends SYN/ACK to the zombie again and reads the new IP ID.

- If the IP ID has increased by **+2** (one step from the zombie, one from this probe): the target port is **open**.
- If the IP ID has increased by **+1**: the port is **closed/filtered** (this is why an idle scan produces the `closed|filtered` state).

To find a good zombie, its IP ID must be "Incremental"; find it via "IP ID Sequence Generation: Incremental" in the `nmap -O -v <zombie>` output, or with `--script ipidseq`. The zombie must stay quiet throughout the scan (if there is traffic, the IP ID increases irregularly and the result is corrupted).

**Note:** The only method that scans without revealing your source IP **at all** is the **idle/zombie scan (`-sI`)**; a decoy (`-D`) still leaks packets from your real IP. With `-g 53` you can get past firewalls that have a "trusted port" rule. A device that responds to `--badsum` is most likely an IDS/IPS (a normal stack silently discards a bad checksum).

**Detection/Defense:** Fragmented packets (`-f`) and abnormal flag combinations trigger IDS signatures; modern IPS reassembles fragments and matches signatures. Even though a decoy scan shows many sources in the log, it is resolved with netflow correlation and anti-spoofing (uRPF). Defense against an idle scan: configure hosts that could serve as zombies so they do not assign a global IP ID, and apply egress/ingress filtering.

## 4.10 Output formats

```
nmap -oN out.nmap IP     # Normal (insan-okur)
nmap -oG out.gnmap IP    # Grepable: filter open ports with 'grep open out.gnmap'
nmap -oX out.xml IP      # XML: Metasploit db_import, searchsploit --nmap, raporlama
nmap -oS out.skid IP     # "script kiddie" (for fun)
nmap -oA basename IP      # All three at once (.nmap .gnmap .xml)
nmap -v / -vv IP          # verbosity level (live progress)
nmap --resume out.gnmap   # resume an interrupted scan
nmap --append-output IP   # append output instead of overwriting
```

Port range selection:

```
nmap -p 80,443 IP          # belirli portlar
nmap -p 1-1000 IP          # range
nmap -p- IP                # all 65535 TCP ports
nmap -F IP                 # fast: 100 most common ports
nmap --top-ports 20 IP     # N most common ports
nmap -p U:53,T:80,443 IP   # protokol belirterek (U:/T:)
nmap -p http,https IP      # by service name
```

## 4.11 Result analysis

You are expected to interpret the output. Analysis framework:

- **open** = a service is listening; get the version information and match it to a CVE (see Section 5). The attack surface starts here.
- **filtered** = a firewall is blocking; the state is uncertain. Map the firewall rule set (which ports pass as unfiltered) with `-sA`.
- **open|filtered** (UDP / NULL-FIN-Xmas) = no response; do not read it as "closed", it is uncertain. In UDP, clarify it with a service-specific probe (`-sUV`).
- **closed|filtered** = only in an idle scan; whether it is closed or filtered is uncertain.
- For an OS guess, look at the **confidence percentage** ("Aggressive OS guesses: ... 95%"). Version detection is not definitive; the banner may have been manually altered (faked).

**TTL / OS hint (on a ping or any response):** The OS is guessed by working the response packet's TTL back from its initial value:

| Initial TTL | Likely OS/device |
| --- | --- |
| ~64 | Linux / Unix / macOS |
| ~128 | Windows |
| ~255 | Network device (Cisco IOS, router, some Unix) |

If the observed TTL is smaller than the initial value, each router in between decreases it by 1; e.g. if you see TTL 60, it is probably 64 to start (Linux) and 4 hops away. This is not definitive but it is a quick hint.

**Common mistakes (summary):**

- "Stealth / half-open" = **`-sS`**; without root, nmap falls back to **`-sT`**.
- For the firewall rule (filtered vs unfiltered), **`-sA`**; its advanced form is **`-sW`**.
- If no ports show up on an ICMP-blocked target, add **`-Pn`** first.
- UDP is slow; target it with `--top-ports` / `-sU`, and do not assume `open|filtered` is "open".
- `-sC` = `--script=default`.
- The `-sV` intensity default is **7**.
- The only scan that never reveals the source is **idle/zombie (`-sI`)**.
- TTL ~64 Linux, ~128 Windows, ~255 network device.
- NULL/FIN/Xmas show all ports as "closed" on Windows; do not use them.
