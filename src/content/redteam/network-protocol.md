---
title: "2. Network and Protocol Fundamentals"
order: 2
part: "Planning & Fundamentals"
description: "TCP/IP and OSI, the TCP handshake, Nmap scan logic, the ports you must know, subnetting, SMB, DNS, Kerberos and NTLM."
---

The whole of a penetration test happens over the network. If you do not know ports, protocols, and handshakes, you cannot interpret an nmap output, a Wireshark capture, or why an attack works. This section builds the foundation; the tooling/technique detail of scanning (nmap timing, NSE, output format) is in Section 4, and the deep workings of Windows authentication are in Section 13; here there is only the **protocol foundation** needed for those topics to settle in.

## 2.1 TCP/IP and OSI layers

The OSI 7 layers (top to bottom) and TCP/IP's practical 4 layers map onto each other. Knowing the layer answers the question "where does this attack happen": ARP spoofing L2, IP spoofing L3, SYN flood L4, SQL injection L7.

| OSI layer | TCP/IP | Unit (PDU) | Example protocol/address | Pentest relevance |
| --- | --- | --- | --- | --- |
| 7 Application | Application | Data | HTTP, DNS, SMB, LDAP | Web/service attacks |
| 6 Presentation | Application | Data | TLS/SSL, encryption, encoding | TLS vulnerability |
| 5 Session | Application | Data | RPC, NetBIOS session | Null session |
| 4 Transport | Transport | Segment (TCP)/Datagram (UDP) | TCP, UDP + port | Port scanning, SYN flood |
| 3 Network | Internet | Packet | IP, ICMP + IP address | Routing, IP spoofing |
| 2 Data Link | Link | Frame | Ethernet, ARP + MAC address | ARP spoofing, VLAN |
| 1 Physical | Link | Bit | Cable, radio | Physical access |

As data travels down, each layer adds its own header (**encapsulation**); on the other side, as it travels up, the headers are stripped off (**decapsulation**). Addressing varies by layer: L2 **MAC** (local network, switch), L3 **IP** (between networks, router), L4 **port** (service on the machine).

- **IP (L3/Internet):** addressing and routing. IPv4 = 32 bit (`192.168.1.10`), IPv6 = 128 bit (`2001:db8::1`). Connectionless, "best effort".
- **TCP (L4):** connection-oriented, reliable, ordered. Established with a 3-way handshake; loss/order is guaranteed via sequence numbers and ACK.
- **UDP (L4):** connectionless, unreliable, fast. No handshake and no delivery guarantee. DNS (queries), SNMP, TFTP, DHCP, SYSLOG, and some VPNs use UDP.

**Note:** Memorize OSI top to bottom (All People Seem To Need Data Processing → Application…Physical). ARP is **L2** (MAC↔IP mapping), ICMP is **L3** (not TCP/UDP, uses no port). A switch is an L2 device, a router an L3 device. Port is an L4 concept, not an IP address.

## 2.2 TCP three-way handshake and flags

TCP establishes every connection with three packets; this mechanism determines the logic of all TCP scanning.

```
Client   → SYN (seq=x)              → Server    (start connection)
Client   ← SYN/ACK (seq=y, ack=x+1) ← Server    (accept + acknowledge)
Client   → ACK (ack=y+1)            → Server    (connection ESTABLISHED)
```

The purpose of the handshake: both sides get the other to acknowledge the initial sequence number (ISN), so packet ordering and loss detection become possible. Closing happens either with a four-packet **FIN/ACK** exchange (graceful) or with a single **RST** (abrupt).

TCP flags (control flags) and their meanings:

| Flag | Name | Meaning |
| --- | --- | --- |
| **SYN** | Synchronize | Start the connection, send ISN |
| **ACK** | Acknowledge | Acknowledge received data/sequence |
| **FIN** | Finish | Data is done, close gracefully |
| **RST** | Reset | Reject/reset the connection (closed port or refusal) |
| **PSH** | Push | Do not buffer, hand the data to the application immediately |
| **URG** | Urgent | Urgent data pointer is valid |

Key behavior (the basis of scanning logic): SYN to an **open** port → SYN/ACK comes back; any packet to a **closed** port → RST comes back; **filtered** (firewall drop) → no response at all. These three distinct outcomes explain how all the scan types below make their decisions.

**Note:** A closed port replies with **RST**; no response (drop) means **filtered**, not "closed". SYN/ACK = open. The handshake is three packets (SYN, SYN/ACK, ACK), not four; closing is four packets or RST.

## 2.3 The protocol logic of Nmap scan types

The goal here is to understand at the protocol level **why** each scan gives the result it does; scan strategy, timing, NSE scripts, and output interpretation are in Section 4.

| Scan | Flags sent | Open | Closed | Filtered | Notes |  |
| --- | --- | --- | --- | --- | --- | --- |
| **SYN / half-open** `-sS` | SYN | SYN/ACK returned | RST returned | no response | Nmap does not send the ACK, aborts with RST; needs root, fast, default |  |
| **Connect** `-sT` | full handshake | `connect()` succeeds | RST | no response | Uses the OS socket; no root needed; noisy, logged |  |
| **UDP** `-sU` | UDP datagram | no response / service response | ICMP port unreachable (type 3, code 3) | ICMP filtered | Slow, ambiguous (open\ | filtered) |
| **Null** `-sN` | no flags | **open\ | filtered** (no response) | RST | no response | RFC loophole; unreliable on stateful firewalls/Windows |
| **FIN** `-sF` | FIN | **open\ | filtered** (no response) | RST | no response | Bypasses some old filters |
| **Xmas** `-sX` | FIN+PSH+URG | **open\ | filtered** (no response) | RST | no response | Flags lit up like a "Christmas tree" |
| **ACK** `-sA` | ACK | - | - | firewall state | Maps the **firewall rule**, not the port state |  |

**SYN scan (`-sS`)** why it is "stealth": because it does not send the third ACK and never completes the connection, it used to not show up in application-layer logs (half-open). Modern IDS/IPS can still see it.

**Null/FIN/Xmas** logic: per TCP RFC 793, an **open** port should not respond to a "weird" packet that contains no SYN, while a **closed** port should send RST. Nmap uses this rule: if RST comes back, closed; if no response comes, open|filtered. This is why these scans cannot definitively tell open from filtered. Critical: **Windows (and many modern stateful firewalls) violate this RFC**, they send RST even to an open port, so on Windows these scans show all ports as "closed" and mislead you. Their main value: they can bypass certain simple/stateless packet filters.

**ACK scan (`-sA`)** does not say whether a port is open/closed; it sends an ACK packet and figures out whether the firewall is **stateful** or stateless and whether the port is filtered. A stateful firewall drops the unsolicited ACK (port "filtered"), while a stateless/unfiltered path returns RST ("unfiltered"). It is used to map the firewall ruleset.

**Detection/Defense:** Because `-sT` (connect) establishes a full connection on the target, it shows up in application/service logs and connection counters; `-sS` is quieter but a network IDS catches it (the signature of many half-open connections). Defense: port scan detection (e.g. SYN to many different ports), rate-limiting, IPS signatures.

**Note:** `-sS` needs root/raw sockets but is the default; `-sT` does not need root but is noisy. Null/FIN/Xmas **do not work against Windows** (they wrongly show open ports as "closed"), they work on Unix. `-sA` does not give the port **state**, it gives the firewall **state**. In a UDP scan, a closed port = ICMP port unreachable, open = silence.

## 2.4 Ports and protocols you need to know

| Port | Proto | Service | Pentest relevance |
| --- | --- | --- | --- |
| 21 | TCP | FTP | Anonymous login, clear-text credentials |
| 22 | TCP | SSH | Brute, key-based, tunneling |
| 23 | TCP | Telnet | Clear-text, legacy |
| 25 | TCP | SMTP | User enum (VRFY/EXPN), relay |
| 53 | TCP/UDP | DNS | UDP query, **TCP zone transfer (AXFR)**, enum |
| 67/68 | UDP | DHCP | Network information |
| 69 | UDP | TFTP | Unauthenticated file access |
| 80 | TCP | HTTP | Web attacks |
| 88 | TCP/UDP | **Kerberos** | **DC indicator**, AS-REP/Kerberoast (see Section 13) |
| 110/143 | TCP | POP3/IMAP | Mail, clear-text |
| 111 | TCP/UDP | RPCbind | NFS discovery (`rpcinfo`) |
| 123 | UDP | NTP | Time; monlist amplification |
| 135 | TCP | MSRPC | Windows RPC, `rpcclient`, wmiexec |
| 137/138/139 | UDP/UDP/TCP | NetBIOS | Legacy SMB, name resolution, session |
| 161/162 | UDP | SNMP | `snmpwalk`, community string (public) |
| 389 | TCP/UDP | LDAP | AD directory query |
| 443 | TCP | HTTPS | TLS web |
| 445 | TCP | **SMB/CIFS** | Shares, EternalBlue, PtH, relay |
| 464 | TCP/UDP | kpasswd | Kerberos password change |
| 500 | UDP | IKE | IPsec VPN |
| 587 | TCP | SMTP submission | Authenticated mail |
| 636 | TCP | LDAPS | Encrypted LDAP |
| 1433 | TCP | MSSQL | `xp_cmdshell`, `impacket-mssqlclient` |
| 1521 | TCP | Oracle | `odat`, TNS |
| 2049 | TCP | NFS | `showmount`, no_root_squash |
| 3268/3269 | TCP | **Global Catalog** | Forest-wide AD LDAP, DC indicator |
| 3306 | TCP | MySQL | DB attacks |
| 3389 | TCP | RDP | Remote desktop, PtH (`xfreerdp /pth`) |
| 5432 | TCP | PostgreSQL | DB |
| 5985/5986 | TCP | **WinRM** | Remote PowerShell, `evil-winrm` |
| 5900 | TCP | VNC | Remote screen |

**DC (Domain Controller) fingerprint:** If 88 (Kerberos), 389/636 (LDAP/S), 445 (SMB), 135 (RPC), 3268/3269 (GC), and usually 53 (DNS) are open together and the domain name appears in the LDAP banner, the host is most likely a DC.

**Note:** 53 uses both UDP (normal query, smaller than 512 bytes) and TCP (zone transfer and large responses); "DNS is UDP only" is wrong. 139 vs 445: 139 is legacy SMB over NetBIOS, 445 is modern SMB directly over TCP. Kerberos **88**, LDAP **389/636**, GC **3268/3269**; do not mix these up.

## 2.5 Subnetting and CIDR fundamentals

CIDR notation `IP/prefix` tells how many bits of the network are the "network" part; the rest are host bits. Essential for correctly computing the target range (giving nmap `10.10.10.0/24`).

| CIDR | Netmask | Total addresses | Usable hosts | Notes |
| --- | --- | --- | --- | --- |
| /30 | 255.255.255.252 | 4 | 2 | Point-to-point link |
| /29 | 255.255.255.248 | 8 | 6 |  |
| /28 | 255.255.255.240 | 16 | 14 |  |
| /27 | 255.255.255.224 | 32 | 30 |  |
| /26 | 255.255.255.192 | 64 | 62 |  |
| /25 | 255.255.255.128 | 128 | 126 |  |
| /24 | 255.255.255.0 | 256 | 254 | Classic "Class C" |
| /23 | 255.255.254.0 | 512 | 510 | Two /24s |
| /16 | 255.255.0.0 | 65,536 | 65,534 | "Class B" |
| /8 | 255.0.0.0 | 16,777,216 | 16,777,214 | "Class A" |

Usable hosts = total addresses - 2 (the network address + broadcast address are reserved). As the prefix grows by 1 bit (e.g. /24 → /25) the network splits in two and the number of addresses halves. Number of hosts = 2^(32-prefix).

Private (RFC 1918) and special-purpose ranges, not routable on the internet, a sign of an internal network:

| Range | CIDR | Use |
| --- | --- | --- |
| 10.0.0.0 to 10.255.255.255 | 10.0.0.0/8 | Private |
| 172.16.0.0 to 172.31.255.255 | 172.16.0.0/12 | Private |
| 192.168.0.0 to 192.168.255.255 | 192.168.0.0/16 | Private |
| 127.0.0.0/8 | 127.0.0.0/8 | Loopback (localhost) |
| 169.254.0.0/16 | 169.254.0.0/16 | APIPA / link-local (when no DHCP) |

**Note:** A /24 network has **254** usable hosts (not 256; .0 network, .255 broadcast). 172.**16**-172.**31** is private; 172.15 and 172.32 are not. A machine showing a 169.254.x.x address means it **failed to get** an IP from DHCP.

## 2.6 SMB (Server Message Block): the lifeblood of AD

SMB is a file/printer sharing protocol, but it sits at the center of AD attacks: authentication (NTLM/Kerberos), remote command execution (psexec/wmiexec), and hash dumping all flow over SMB. Ports: 139 (legacy, over NetBIOS session) and 445 (modern, directly over TCP).

**SMB versions (dialect).** The version is the highest common dialect that the client and server agree on during the NEGOTIATE phase. For an attacker, the version means which vulnerability (e.g. SMBv1 → EternalBlue) and which security feature (signing, encryption) is present.

| Dialect | Revision code | First Windows | Notes |
| --- | --- | --- | --- |
| SMB1 (CIFS) | NT LM 0.12 | NT/2000/XP | **Dangerous, deprecated**; EternalBlue (MS17-010) |
| SMB 2.0.2 | 0x0202 | Vista / Server 2008 | SMB2 redesign |
| SMB 2.1 | 0x0210 | Windows 7 / Server 2008 R2 |  |
| SMB 3.0 | 0x0300 | Windows 8 / Server 2012 | Encryption (AES-CCM) added |
| SMB 3.0.2 | 0x0302 | Windows 8.1 / Server 2012 R2 |  |
| SMB 3.1.1 | 0x0311 | Windows 10 / Server 2016+ | Pre-auth integrity (SHA-512), downgrade protection |

Microsoft deprecated SMB1 in 2014, and it is no longer installed by default starting with Windows 10 1709. The default negotiation picks the highest between SMB 2.0.2 and 3.1.1.

**SMB signing.** By signing every SMB message with a key, it prevents an on-path attacker from altering the packet (tampering) and, most importantly, the **relay** attack. The signing algorithm varies by dialect: SMB 2.x HMAC-SHA256, SMB 3.0/3.0.2 AES-128-CMAC, SMB 3.1.1 AES-128-GMAC. If signing is **off or not required**, NTLM relay is possible (the relay attack itself is in Section 11). In a quick check, `signing:False` or "signing: enabled but not required" is a green light for relay.

**Null session.** An SMB session established without a username and password (anonymous); historically it allowed enumerating the user list, groups, password policy, and shares via RPC over the IPC$ share. Old Windows (NT/2000) came with it open; modern Windows restricts it with `RestrictAnonymous`/`RestrictAnonymousSAM`, but it is still found on misconfigured systems and legacy devices.

Quick reconnaissance:

```
nxc smb 10.10.10.10                         # banner: name, domain, OS, SMB version, signing status
nxc smb 10.10.10.10 -u '' -p ''             # null session attempt
smbclient -L //10.10.10.10 -N               # -N: no password prompt (null); share listing
smbmap -H 10.10.10.10 -u '' -p ''           # share + read/write permissions
rpcclient -U "" -N 10.10.10.10              # null RPC; then: enumdomusers, querydominfo
enum4linux-ng -A 10.10.10.10                # otomatik null session enum
```

Example `nxc` output and its interpretation:

```
SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
```

Here `signing:True` makes relay harder, `SMBv1:False` rules out EternalBlue, `domain:corp.local` + the machine name DC01 → this is a Domain Controller.

**Detection/Defense:** If auditing is enabled on the DC, anonymous SMB/RPC enum attempts show up via **Event ID 5145** (detailed file share access) and logon events (anonymous logon). Defense: remove SMBv1, make SMB signing **required** (this kills relay), close null sessions with `RestrictAnonymous=2`, enable SMB encryption.

**Note:** If SMB signing is **off/not required**, NTLM relay is possible; "signing enabled" is not enough, it must be "required". SMBv1 = EternalBlue (MS17-010) risk. 139 = SMB over NetBIOS, 445 = directly over TCP. A null session gathers information **without** a username/password.

## 2.7 DNS (Domain Name System)

It is the name-to-IP resolution system; it is one of the richest information sources of the reconnaissance phase. Queries generally use UDP/53 (small responses), while large responses and zone transfers use TCP/53.

Record types:

| Record | Meaning | Pentest value |
| --- | --- | --- |
| **A** | Name → IPv4 | Host discovery |
| **AAAA** | Name → IPv6 | IPv6 hosts |
| **MX** | Mail server | Mail infrastructure, phishing target |
| **NS** | Authoritative name server | Finding the DNS servers |
| **TXT** | Free text | SPF/DKIM/DMARC, domain verification tokens |
| **CNAME** | Alias → canonical name | Service/CDN relationships |
| **SOA** | Start of zone authority | Zone serial number, primary NS |
| **PTR** | IP → name (reverse) | Reverse lookup, internal naming |
| **SRV** | Service location | In AD `_ldap._tcp.dc._msdcs.<domain>` → **exposes the DCs** |

**Zone transfer (AXFR).** The mechanism DNS uses for secondary servers to pull a full copy of the zone from the primary (TCP/53). While the server should only allow authorized secondaries, if it serves all records **to anyone due to misconfiguration**, an attacker gets all internal hosts, names, and IPs in a single command: a gold mine in reconnaissance. **IXFR** is the incremental (only changed records) form of the same thing.

```
dig axfr @ns1.target.com target.com          # AXFR attempt; dumps all records if successful
host -t ns target.com                         # find the NS records first
host -l target.com ns1.target.com             # -l: zone transfer list
dnsrecon -d target.com -t axfr                # otomatik AXFR + enum
```

If AXFR is closed, subdomain discovery is done with brute-force/wordlists (e.g. `dnsenum`, `gobuster dns`) or with certificate transparency logs.

**Detection/Defense:** Unauthorized AXFR requests appear in DNS server logs. Defense: restrict zone transfer to only known secondary NS IPs (`allow-transfer`), sign with TSIG where possible; separate internal and external DNS (split-horizon).

**Note:** Zone transfer uses **TCP/53** (not UDP). The SRV record `_ldap._tcp.dc._msdcs` points to the DCs in AD; this is the pentest value of SRV. PTR = reverse resolution (IP→name), the inverse of A.

## 2.8 Kerberos and NTLM (Windows authentication): overview

Only the network/protocol basics of the two Windows authentication protocols are here; the workings of the attacks (Kerberoasting, AS-REP roasting, Pass-the-Hash, relay) are in Section 13.

- **NTLM:** challenge/response. The server sends a challenge, the client computes the response with the NT hash of the password; the password never crosses the network. Because the hash is **unsalted**, Pass-the-Hash is possible. Its over-the-network forms are NetNTLMv1/v2 (can be captured with tools). Port usage: carried over SMB (445) and other services.
- **Kerberos:** ticket-based, port **88**. The client gets a TGT from the KDC (on the DC), then requests a TGS (service ticket) for the target service. It is the modern AD default; passwords/hashes do not constantly travel the network, tickets are used instead.

**Note:** Because the NTLM hash is **unsalted**, Pass-the-Hash works; this is a property of NTLM, not Kerberos. Kerberos uses port **88**, kpasswd port **464**. For protocol detail and attacks see Section 13.

Once this foundation is in place, scan output (Section 4) and identity attacks (Section 13) fall into place.
