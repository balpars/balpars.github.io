---
title: "3. Reconnaissance"
order: 3
part: "Reconnaissance & Scanning"
description: "Passive vs active recon, WHOIS/RDAP, ASN mapping, DNS and subdomain discovery, dorking, OSINT, document metadata and breach data."
---

Reconnaissance is the first and often the most decisive phase of a penetration test: here you gather the input for every subsequent phase (scanning, exploitation, phishing, password attacks). The weight of this section is on **passive** reconnaissance and **information leakage**; active scanning and service fingerprinting are covered in Sections 4 and 5. Here you learn how much information you can extract "without the target noticing".

## 3.1 Passive vs Active Reconnaissance: the distinction and why

**Passive reconnaissance:** Gathering information from third-party sources (registrar/WHOIS, search engines, Certificate Transparency logs, social media, breach data, archives) **without direct contact** with the target's infrastructure. You do not send a single packet to the target's servers; therefore you **leave no trace** in the target's IDS/IPS/firewall logs. The protocol-level difference is this: in passive reconnaissance your TCP/UDP sessions are always established with *other* servers (Google, crt.sh, Shodan), and no socket is opened on the target side.

**Active reconnaissance:** You send packets to the target's own infrastructure: DNS queries (to the target's authoritative name server), ping, port scanning, banner grabbing, web directory brute. This appears in the target's logs and is detectable (see Section 4).

**Gray area (semi-passive):** Some techniques are borderline. Making a normal `A` query to the target's authoritative DNS server technically sends a packet to the target but cannot be distinguished from normal traffic. Visiting the target's website with a browser is the same. Shodan/Censys, on the other hand, have scanned the target **beforehand**; you ask Shodan (passive), and Shodan scans the target (active), which is why Shodan counts as "passive".

| Technique | Class | Does the target see it? | Example |
| --- | --- | --- | --- |
| WHOIS/RDAP, CT logs (crt.sh) | Passive | No | `whois`, `crt.sh` |
| Shodan/Censys query | Passive | No (Shodan scanned earlier) | `shodan host` |
| Google/GitHub/paste dork | Passive | No | `site:`, `filetype:` |
| Breach/metadata/archive | Passive | No | HIBP, exiftool, gau |
| Authoritative DNS query | Semi-passive | Technically yes, indistinguishable | `dig a @ns1` |
| Zone transfer (AXFR) | Active | Yes (the TCP/53 session is logged) | `dig axfr` |
| Subdomain brute (DNS) | Active | Yes (thousands of queries to the NS) | `dnsx`, `gobuster dns` |
| Port scanning / banner | Active | Yes | `nmap` (Section 4) |

**Why passive first?** Three reasons: (1) It leaves no trace, lowering your risk of being detected and blocked early. (2) It often yields more and "deeper" information than active scanning (leaked passwords, internal usernames, old endpoints never surface through active scanning). (3) It clarifies the scope; if you run active scanning without learning which IPs/domains truly belong to the organization, you go **out of scope** and commit a legal/contractual violation.

**Note:** "Gathering information without making contact with the target" = **passive reconnaissance**. A Shodan/Censys query is **passive** (you connect to Shodan, not to the target), but `nmap` or zone transfer is **active**. Finding subdomains via crt.sh is passive, while DNS brute-force is active.

## 3.2 Attack surface and information leakage

The more you know, the more entry points you find. Every piece of data you gather in reconnaissance is the **input** to a subsequent phase:

| Information gathered | Which phase it feeds |
| --- | --- |
| Domains, subdomains | Active scanning scope, web exploitation |
| IP blocks / ASN | Scanning scope (Section 4) |
| Employee names/emails | Username generation → password spraying (Section 9), phishing |
| Technology/version in use | CVE mapping → vulnerability scanning/exploitation (Section 5) |
| Leaked passwords (breach) | Credential stuffing / spraying |
| Document metadata | Internal usernames, internal paths, software version |
| Technical/non-technical people | Social engineering, spear-phishing (Section 11) |

**Note:** The information gathered in reconnaissance, "IP address ranges, document formats, and supported systems", maps exactly onto this table: IP blocks = scope, document formats/metadata = internal information leakage, supported systems = technology fingerprint (CVE mapping).

## 3.3 WHOIS and RDAP: domain and IP registration

**WHOIS** (TCP **port 43**, plain text) gives the registration information of a domain name or IP block: the registrant, registrar, creation/expiry date, name servers, and often an administrator email/phone. **RDAP** (Registration Data Access Protocol, HTTPS **port 443**, structured **JSON**) is the modern successor to WHOIS; standardized by RFC 7482-7484, it offers a query/response structure, references/links, and consistent error codes. Regional registries (ARIN, RIPE, APNIC) now redirect to RDAP.

```
whois example.com                 # registrant, registrar, creation date, name servers
whois 203.0.113.10                # IP owner (netblock), org name, abuse email
whois -h whois.arin.net 203.0.113.10   # query a specific registry

# RDAP (JSON, HTTPS) - openrdap/rdap istemcisi
rdap example.com                  # domain record (JSON/whois-style)
rdap 203.0.113.10                 # IP / netblock record
rdap AS15169                      # ASN record
rdap -t ip 203.0.113.10           # type can be specified explicitly
# Raw RDAP query if there is no client:
curl -s https://rdap.org/domain/example.com | jq .
curl -s https://rdap.arin.net/registry/ip/203.0.113.10 | jq .
```

**Flag/field explanation:**

| WHOIS/RDAP field | What it is good for |
| --- | --- |
| Registrant / Admin / Tech Contact | Technical and non-technical contacts (social engineering, 3.14) |
| Name Server (NS) | DNS enum and zone transfer target (3.5) |
| Creation/Expiry Date | Domain age, domains forgotten at renewal (domain takeover hint) |
| NetRange / CIDR | The organization's IP block = scanning scope |
| OrgName / abuse-c | Mapping ASN/other blocks by organization name (3.4) |

**Reverse WHOIS:** Finds **other** domain names registered with the same registrant email/organization, revealing the organization's unknown domains:

```
amass intel -whois -d example.com     # fields associated through shared WHOIS data
```

**Note:** After GDPR/ICANN redaction, the registrant name/email is usually hidden for gTLDs like `.com/.net` ("REDACTED FOR PRIVACY"). Even so, the name server, creation date, and often the abuse email remain visible; the IP (RIR) WHOIS, on the other hand, is generally **not** redacted, and the OrgName and netblock are open.

**Note:** Domain WHOIS comes from the registrar (GoDaddy etc.), while IP/ASN WHOIS comes from the Regional Internet Registry (RIR: ARIN/RIPE/APNIC/LACNIC/AFRINIC); the two are different databases. RDAP is the **successor** to WHOIS and returns JSON (not plain text).

## 3.4 ASN → IP block mapping

**ASN (Autonomous System Number)** is the set of IP prefixes advertised on the internet under a single administration via BGP. Large organizations have their own ASNs; if you find the ASN, you extract **all the IP blocks the organization advertises** (and therefore the scanning scope) in one go. The logic: `organization name → ASN → BGP prefixes (CIDR) → IP ranges`.

```
# 1) Find the ASN from the organization name
amass intel -org "Example Inc"        # returns ASNs matching in the AS description

# 2) Extract root domains / IP blocks from the ASN
amass intel -asn 15169                # root domains belonging to the ASN
amass intel -cidr 203.0.113.0/24      # domains from CIDR

# 3) Team Cymru IP→ASN mapping (verbose)
whois -h whois.cymru.com " -v 8.8.8.8"

# 4) ASN record via RDAP
rdap AS15169
```

`whois.cymru.com` verbose (`-v`) output: from a single IP, the ASN, BGP prefix, country, registry, and allocation date:

```
$ whois -h whois.cymru.com " -v 8.8.8.8"
AS      | IP       | BGP Prefix   | CC | Registry | Allocated  | AS Name
15169   | 8.8.8.8  | 8.8.8.0/24   | US | arin     | 1992-12-01 | GOOGLE, US
```

Note: Put the query **in quotes**, otherwise the daemon treats the lines as separate queries. For two or more IPs, use the **bulk** interface instead of querying one by one; this requires GNU netcat (not BSD `nc`), and the input is wrapped with `begin` / `verbose` headers:

```
printf "begin\nverbose\n8.8.8.8\n1.1.1.1\nend\n" | netcat whois.cymru.com 43
```

**bgp.he.net (Hurricane Electric BGP Toolkit):** A web interface; you search by organization name, ASN, IP, or prefix. The ASN page lists **all IPv4/IPv6 prefixes** that ASN advertises, its peers, and its reverse DNS: a passive and very fast method of extracting scope.

Worked example (scope extraction flow):

```
"Example Inc"  --amass intel -org-->  AS64500, AS64501
AS64500        --bgp.he.net-------->  203.0.113.0/24, 198.51.100.0/23
AS64501        --bgp.he.net-------->  192.0.2.0/24
=> Active scan scope (Section 4): 203.0.113.0/24, 198.51.100.0/23, 192.0.2.0/24
```

**Note:** An ASN is not a single IP but the set of **IP blocks an organization advertises**. Finding an IP range is an "information leakage/scope" matter. To find the ASN of an IP, use `whois -h whois.cymru.com` or bgp.he.net; for the ASN from an organization name, `amass intel -org`. If you forget to quote the `whois.cymru` query, it returns empty (a common mistake).

## 3.5 DNS reconnaissance and all record types

DNS (UDP/TCP **port 53**) is the organization's naming map. Each record type leaks different information. You can use a recursive resolver, but if you ask the target's **authoritative** NS directly, you get the most up-to-date/complete answer.

| Record | Information it reveals |
| --- | --- |
| A / AAAA | Host → IPv4/IPv6 |
| CNAME | Alias → real host (third-party service/takeover hint) |
| MX | Mail servers (phishing/mail security target) |
| NS | Authoritative name servers (AXFR target) |
| SOA | Primary NS + **administrator email (RNAME)** + serial/timing values |
| TXT | SPF, DKIM, DMARC, domain verification records, sometimes internal notes |
| SRV | Service location (e.g. `_ldap._tcp`, `_kerberos._tcp` → AD DCs, Section 8) |
| PTR | Reverse DNS (IP → name); reveals host names in an IP block |
| CAA | Which CA can issue certificates |
| HINFO/LOC | (Rare) OS/location leakage |

```
host example.com                          # A record
host -t aaaa example.com                  # IPv6
host -t mx example.com                    # mail sunucular
host -t ns example.com                    # authoritative NS
host -t soa example.com                   # SOA (RNAME = admin email!)
host -t txt example.com                   # SPF/DKIM/DMARC
dig +short ns example.com
dig example.com ANY +noall +answer        # (most resolvers restrict ANY, RFC 8482)
dig txt _dmarc.example.com +short         # DMARC policy
dig srv _ldap._tcp.dc._msdcs.example.com  # AD domain controller discovery

# Reverse DNS (hostnames in an IP block)
dig -x 203.0.113.10 +short
for ip in 203.0.113.{1..254}; do host $ip | grep -v NXDOMAIN; done

# Automated DNS enum tools
dnsrecon -d example.com -t std            # std: SOA/NS/MX/A/TXT/SRV standart enum
dnsrecon -d example.com -t axfr           # try zone transfer (3.5.1)
dnsrecon -d example.com -D wordlist.txt -t brt   # alt alan brute
dnsenum example.com                       # enum + Google scrape + try AXFR
dnsenum --enum -f wordlist.txt example.com
fierce --domain example.com               # NS discovery + AXFR + nearby IP scan
fierce --domain example.com --subdomain-file wordlist.txt --wide
```

**Flag explanation:** `dnsrecon -t std` pulls standard records; `-t axfr` attempts a zone transfer; `-t brt -D <list>` brute-forces subdomains with a wordlist. `fierce --wide` also scans the neighboring /24 of a found IP; `--subdomain-file` supplies a custom wordlist. `dig +noall +answer` reduces the output to just the answer section.

**SOA RNAME = technical contact:** The second field in the SOA record is the administrator email; the first dot is replaced with `@`. `hostmaster.example.com.` → `hostmaster@example.com`. This is a direct OSINT source for the "technical contact" in 3.14.

**Detection/Defense:** Normal `A/MX/NS` queries cannot be distinguished from an attack; what is actually detectable are **high-volume** queries (brute) and **zone transfer**. Defense: DNS query logging/analytical logging (see 3.5.1), split-horizon DNS (do not leak internal records to the outside), not keeping internal information in TXT records.

**Note:** An `ANY` query used to return all records at once; after RFC 8482 most resolvers restrict this/return HINFO, so you must query the record types **one by one**. SRV records (especially `_msdcs`) give away the Active Directory infrastructure.

### 3.5.1 Zone transfer (AXFR) in detail

**Mechanism:** A zone transfer is a secondary (slave) name server copying the **entire zone file** from the primary (master). **AXFR** is a full transfer, **IXFR** an incremental (only the changed ones) transfer, and because the connection needs to be reliable it is done over **TCP/53** (not UDP). By design it should only be served to authorized secondary servers; when misconfigured, the NS accepts AXFR from anyone and exposes **all internal DNS records** (internal hosts, dev/test systems, IP plan) in a single command.

```
# find NS records, then try AXFR against each
dig +short ns example.com
dig axfr example.com @ns1.example.com
host -l example.com ns1.example.com       # -l = list zone (AXFR)
dnsrecon -d example.com -t axfr           # automatically tries all NS records
fierce --domain example.com               # NS'leri bulup AXFR dener
```

Worked example: the publicly available test domain `zonetransfer.me` (digi.ninja, left open on purpose):

```
$ dig axfr zonetransfer.me @nsztm1.digi.ninja

; <<>> DiG 9.18.x <<>> axfr zonetransfer.me @nsztm1.digi.ninja
zonetransfer.me.      7200 IN SOA  nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.      7200 IN NS   nsztm1.digi.ninja.
zonetransfer.me.      7200 IN MX   0 ASPMX.L.GOOGLE.COM.
zonetransfer.me.      7200 IN A    5.196.105.14
zonetransfer.me.      7200 IN TXT  "google-site-verification=..."
office.zonetransfer.me.   7200 IN A   4.23.39.254
testing.zonetransfer.me.  7200 IN CNAME www.zonetransfer.me.
vpn.zonetransfer.me.      7200 IN A   174.36.59.154
internal.zonetransfer.me. 7200 IN A   10.1.1.17        <-- internal IP leak
zonetransfer.me.      7200 IN SOA  nsztm1.digi.ninja. robin.digi.ninja. 2019100801 ...
;; Query time: 95 msec
```

From here you extract both all the subdomains/internal IPs and, from the SOA RNAME, the administrator's email (`robin.digi.ninja` → `robin@digi.ninja`). **Next step:** internal IPs and dev/vpn hosts enter the scanning and exploitation scope (Sections 4-5); the administrator email becomes a phishing target (3.14).

**Detection/Defense:** AXFR is an active and loggable event. On Microsoft DNS, analytical logging (ETW, the `Microsoft-Windows-DNSServer/Analytical` channel, **off by default**) shows transfer requests with the keywords `AXFR_REQ_RECV` / `IXFR_REQ_RECV`. Classic event IDs: **Event ID 6001** for a successful transfer, **6536** for an invalid IXFR, **734** for an unauthorized/nonexistent zone request (these classic Event IDs vary by version; the most reliable signal is the analytical log keywords above). Defense: with `allow-transfer` restrict the transfer to **only known secondary IPs**, use **TSIG** (transfer signed with a shared key), and do not keep internal records in external DNS (split-horizon).

**Note:** AXFR is over **TCP/53** (rejected over UDP) and is a **misconfiguration**: if it succeeds, it gives you the whole zone. `dig axfr <domain> @<ns>` and `host -l <domain> <ns>` do the same job. If you see "Transfer failed / connection refused", the NS is configured correctly; try the other NSs too, because often only one is misconfigured.

## 3.6 Subdomain reconnaissance

Subdomains usually expose the weakest systems: `dev.`, `staging.`, `test.`, `uat.`, `vpn.`, `jenkins.`, `git.`, `admin.`. There are two approaches:

**A) Passive (without touching the target):**

```
# From Certificate Transparency (CT) logs - passive and very effective
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

subfinder -d example.com -silent -o subs.txt     # many passive sources
amass enum -passive -d example.com -o amass.txt   # passive OSINT sources
assetfinder --subs-only example.com
```

**Why do CT logs work?** Certificate Transparency (RFC 6962) requires every public TLS certificate to be written to public, append-only logs. If an organization obtained a certificate for `dev.example.com`, that name appears in the CT log **permanently**, even if the subdomain does not resolve in DNS or is removed. `crt.sh` makes these logs queryable; `%25` = the URL-encoded `%` wildcard character.

A subdomain list from crt.sh JSON output:

```
$ curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
*.example.com
api.example.com
dev.example.com
jira.example.com
mail.example.com
vpn.example.com
www.example.com
```

**B) Active (DNS brute / resolution):**

```
# Resolve the passive list and verify which are live (dnsx, ProjectDiscovery)
subfinder -d example.com -silent | dnsx -silent -resp -o resolved.txt
dnsx -l subs.txt -resp                      # resolve existing list (returns A/CNAME)

# brute-force with wordlist
dnsrecon -d example.com -D /usr/share/wordlists/subdomains.txt -t brt
gobuster dns -d example.com -w wordlist.txt -t 50
ffuf -u https://FUZZ.example.com -w wordlist.txt   # vhost/subdomain fuzz
```

**Flag explanation:** `subfinder -silent` prints only the domain names (for a pipeline); `dnsx -resp` also shows the resolved IP/record, `-l` takes input from a file. `gobuster dns -t 50` uses 50 concurrent threads.

**Decision guide:** Run **passive** first (crt.sh + subfinder + amass passive), it leaves no trace and gives most subdomains. For subdomains that do not surface in passive but that you think exist, do a **brute** (active). Always resolve the passive results with `dnsx` and filter out the live ones (a name in the CT log may no longer be in DNS).

**Detection/Defense:** Passive reconnaissance cannot be detected. DNS brute-force, on the other hand, produces thousands of NXDOMAINs on the authoritative NS in a short time, which is seen/blocked by a DNS firewall/RPZ and rate-limiting. Defense: wildcard DNS (`*.example.com`) makes brute pointless (every query resolves); monitor the CT log for your own domains to notice leaked internal/unexpected certificates.

**Note:** crt.sh/CT logs are **passive** and show even removed/non-resolving subdomains (certificate history is permanent). DNS brute-force is **active**. `subfinder`/`amass -passive` are passive, `gobuster dns`/`dnsrecon -t brt` are active.

## 3.7 Search engine and device dorks (Google / Shodan / Censys)

**Google dorking**: finding sensitive content with operators:

| Dork | What it finds |
| --- | --- |
| `site:example.com` | All indexed pages on the domain |
| `site:example.com -www` | Subdomains other than www |
| `filetype:pdf site:example.com` / `ext:xlsx` | Documents (for metadata, 3.10) |
| `intitle:"index of" site:example.com` | Open directory listings |
| `inurl:admin` / `inurl:login` | Admin/login panels |
| `intext:"password" filetype:log` | Passwords leaked in logs |
| `site:pastebin.com example.com` | Leaks on paste sites |
| `cache:example.com` | Google cache (deleted content) |
| `filetype:env "DB_PASSWORD"` | Exposed .env files |

**Shodan**: a search engine for internet-exposed devices/services (passive; Shodan has scanned the target earlier):

```
shodan host 203.0.113.10                 # everything known about a single IP (ports, banners, CVEs)
shodan search 'org:"Example Inc"'        # devices belonging to the organization
shodan count 'port:3389 country:TR'      # match count only (doesn't spend credits)
shodan search --fields ip_str,port,org 'ssl:"example.com" port:443'
shodan domain example.com                # DNS/subdomain data for the domain
```

| Shodan filter | Meaning |
| --- | --- |
| `org:"Example Inc"` | Ownership (WHOIS org name) |
| `net:203.0.113.0/24` | CIDR block |
| `port:3389` | Open port (RDP) |
| `hostname:example.com` | Host name match |
| `ssl:"example.com"` / `ssl.cert.subject.cn:` | Name appearing in the TLS certificate |
| `product:"Apache"` / `http.title:` | Software/page title fingerprint |
| `vuln:CVE-2021-44228` | Devices vulnerable to a specific CVE (membership required) |

**Censys**: a similar internet scanning engine. There is a difference between the old query language and the new **CenQL** (Censys Platform):

```
# Old (Search v1/v2) syntax:
services.port: 443 AND autonomous_system.name: "EXAMPLE"
services.service_name: HTTP AND services.tls.certificates.leaf_data.subject.common_name: example.com

# New CenQL (unified Platform) - syntax changed, verify:
host.services.port = 443 and host.autonomous_system.name = "AMAZON-02"
```

(The CenQL migration is ongoing; the syntax may vary by your setup/plan version.)

**Note:** Shodan and Censys are **passive** (you connect to the service, not to the target). `shodan count` does not spend credits, `shodan search` does, so in practice run `count` first to save credits. Via Google dorking, `.env`/log/backup files are the most common source of information leakage.

## 3.8 OSINT automation: theHarvester and frameworks

**theHarvester** gathers emails, subdomains, hosts, names, and IPs from many open sources (search engines, crt.sh, DNS) in a single command:

```
theHarvester -d example.com -b bing,duckduckgo,crtsh,dnsdumpster -l 500 -f example_recon
theHarvester -d example.com -b all -f fullscan      # all sources
```

**Flag explanation:** `-d` the target domain, `-b` data sources (comma-separated; `all` = all of them), `-l` result limit, `-f` writes the output to a file (XML/JSON). Note: the name `theharvester` (lowercase) is deprecated, use `theHarvester`.

Example output:

```
$ theHarvester -d example.com -b bing,duckduckgo,crtsh -l 500 -f example_recon
[*] Target: example.com

[*] Emails found:
--------------------
john.smith@example.com
hr@example.com
noreply@example.com

[*] Hosts found:
--------------------
mail.example.com:203.0.113.25
vpn.example.com:203.0.113.40
dev.example.com:198.51.100.12
```

**Other frameworks:** `recon-ng` (a Metasploit-like module-based OSINT framework, `marketplace install`, `modules load recon/domains-hosts/...`), `SpiderFoot` (web-based automatic OSINT correlation), `Maltego` (relationship graph/transforms).

**Note:** theHarvester is passive and quickly gathers especially the **email + subdomain + host** triad. The emails in its output are both a phishing target and give away the username pattern (3.9).

## 3.9 Email and username generation

**Why is it critical?** In many authentication systems (especially Active Directory), the username is derived from an email/first-last pattern. If you learn an employee's email format (`john.smith@example.com`), you can turn the entire list of names you gathered from LinkedIn into **valid usernames** and use them for **password spraying** (Section 9) and **phishing** (Section 11). In AD this name is usually the `sAMAccountName` or UPN (`user@domain`).

Common patterns (once one is solved, all are derived):

| Pattern | "John Smith" example |
| --- | --- |
| `first.last` | john.smith |
| `flast` | jsmith |
| `firstl` | johns |
| `f.last` | j.smith |
| `lastf` | smithj |
| `first_last` | john_smith |
| `first` | john |

Sources and automation:

```
# Name sources: LinkedIn, corporate "about us", theHarvester, hunter.io
# Names from LinkedIn -> AD username list
linkedin2username -c "Example Inc" -o usernames.txt       # generates various patterns
# Pattern generation from a name list
username-anarchy -i names.txt                              # emits all common patterns
```

Verifying the email format: `hunter.io`, the mail server's SMTP `VRFY`/`RCPT TO` behavior (mostly disabled), or O365/Entra user enumeration (see Section 8/12). The generated list becomes direct input to `kerbrute userenum`, `nxc smb -u users.txt`, and O365 spraying tools.

**Note:** Gathering employee names is not only for phishing; its real value is **username generation → password spraying**. A single valid email format reveals the whole organization's username scheme. Gathering names (LinkedIn/theHarvester) is passive; verifying whether the generated names are valid in AD (kerbrute/VRFY) is active.

## 3.10 Document metadata

Publicly available documents (PDF, DOCX, XLSX, PPTX, images) leak internal information: **author usernames**, internal file paths, software name/version, printer/server names, GPS coordinates.

```
# Single file, all metadata, with group tags
exiftool report-2024.pdf
exiftool -a -u -g1 report-2024.pdf            # -a: yinelenen etiketler, -u: bilinmeyenler, -g1: grupla
exiftool -Author -Creator -Producer *.pdf     # relevant fields only, bulk
exiftool -xmp -b report.pdf                    # ham XMP paketi

# Bulk-download documents from a domain and extract metadata
metagoofil -d example.com -t pdf,docx,xlsx -l 100 -o loot -f results.html
# FOCA (Windows GUI): finds and downloads domain documents via Google/Bing,
# extracts the metadata and compiles it into a user/software/path/network map.
```

**Flag explanation:** `exiftool -g1` separates tags by source group (PDF, XMP, XML); `-a` shows all tags with the same name; `-u` also prints unextractable/unknown tags. `metagoofil -t` sets the file types, `-l` the download limit.

Example exiftool output: a leak of an employee username and software version:

```
$ exiftool report-2024.pdf
ExifTool Version Number         : 12.76
File Name                       : report-2024.pdf
File Type                       : PDF
PDF Version                     : 1.7
Author                          : jsmith
Creator                         : Microsoft® Word for Microsoft 365
Producer                        : Microsoft® Word for Microsoft 365
Create Date                     : 2024:03:14 09:22:17-05:00
Modify Date                     : 2024:03:14 09:25:03-05:00
Company                         : Example Inc
```

From here, `jsmith` is probably an AD username (→ spraying/phishing), that `Microsoft 365` is used (→ O365/Entra attack surface, Section 12), the company name, and document creation dates can be extracted. In Office/legacy formats you may also see **internal file paths** (`C:\Users\jsmith\...`) and **printer/server names**.

**Detection/Defense:** Metadata gathering is completely passive, undetectable. Defense: clean metadata before publishing documents (Office "Inspect Document / Document Inspector", `exiftool -all= file`), automatic cleaning via central policy, not publishing sensitive documents publicly.

**Note:** For metadata extraction you need to know the **exiftool** and **FOCA** tools. The `Author`/`Creator` field in metadata is often a real internal **username** and directly feeds username generation (3.9).

## 3.11 Breach / credential (password leak) data

Email/password pairs leaked in past breaches are worth gold for credential stuffing and password spraying (Section 9), because people reuse passwords.

```
# HaveIBeenPwned (HIBP) API v3 - which breaches an account appears in (does not return passwords)
curl -s -H "hibp-api-key: <APIKEY>" -H "user-agent: recon" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/john.smith@example.com"
# Domain-wide breach search via HIBP "Domain Search" (requires account verification, done on the web)

# DeHashed - returns real leaked passwords/hashes (paid, requires credits)
curl -s -u "<APIKEY>:" "https://api.dehashed.com/search?query=domain:example.com" | jq .
# New API: POST /v2/search (syntax changed in 2024 - verify)
```

**Flag/field explanation:** HIBP v3 requires an `hibp-api-key` header and a `user-agent` (paid key); it only tells which breach you were in, it does not give the password. DeHashed, in basic-auth the username = the API key and the password is empty; in the `query` field the `email:`, `username:`, `domain:`, `password:`, `hash:` operators are used and it returns the actual record/password. (DeHashed switched to the `POST /v2/search` endpoint in 2024; for the current full syntax see the official API documentation.)

Others: `breach-parse` (searching `email:password` in local combolist dumps), WeLeakInfo/LeakCheck-like services, `h8mail` (multi-source email OSINT).

**Note:** HIBP tells **which breach** an account was in but does not give the password; for the actual password/hash you need paid services like DeHashed. Breach data is passive and is direct input to credential stuffing/spraying.

## 3.12 Code and paste leaks (GitHub / GitLab / paste sites)

Developers often accidentally write API keys, passwords, internal host names, and connection strings into public repos or paste sites.

```
# Secret scanning in Git history (including deleted commits)
trufflehog github --org=example-inc --only-verified      # org-wide, verified secrets
trufflehog git https://github.com/example/repo.git       # single repo (full history)
trufflehog git file://./repo                              # local clone
gitleaks detect --source . -v                             # local repo/directory, verbose
gitleaks git https://github.com/example/repo.git

# GitHub dorks (web): "example.com" password, org:example-inc filename:.env,
#   "example.com" AWS_SECRET_ACCESS_KEY
```

**Flag explanation:** trufflehog `--only-verified` tests the found key against the API to see whether it actually works (reduces false positives); `github --org` scans all the organization's repos. gitleaks `detect` scans, `git` the remote/local git history, `protect` is for pre-commit blocking.

**Decision guide:** For a fast/local pre-scan, `gitleaks`; for deep and verified (CI, history, live key test) scanning, `trufflehog`. Using the two together gives the best coverage.

**Detection/Defense:** Repo scanning is passive. Defense: pre-commit hook (gitleaks protect), **immediately rotate/revoke** a leaked key (deleting is not enough, it stays in history and in clones), use of a secret manager.

**Note:** A secret deleted from a commit **stays in the git history**; this is why trufflehog/gitleaks look at the entire **history**, not the current state of the file. Even if a leaked key is deleted, it is not considered safe until it is revoked.

## 3.13 Archive and historical data (Wayback / gau)

Archived URLs reveal old endpoints, parameters, backup files, and API paths that are no longer on the site: these are often outdated/weak.

```
waybackurls example.com > urls.txt                  # Wayback Machine'den *.domain URL'leri
cat domains.txt | waybackurls                        # borudan toplu
gau example.com --subs --o gau-urls.txt              # Wayback + Common Crawl + OTX + URLScan
gau --mc 200 --from 202301 --to 202412 example.com   # durum kodu/tarih filtreli
```

**Flag explanation:** `gau --subs` includes subdomains; `--mc 200,500` filters by HTTP status code; `--from/--to` a `YYYYMM` date range; `--providers wayback,commoncrawl,otx` selects sources; `--blacklist png,jpg` skips static files. waybackurls `--no-subs` excludes subdomains, `--dates` adds the fetch date.

**Note:** gau combines multiple archive sources (Wayback + Common Crawl + AlienVault OTX + URLScan), while waybackurls uses only the Wayback Machine. The old parameters/endpoints found are input to web vulnerability testing (Section 10). It is completely passive.

## 3.14 Technical and non-technical contacts (social engineering target)

**Technical contacts**: system/network/DNS administrators, DevOps, IT support. Sources: WHOIS "Tech Contact", the **SOA RNAME** email (3.5), LinkedIn ("System Administrator", "Network Engineer"), the `Author` in document metadata (3.10), GitHub contributors. Value: these people have highly privileged accounts; a successful spear-phish can directly give administrator credentials/VPN access. They are also easier to trick with technical jargon (a fake "IT support" call).

**Non-technical contacts**: reception, HR, finance/accounting, sales, senior management. Sources: the corporate website "contact/about us", LinkedIn, press releases, WHOIS "Registrant". Value: security awareness is usually low; they are the primary target for **vishing** (phone-based deception), **CEO/BEC fraud** (a wire transfer request via a fake executive email), physical intrusion (tailgating, fake visitor), and general phishing. The finance team is targeted for BEC, reception for physical access, and HR for a fake resume/macro-laden document.

```
# Bulk people/email extraction
theHarvester -d example.com -b all -f contacts
# Technical admin email from SOA
dig +short soa example.com        # RNAME field: hostmaster.example.com -> hostmaster@example.com
```

**Note:** The distinction between **technical and non-technical contacts** matters. Technical people = privileged access/spear-phishing; non-technical people = low awareness/vishing/BEC/physical. Gathering both in reconnaissance is part of the "information leakage" objective.

## 3.15 Decision guide: when to use which tool/technique

| Goal | First (passive) | Then (active, if needed) |
| --- | --- | --- |
| The organization's domains | reverse WHOIS (`amass intel -whois`) | - |
| IP blocks / scope | `amass intel -org`, bgp.he.net, `whois.cymru -v` | - |
| Subdomains | crt.sh, subfinder, `amass -passive` | resolve with `dnsx`, `gobuster dns` brute |
| All DNS records | `host -t`, `dig` (authoritative) | `dnsrecon -t axfr` (zone transfer) |
| Internet-exposed services | Shodan/Censys | nmap (Section 4) |
| Email/name/username | theHarvester, LinkedIn, hunter.io | verification with kerbrute/VRFY |
| Internal username/software | document metadata (exiftool/FOCA/metagoofil) | - |
| Leaked password | HIBP, DeHashed, breach-parse | spraying (Section 9) |
| Secret/key leak | GitHub dork, trufflehog, gitleaks | - |
| Old endpoint/parameter | waybackurls, gau | web testing (Section 10) |

General rule: **exhaust the fully passive** sources first (no trace, no scope risk), clarify the scope, then apply **targeted active** techniques at the points where a need remains.

## 3.16 Common mistakes and field tips

- **Going out of scope:** Before active scanning/AXFR, verify (with ASN/WHOIS) that the IP block/domain list truly belongs to the organization; otherwise you test a cloud provider or another organization.
- **Quoting `whois.cymru`:** If you do not quote the query in the form `" -v 8.8.8.8"`, the daemon errors out or returns empty.
- **AXFR fails on one NS:** Try each name server separately; often only one is misconfigured. AXFR is TCP/53; it is rejected over UDP.
- **Do not rely on the `ANY` query:** with RFC 8482 most resolvers restrict `ANY`; query the records one by one.
- **CT log vs live DNS:** names from crt.sh may not resolve; filter with `dnsx` and pick out the live ones.
- **theHarvester source error:** Some sources require an API key; if you do not have the key, remove it from the `-b` list, otherwise the whole scan may error out.
- **Do not forget exiftool:** on a PDF/DOCX handed to you in practice, `exiftool` should be your first reflex: the author/internal path/version is in there.
- **Shodan credits:** First `shodan count`, then `shodan search`; `count` does not spend credits.
- **Flag the passive/active distinction:** For each technique, ask "does this send a packet to the target?".
