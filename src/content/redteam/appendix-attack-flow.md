---
title: "19. Appendix B: Attack flow and terms"
order: 19
part: "Reference"
description: "End-to-end attack flow, when-to-use-which quick decisions and a glossary of terms."
---

## 19.2 End-to-end attack flow (mental map)

```
Planlama (RoE/scope)
   → Recon (pasif: whois, DNS, OSINT, metadata)
   → Scanning (nmap -sn → -p- → -sVC; UDP; masscan)
   → Vuln scan (Nessus credentialed; searchsploit; nmap --script vuln)
   → Exploitation (public exploit / Metasploit / web / service) → FOOTHOLD (shell)
   → Local privesc (Linux: sudo/SUID/GTFOBins/cron; Windows: SeImpersonate/service/token) → SYSTEM/root
   → Credential access (mimikatz, secretsdump, hashdump, Responder) → hash/plaintext/ticket
   → AD recon (BloodHound, enum4linux, ldap) → attack path
   → AD attacks (Kerberoast/AS-REP/ADCS/PtH/relay/DCSync) → DA / krbtgt
   → Lateral movement (evil-winrm, psexec, wmiexec) + Pivot (chisel/ligolo/socks)
   → Persistence (Golden ticket, scheduled task, ADCS cert)
   → Exfil (HTTP/DNS/SMB, encrypted/chunked)
   → Reporting (risk order, evidence, remediation)
Cloud branch: Entra recon → spray/device-code/PRT → managed identity/IMDS → Golden SAML/federation
```

## 19.3 "When to use which" quick decisions

- There is account lockout risk → **spraying** (1 password × many users).
- A hash was obtained → **offline cracking** (drop online brute-forcing).
- An NT hash is available, the password is not needed → **Pass-the-Hash**.
- Kerberos environment, service account password → **Kerberoasting**.
- An account with pre-auth disabled → **AS-REP roasting**.
- krbtgt hash → **Golden Ticket** (domain persistence).
- SMB signing disabled + a captured NTLM → **NTLM relay**.
- No access to the internal network → **pivot** (chisel/ligolo/socks + proxychains).
- Firewall blocks ICMP, host shows as "down" → **nmap -Pn**.
- Firewall rule analysis → **nmap -sA**.
- Cloud with MFA → single-factor/legacy protocol + **device code phishing**.
- Managed identity on an Azure resource → **IMDS token** (169.254.169.254).

## 19.4 Glossary

- **TGT / TGS:** Ticket Granting Ticket (encrypted with krbtgt) / service ticket (encrypted with the service account).
- **SPN:** Service Principal Name; a service's identity in Kerberos (the Kerberoast target).
- **NT hash:** MD4(UTF-16LE(password)), unsalted, PtH possible.
- **NetNTLMv2:** challenge/response over the network, no PtH, crackable (5600).
- **PtH / PtT / OPtH:** Pass-the-Hash / Pass-the-Ticket / Overpass-the-Hash.
- **DCSync:** pulling hashes from the DC using replication rights.
- **DACL / ACE:** access control list / entry (BloodHound rights).
- **PRT:** Primary Refresh Token (Entra device SSO token).
- **SP / App Registration / Managed Identity:** Entra application identities.
- **IdP / SP (SAML):** identity provider / service provider.
- **FOCI:** Family of Client IDs (one refresh token gets tokens for many Microsoft clients).
- **Golden/Silver Ticket:** forged TGT with krbtgt / forged TGS with the service hash.
- **Golden SAML:** forged SAML token with AD FS's signing key.
- **Beacon / sleep / jitter:** C2 agent / check-in interval / randomness.
- **Redirector / malleable profile / domain fronting:** C2 concealment techniques.
- **CVSS:** vulnerability severity score (0-10).
- **RoE / SOW / MSA / NDA:** pre-engagement agreement documents.
- **LOLBAS / GTFOBins:** malicious operations with legitimate binaries (Windows / Unix).
- **IMDS:** Instance Metadata Service (cloud identity token endpoint).
