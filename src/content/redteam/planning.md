---
title: "1. Penetration Test Planning (Planning, Legal, Reporting)"
order: 1
part: "Planning & Fundamentals"
description: "Legal basis, pre-engagement documents (NDA/MSA/SOW/RoE), scoping, threat modeling, methodologies, risk scoring and reporting."
---

A penetration test is an **authorized** security assessment performed from an attacker's point of view. What separates it from a vulnerability assessment is **exploitation and proof of business impact**: a scan says "this port is open and this CVE exists", a penetration test says "I used this CVE to become domain admin, here is the proof". A red team engagement is narrower, focused on a specific objective (e.g. "exfiltrate the crown-jewel data"), tests working without being detected, and is usually run without the Blue team's knowledge.

## 1.1 Why plan? The legal basis

Running a penetration test without permission is a crime. There is no technical difference between you and a criminal hacker; the only difference is **written authorization**. Relevant law:

| Country/Region | Law | Scope |
| --- | --- | --- |
| US | Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030) | Unauthorized access and exceeding authorized access |
| US | DMCA | Circumventing technological protection measures |
| UK | Computer Misuse Act 1990 | Unauthorized access/modification |
| EU | GDPR | Personal data processed during the test; breach notification |
| Turkey | TCK 243-245 (cybercrime), 6698 KVKK | Unauthorized access, data; personal data protection |

The golden rules of planning: (1) Never test a system you do not have written permission for. (2) **Never** go out of scope; `scope creep` is both a legal and a contractual problem. (3) For third-party hosted assets (cloud, shared data center, SaaS), the **host provider's** rules also apply even if the customer owns the target. (4) If you accidentally land on an out-of-scope system during the test, stop, document it, and notify the contact listed in the RoE.

**Note:** Even if the customer verbally says "test this IP too", do not test until the SOW/RoE is updated and **written** approval (ideally a signature) arrives. Verbal permission does not protect you from the CFAA.

## 1.2 Pre-engagement documents

These documents are the outputs of PTES's "Pre-engagement Interactions" phase. Each one's function, contents and how it differs from the others is described separately below.

| Document | Full name | Core function | Typical contents |
| --- | --- | --- | --- |
| **NDA** | Non-Disclosure Agreement | Confidentiality commitment | What counts as confidential, disclosure ban, duration, data destruction, mutual or one-way |
| **MSA** | Master Service Agreement | Long-term commercial framework | Payment terms, liability limit, intellectual property, insurance, termination; not rewritten for each engagement |
| **SOW** | Statement of Work | Contract specific to this engagement | Scope, target list, deliverables, schedule, price, acceptance criteria |
| **RoE** | Rules of Engagement | The "how" of the test | Allowed IPs/networks, test window, allowed/forbidden techniques, contact and escalation |
| **Authorization letter** | Authorization letter | Legal "proof of permission" | Signature of the senior manager granting authority, scope, date range |

**NDA (Non-Disclosure Agreement).** A confidentiality agreement binding the tester not to disclose the sensitive data they will see (customer passwords, customer data, internal network topology). It comes in two forms: *unilateral* (only the tester is bound) or *mutual/bilateral* (both parties protect each other's secrets). It contains: the definition of confidential information, usage restrictions, disclosure exceptions (court order), the duration of confidentiality, and clauses on destroying data/evidence at the end of the engagement.

**MSA (Master Service Agreement).** The general, reusable legal and commercial framework between vendor and customer. It defines once the clauses that stay the same across projects: limitation of liability, indemnification, payment terms, intellectual property ownership, insurance and termination. A new test does not get a fresh MSA; only a new **SOW** is added. So MSA = the umbrella, SOW = a single engagement under it.

**SOW (Statement of Work).** The contract specific to this test: full scope, target IP/domain/application list, test type, deliverables (report, presentation, retest), project schedule, milestones, price and acceptance criteria. The SOW defines "what will be done and what will be delivered".

**RoE (Rules of Engagement).** Defines the operational rules of the test; the most critical pre-engagement document. Contents:

- Authorized target IP/CIDR and explicitly **excluded** systems.
- Test window: which days/hours testing is allowed (e.g. only outside business hours, weekends).
- Allowed and forbidden techniques: **will DoS testing be done**, is password **brute-force** (account lockout risk) allowed, is there permission for **social engineering/phishing**, is there physical testing.
- Data handling rules: whether sensitive data found is to be exfiltrated or only proven accessible.
- Contacts (technical + management) and the **escalation path**: who to call and how when a critical vulnerability or an active breach is found.
- What to do if detected (the "deconfliction" / "get out of jail" protocol in red teaming).

**Authorization letter ("get out of jail free card").** A signed letter from a senior manager legally competent to grant authorization (the owner of the systems) stating "these people are authorized to test these systems on these dates". On a physical intrusion or social engineering job the tester **carries it** and shows it if security or police stop them. It is critical that the signer is actually entitled to authorize testing of those assets.

**Note:** Map each document to its purpose. "Defines the test hours and allowed techniques (including DoS/SE)?" is the **RoE**. "Provides confidentiality?" is the **NDA**. "Work scope, deliverables, price?" is the **SOW**. "General long-term commercial framework between the parties, liability limit?" is the **MSA**. "The signed permission you carry on a physical test?" is the **Authorization letter**. Also verify that the person signing the authorization is entitled to authorize testing of those systems.

## 1.3 Scoping

Scoping sets the boundaries and depth of the test; bad scoping both leaves gaps and creates legal risk. What to nail down:

**Target definition.** IP ranges/CIDR, domains, URLs, applications, APIs, accounts. **Exclusions** (out-of-scope) are written explicitly: legacy/fragile production systems, third-party services, partner networks.

**Perspective (position).**

| Perspective | Where the tester is | Threat simulated |
| --- | --- | --- |
| **External** | From the internet, external IPs | Internet-based attacker; the perimeter |
| **Internal** | From inside the network (VPN/device/"assumed breach") | Malicious employee or an already-compromised machine |

The **assumed breach** model, common in internal tests, assumes the attacker is already inside and gives the tester a foothold on the network (a low-privilege machine/account) so that valuable lateral movement and privesc time is not spent on reconnaissance.

**Information level (box type).**

| Type | Information given | Advantage / Disadvantage |
| --- | --- | --- |
| **Black-box** | None | Most realistic external attacker; but time burns in recon, depth can drop |
| **Gray-box** | Partial (some credentials/architecture) | Most efficient; balance of realism and depth |
| **White-box / crystal-box** | Full (source code, architecture, credentials) | Deepest and most thorough; least realistic |

**Sensitive systems and risky techniques.** Special restrictions apply to production, SCADA/ICS, medical devices and legacy/fragile services. **DoS testing** is forbidden in most RoEs or needs separate written permission. **Brute-force** can trip the account lockout policy and lock up production; the threshold and permission are clarified. For **social engineering/phishing**, employees' personal data and legal limits are observed.

**Cloud provider rules.** Even if the asset belongs to the customer, testing on **shared infrastructure** is subject to the provider's rules. Current (2024-2025) state:

| Provider | Pre-approval | Key rule |
| --- | --- | --- |
| **AWS** | Not required for services on the "Permitted Services" list | DoS/DDoS and simulated DoS are **forbidden**; C2 (command-and-control) testing **requires pre-approval**; testing AWS's own infrastructure is forbidden |
| **Azure (Microsoft)** | Not required since 15 June 2017 | Follow the "Microsoft Cloud Unified Penetration Testing Rules of Engagement"; **DoS/DDoS is forbidden under all conditions**; DDoS resilience is tested only with approved simulation partners (e.g. BreakingPoint Cloud, Red Button) |
| **GCP (Google)** | Generally not required, no notification process | Only affect your own projects; follow the Google Cloud Acceptable Use Policy and ToS |

On all three providers only the resources **you own or are responsible for** are targets; testing that would affect other customers is forbidden. During scoping, verify which cloud the asset is in and the provider's current policy.

**Note:** The answer to "is a permission request always filed with the cloud provider before testing?" is now **no**: AWS/Azure/GCP generally do not require pre-approval for your own resources, but **DoS testing** is a special rule on all three (fully forbidden on Azure, forbidden plus C2 pre-approval on AWS). Owning the resource does not grant the **right to DoS** it.

**Note:** The most realistic external-attacker scenario is **black-box**; the deepest and most thorough assessment is **white-box**. Most commercial tests are **gray-box** in practice (time/budget balance). "Source code access is given" points to white-box.

## 1.4 Threat Modeling

Threat modeling, PTES's third phase, structures the question "who attacks us, why and how"; the test validates the scenarios derived from this model. First assets and business processes are listed, then threat actors (state-sponsored APT, organized crime, hacktivist, insider threat, opportunist) and their capabilities are mapped, and finally attack paths are modeled.

Common threat modeling frameworks:

| Framework | Focus | Expansion/logic |
| --- | --- | --- |
| **STRIDE** (Microsoft) | Threat type classification | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege |
| **DREAD** | Risk rating | Damage, Reproducibility, Exploitability, Affected users, Discoverability |
| **PASTA** | Process-centric, tied to business risk | 7-stage risk-centric threat analysis |
| **Attack trees** | Attack-path modeling | Root = goal, branches = sub-attack steps |

The output of threat modeling sets the test's priorities: which asset is most valuable, which attack path most likely. MITRE ATT&CK (see 1.5) is used at this stage to tie real-world TTPs to the model.

**Note:** STRIDE is a **threat classification** model, not risk scoring; **DREAD** does the risk scoring. The category of "elevation of privilege" belongs to **STRIDE**.

## 1.5 Methodologies and frameworks

You need to know what these names are, who published them, and their phases. Do not confuse them: PTES/OSSTMM/NIST 800-115 are **test methodologies**; MITRE ATT&CK is a **knowledge base**; the Cyber Kill Chain is an **attack model**.

**PTES (Penetration Testing Execution Standard).** Published in 2009, a seven-phase standard defining how a test is planned and carried out end to end:

| # | Phase | Contents |
| --- | --- | --- |
| 1 | Pre-engagement Interactions | Scope, documents (NDA/MSA/SOW/RoE), objectives |
| 2 | Intelligence Gathering | OSINT, passive/active reconnaissance |
| 3 | Threat Modeling | Asset + threat actor + attack path modeling |
| 4 | Vulnerability Analysis | Finding and verifying vulnerabilities |
| 5 | Exploitation | Exploiting vulnerabilities, gaining access |
| 6 | Post-Exploitation | Privilege escalation, lateral movement, data value, persistence |
| 7 | Reporting | Reporting the findings |

**NIST SP 800-115** ("Technical Guide to Information Security Testing and Assessment"). A US government standard; defines the test process in **four phases**:

| # | Phase | Contents |
| --- | --- | --- |
| 1 | Planning | Scope, rules, approval, objectives |
| 2 | Discovery | Information gathering + vulnerability identification |
| 3 | Attack | Verifying/exploiting vulnerabilities (gained access can loop back to Discovery) |
| 4 | Reporting | Findings, risk, methodology, remediation |

**OSSTMM (Open Source Security Testing Methodology Manual).** Published by ISECOM, a **measurable and repeatable** security testing methodology. Known for the "RAV" (Risk Assessment Values) concept that quantifies operational security; it covers five channels (Human, Physical, Wireless, Telecommunications, Data Networks).

**OWASP WSTG (Web Security Testing Guide).** The de facto standard for web application testing; current stable version **v4.2** (December 2020), with v5.0 in development. It splits tests into categories such as authentication, session management, input validation and business logic. Web application detail is in the relevant section of this guide; here it appears only as a methodology name.

**MITRE ATT&CK.** A knowledge base of real attackers' tactics and techniques (TTPs). **Not a methodology** but a catalog of observed behavior. The Enterprise matrix has **14 tactics** (in order): Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. Under each tactic are techniques (e.g. T1558.003 Kerberoasting). Mapping findings to ATT&CK techniques in the report lets the Blue team see its detection gaps.

**Cyber Kill Chain (Lockheed Martin, 2011).** Breaks an intrusion into seven sequential stages; the defender can break the chain at any stage:

| # | Stage | What the attacker does |
| --- | --- | --- |
| 1 | Reconnaissance | Gathers information about the target |
| 2 | Weaponization | Weaponizes an exploit + payload |
| 3 | Delivery | Delivers the payload to the target (email, web) |
| 4 | Exploitation | Triggers the vulnerability and runs code |
| 5 | Installation | Installs persistent access/backdoor |
| 6 | Command & Control (C2) | Command channel to the compromised machine |
| 7 | Actions on Objectives | Reaches the goal (data theft, disruption) |

**Note:** PTES has **7** phases, NIST SP 800-115 has **4**; do not confuse the counts. ATT&CK is **not a methodology, it is a TTP knowledge base**. The Cyber Kill Chain is a **linear attack model**, not a test methodology. OSSTMM = measurability/RAV; OWASP WSTG = web; NIST 800-115 = US technical testing guide.

## 1.6 Risk Scoring

Finding priority is set by **risk**, not by how impressive the technique is. The basic formula:

```
Risk = Likelihood × Impact
```

**CVSS (Common Vulnerability Scoring System).** An open standard that scores vulnerabilities from 0.0 to 10.0; current versions are v3.1 and v4.0. Qualitative bands (same for v3.0, v3.1 and v4.0):

| Score | Severity |
| --- | --- |
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

CVSS uses three metric groups: **Base** (the vulnerability's unchanging nature), **Temporal/Threat** (exploit availability, changes over time), **Environmental** (adapted to the customer environment). Important: by NVD's own warning, **CVSS is not a risk measure**, it is a technical measure of vulnerability severity; for real risk you must add the asset's business value and environment (Environmental). CVSS v2 had no Critical band (the top was High, 7.0-10.0); Critical was added from v3 onward.

**DREAD.** Qualitative risk ranking: the average of the Damage, Reproducibility, Exploitability, Affected users and Discoverability axes. Because of its subjectivity it is no longer as widespread as CVSS, but it still comes up as a concept.

**Note:** CVSS measures **severity**, it is not **risk** on its own; business impact and environment are added to get risk. Note the bands: 9.0-10.0 = Critical, 7.0-8.9 = High (boundaries inclusive: 7.0 = High, 6.9 = Medium). CVSS v2 has no Critical band.

## 1.7 Reporting

The report is the real product; the customer buys the **report**, not the test itself. Two different audiences (management and the technical team) need two different languages. Sections of a typical pen test report:

| Section | Contents | Audience |
| --- | --- | --- |
| Cover / confidentiality notice | Document class, distribution restriction | All |
| **Executive Summary** | Overall risk posture, business impact, count of critical findings, high-level recommendation | Management |
| Scope | Assets tested, dates, exclusions | All |
| Methodology | Which methodology/tools (PTES, NIST, etc.) | Technical |
| **Technical Findings** | Each finding: title, severity (CVSS), affected system, evidence, reproduction, business impact, remediation | Technical |
| Remediation roadmap | Prioritized remediation plan | Technical + management |
| Appendices | Tool output, raw data, accounts used | Technical |

**Executive Summary.** In non-technical language: business risk, overall security posture, count of critical/high findings and strategic recommendation. **No exploit code, commands or deep technical detail here.** It answers the manager's question of "how bad is it, what should I do, what will it cost".

**Technical Findings.** For each finding: a descriptive title, severity (CVSS score + band), affected systems, **evidence** (command output/screenshot), **reproduction** (how to repeat it), **business impact** (what is lost if this is exploited) and **remediation** (a concrete, actionable fix such as "apply the patch" or "enforce SMB signing"). Good remediation is specific and prioritized, not generic.

**Prioritization.** Findings are ordered by **risk and business impact**, not by discovery order; the critical ones first. Every claim is proven (output/screenshot); an unproven finding is dropped from the report.

**Retest / verification.** A second, narrow-scope test done after the customer applies fixes; it only verifies whether the previous findings are closed. The retest right and its timeframe should be defined in the SOW.
