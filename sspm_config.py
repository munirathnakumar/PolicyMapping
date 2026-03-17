"""
sspm_config.py
══════════════════════════════════════════════════════════════════════════════
ALL configurable settings for SSPM Policy Mapper.

Edit ONLY this file to customise matching behaviour.
sspm_mapper.py imports everything from here via:  from sspm_config import *

Sections:
  1.  Model path
  2.  Matching thresholds
  3.  Scoring boost / penalty constants
  4.  Conflict pairs          ← suppress false positives here
  5.  Domain pairing map      ← control domain filtering here
  6.  Synonym map             ← abbreviation expansion here
  7.  Concept bridges         ← vocabulary gap bridging here
  8.  Keyword groups          ← security term groups here
  9.  Policy name library     ← vendor policy descriptions here
══════════════════════════════════════════════════════════════════════════════
"""

from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — MODEL PATH
# ═══════════════════════════════════════════════════════════════════════════════
SECBERT_MODEL_PATH = "./secbert_clean"   # ← SET THIS TO YOUR FOLDER


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — MATCHING THRESHOLDS
# ═══════════════════════════════════════════════════════════════════════════════
THRESHOLD_FULL     = 0.82   # Strong match → FULL coverage
THRESHOLD_PARTIAL  = 0.60   # Moderate match → PARTIAL coverage
THRESHOLD_INDIRECT = 0.40   # Weak match → INDIRECT coverage
THRESHOLD_MIN      = 0.40   # Below this → no match at all


CACHE_DIR = Path("policy_cache")
CACHE_DIR.mkdir(exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SCORING BOOST / PENALTY CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
KEYWORD_BOOST    = 0.08   # per matching keyword group (capped at 0.25)
DOMAIN_BOOST     = 0.05   # when control domain aligns with policy category
NONSENSE_PENALTY = 0.20   # applied when zero keyword overlap AND base score < 0.55
CONFLICT_PENALTY = 0.25   # applied when conflicting sub-groups detected

# Pairs of keyword sub-groups that CONFLICT with each other
# If one side has group A and the other exclusively has group B → penalise


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CONFLICT PAIRS
# ═══════════════════════════════════════════════════════════════════════════════
CONFLICT_PAIRS = [
    ("encryption_at_rest",   "encryption_in_transit"),  # at-rest ≠ in-transit
    ("compliance_retention", "incident_response"),       # retain logs ≠ incident block
    ("user_lifecycle",       "endpoint_device"),         # user account ≠ device mgmt
    ("mfa",                  "network_security"),        # MFA auth ≠ IP/network restriction
    ("mfa",                  "data_residency"),          # MFA auth ≠ data location
    ("session",              "access_control"),          # session timeout ≠ access policy
]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — DOMAIN PAIRING MAP
# ═══════════════════════════════════════════════════════════════════════════════
DOMAIN_PAIRS: dict[str, list[str]] = {
    # ── Standard Domain → Allowed Policy Domains ─────────────────────────────
    "identity and access management": [
        "mfa",
        "access control",
        "password management",
        "permissions",
        "privacy control",
        "auditing",
    ],
    "access control": [
        "access control",
        "permissions",
        "mfa",
        "password management",
        "auditing",
    ],
    "secure configuration management": [
        "secure baseline",
        "configuration and posture management",
        "permissions",
        "auditing",
        "access control",
    ],
    "data protection": [
        "data leakage protection",
        "key management",
        "privacy control",
        "auditing",
    ],
    "third-party plugin and integration management": [
        "access control",
        "permissions",
        "secure baseline",
        "auditing",
    ],
    "securityoperations": [
        "auditing",
        "malware protection",
        "operational resilience",
        "secure baseline",
    ],
    "configuration and posture management": [
        "secure baseline",
        "auditing",
        "permissions",
        "access control",
    ],
    "network services security requirements": [
        "access control",
        "secure baseline",
        "auditing",
    ],
    "governance": [
        "auditing",
        "secure baseline",
        "operational resilience",
        "privacy control",
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — SYNONYM MAP
# ═══════════════════════════════════════════════════════════════════════════════
SYNONYM_MAP = {
    # Authentication
    r"\bmfa\b":                   "mfa multi-factor authentication two-factor 2fa",
    r"\b2fa\b":                   "2fa two-factor authentication mfa multi-factor",
    r"\bsso\b":                   "sso single sign-on saml federation",
    r"\bsaml\b":                  "saml sso single sign-on federation",
    r"\boidc\b":                  "oidc openid connect oauth federation",
    r"\bfido\b":                  "fido fido2 hardware key security key phishing-resistant",
    r"\bpam\b":                   "pam privileged access management",
    r"\bpim\b":                   "pim privileged identity management just-in-time",
    # Access Control
    r"\brbac\b":                  "rbac role-based access control permission",
    r"\babac\b":                  "abac attribute-based access control",
    r"\bjit\b":                   "jit just-in-time access",
    r"\biam\b":                   "iam identity access management",
    # Data Protection
    r"\bdlp\b":                   "dlp data loss prevention sensitive data",
    r"\bpii\b":                   "pii personally identifiable information sensitive data",
    r"\bphi\b":                   "phi personal health information sensitive data",
    r"\bpci\b":                   "pci payment card industry financial data",
    r"\bgdpr\b":                  "gdpr data protection regulation privacy",
    r"\bhipaa\b":                 "hipaa health information privacy compliance",
    # Encryption
    r"\btls\b":                   "tls transport layer security ssl encrypt",
    r"\bssl\b":                   "ssl secure sockets layer tls encrypt",
    r"\baes\b":                   "aes advanced encryption standard encrypt",
    r"\bkms\b":                   "kms key management service encryption",
    r"\be2e\b":                   "e2e end-to-end encryption",
    # Infrastructure
    r"\bsiem\b":                  "siem security information event management log monitoring",
    r"\bsoc\b":                   "soc security operations center monitoring",
    r"\bueba\b":                  "ueba user entity behaviour analytics anomaly detection",
    r"\bcasb\b":                  "casb cloud access security broker",
    r"\bcspm\b":                  "cspm cloud security posture management",
    r"\bsspm\b":                  "sspm saas security posture management",
    r"\bmdm\b":                   "mdm mobile device management endpoint",
    r"\bbyod\b":                  "byod bring your own device mobile endpoint",
    r"\bvpn\b":                   "vpn virtual private network remote access",
    r"\bscim\b":                  "scim system cross-domain identity management provisioning",
    # Protocols blocked
    r"\bsmtp\b":                  "smtp email legacy authentication protocol",
    r"\bimap\b":                  "imap email legacy authentication protocol",
    r"\bpop3\b":                  "pop3 email legacy authentication protocol",
    r"\bntlm\b":                  "ntlm legacy windows authentication protocol",
    # Frameworks
    r"\bnist\b":                  "nist cybersecurity framework standard",
    r"\biso\b":                   "iso international standard",
    r"\bsox\b":                   "sox sarbanes oxley compliance financial",
    # Actions
    r"\bdecommission\b":         "decommission disable remove block",
    r"\bdeprovision\b":          "deprovision remove revoke disable account",
    r"\blegacy auth\b":            "legacy authentication basic auth old protocol",
    r"at rest":                    "at rest storage encryption data stored",
    r"in transit":                 "in transit network encryption data transmitted",
    r"step-up":                    "step-up authentication mfa challenge",
    r"least privilege":            "least privilege minimum access rbac permission",
    r"zero trust":                 "zero trust verify always access control",
    r"data residency":             "data residency geographic location region compliance",
    r"audit trail":                "audit trail log record activity history",
    r"anomalous":                  "anomalous unusual suspicious behaviour detection",
    # Explicit at-rest vs in-transit expansions
    r"at.rest":            "at rest storage encryption data stored encrypted storage",
    r"in.transit":         "in transit transport encryption tls ssl network encrypted",
    r"data.in.transit":    "data in transit transport layer security tls ssl https network encrypted NOT at rest NOT storage NOT shield NOT field encryption",
    r"transit.*encrypt":   "transit encryption tls ssl https network transport layer security",
    r"encrypt.*transit":   "transit encryption tls ssl https network transport NOT at rest",
    r"data.at.rest":       "data at rest storage encryption encrypted storage",
    r"data.in.transit":    "data in transit transport tls ssl network encryption",
    r"transparent.data":   "transparent data encryption at rest database storage",
}


# ── Concept Bridge Map ────────────────────────────────────────────────────────
# Maps HIGH-LEVEL control concepts → POLICY-LEVEL implementation vocabulary
# This is the key fix for mismatches like:
#   "geofencing" → "conditional access location-based policy"
#   "risky sign-in" → "identity protection risk-based conditional access"
#
# Each entry: (phrase_in_control, text_to_append_to_encoding)
# The appended text uses the vocabulary the POLICY would use
#
# Add your own entries here when you find bad/missing matches

CONCEPT_BRIDGES = [
    # ── Location & Network Access ─────────────────────────────────────────────
    ("geofenc",
     "geofencing location-based access conditional access trusted location "
     "ip range network location restriction country block"),

    ("location-based",
     "location-based access conditional access trusted location ip restriction "
     "named location country-based geofencing"),

    ("country.*block",
     "country block conditional access location policy geofencing ip restriction"),

    ("trusted location",
     "trusted location conditional access named location ip range geofencing"),

    ("network restriction",
     "network restriction ip range location conditional access allowlist"),

    # ── Risk-Based Access ─────────────────────────────────────────────────────
    ("risky sign",
     "risky sign-in risk-based conditional access identity protection "
     "risk policy anomalous login suspicious authentication block"),

    ("risky user",
     "risky user identity protection risk-based access conditional access "
     "compromised account high risk block"),

    ("risk-based access",
     "risk-based access conditional access identity protection sign-in risk "
     "user risk policy"),

    ("high risk",
     "high risk user sign-in risk identity protection conditional access "
     "block remediate"),

    ("compromised account",
     "compromised account risky user identity protection conditional access "
     "block revoke session"),

    ("anomalous login",
     "anomalous login risky sign-in identity protection conditional access "
     "unusual activity suspicious"),

    # ── Identity & Authentication ─────────────────────────────────────────────
    ("step-up auth",
     "step-up authentication mfa challenge conditional access sensitive resource"),

    ("adaptive auth",
     "adaptive authentication risk-based mfa conditional access"),

    ("passwordless",
     "passwordless fido2 security key windows hello authentication"),

    ("continuous auth",
     "continuous authentication session re-evaluation conditional access"),

    # ── Data Governance ───────────────────────────────────────────────────────
    ("data classification",
     "data classification sensitivity label information protection dlp policy"),

    ("sensitivity label",
     "sensitivity label data classification information protection dlp encrypt"),

    ("information barrier",
     "information barrier dlp communication compliance data segmentation"),

    ("data sovereignty",
     "data sovereignty data residency region compliance geographic restriction"),

    # ── Endpoint & Device ─────────────────────────────────────────────────────
    ("unmanaged device",
     "unmanaged device byod conditional access device compliance mdm"),

    ("device compliance",
     "device compliance conditional access managed device intune mdm"),

    ("jailbreak",
     "jailbreak rooted device mdm endpoint compliance block"),

    # ── Threat & Incident ─────────────────────────────────────────────────────
    ("lateral movement",
     "lateral movement privileged access pam session monitoring detection"),

    ("impossible travel",
     "impossible travel risky sign-in identity protection anomaly alert"),

    ("brute force",
     "brute force password lockout account protection smart lockout"),

    ("credential stuffing",
     "credential stuffing password spray smart lockout identity protection"),

    # ── Sharing & Collaboration ───────────────────────────────────────────────
    ("oversharing",
     "oversharing external sharing dlp data classification sensitivity label"),

    ("guest sharing",
     "guest sharing external user access review conditional access"),

    ("email forwarding",
     "email forwarding mailbox rule exfiltration dlp transport rule"),

    # ── Privilege & Admin ─────────────────────────────────────────────────────
    ("standing access",
     "standing access just-in-time pim privileged access time-bound"),

    ("emergency access",
     "emergency access break glass privileged account admin"),

    ("shadow admin",
     "shadow admin privileged account access review role assignment"),

    # ── Compliance ────────────────────────────────────────────────────────────
    ("right to be forgotten",
     "right to be forgotten gdpr data deletion retention policy"),

    ("data minimisation",
     "data minimisation gdpr privacy dlp classification retention"),

    ("cross-border transfer",
     "cross-border transfer data residency gdpr compliance geographic"),

    # ── Explicit in-transit vs at-rest disambiguation ─────────────────────────
    ("in transit",
     "in transit network transport tls ssl https transport layer security "
     "wire encryption channel encryption data moving"),

    ("data in transit",
     "data in transit transport layer security tls ssl https network encryption "
     "data moving data transmitted wire channel"),

    ("transit encrypt",
     "transit encryption tls ssl https network transport security layer "
     "wire channel moving data"),

    ("cryptography and key management",
     "cryptography key management standards tls ssl transport encryption "
     "certificate pki in transit network security cipher"),
]


# ── Vendor Policy Name Library ───────────────────────────────────────────────
# When a policy has NO description (common with OOTB policies), this library
# provides semantic descriptions automatically keyed on the policy name.
# This solves the "short policy name vs long control text" mismatch.
# Add entries for your specific vendor's policy names here.

POLICY_NAME_LIBRARY = {
    # ── Salesforce — Identity & Authentication ────────────────────────────────
    "enable sso": (
        "Enable Single Sign-On SSO SAML federation centralized authentication "
        "identity provider all applications must federate"
    ),
    "enforce authentication through custom domain": (
        "Enforce SSO authentication through custom domain SAML identity provider "
        "federated login prevent direct salesforce login"
    ),
    "disable login with salesforce credentials": (
        "Disable native Salesforce credential login enforce SSO single sign-on "
        "identity provider federated authentication"
    ),
    "mfa": (
        "Multi-factor authentication MFA two-factor step-up enforced all users "
        "login verification second factor"
    ),
    "physical security key authentication": (
        "Physical security key FIDO2 hardware token phishing-resistant MFA "
        "step-up authentication privileged accounts"
    ),
    "enable authenticator passwordless login": (
        "Authenticator passwordless login lightning login FIDO MFA two-factor "
        "authentication step-up"
    ),
    "certificate-based authentication": (
        "Certificate-based authentication PKI x509 mutual TLS strong authentication "
        "MFA alternative"
    ),
    "identity verification with sms": (
        "SMS identity verification two-factor MFA step-up authentication "
        "second factor verification code"
    ),
    "force non-email verification methods": (
        "Force non-email MFA verification methods authenticator app security key "
        "phishing-resistant step-up"
    ),
    "require identity verification for email address change": (
        "Require identity verification MFA step-up for email address change "
        "account modification sensitive change"
    ),
    "email confirmations for email change": (
        "Email confirmation for email address change identity verification "
        "account security external users communities"
    ),
    # ── Salesforce — Session Management ──────────────────────────────────────
    "inactive sessions logout timeout": (
        "Inactive session logout timeout idle session expiry auto-logout "
        "session management controls"
    ),
    "inactive sessions logout": (
        "Inactive session logout timeout idle expiry session management "
        "auto-logout session controls"
    ),
    "profile inactive sessions logout timeout": (
        "Profile-level inactive session logout timeout idle expiry "
        "session management per profile"
    ),
    "session timeouts": (
        "Session timeout idle expiry management controls auto-logout "
        "re-authentication session duration"
    ),
    "enforce session termination on admin password reset": (
        "Enforce session termination terminate all sessions on admin password reset "
        "security incident response revoke session"
    ),
    "lock sessions to the domain in which they were first used": (
        "Lock session to originating domain session security prevent hijacking "
        "session binding"
    ),
    "re-login after login as user": (
        "Re-login after admin login-as-user session security admin access "
        "audit logging"
    ),
    "external client application- required session level": (
        "External client application required session level assurance "
        "MFA session security OAuth"
    ),
    # ── Salesforce — Password & Lockout ──────────────────────────────────────
    "lockout interval": (
        "Lockout interval account lockout duration brute force protection "
        "failed login attempts password policy"
    ),
    "profile lockout interval": (
        "Profile lockout interval per-profile account lockout duration "
        "brute force protection"
    ),
    "invalid login attempts": (
        "Invalid login attempts threshold account lockout brute force protection "
        "failed authentication password policy"
    ),
    "security check": (
        "Security health check password policy settings baseline configuration "
        "security posture assessment"
    ),
    "autocomplete user name": (
        "Autocomplete username disable credential exposure browser autofill "
        "login security"
    ),
    "password reset mechanism": (
        "Password reset mechanism self-service password reset alignment "
        "identity management standards procedures"
    ),
    # ── Salesforce — Access Control & IP Restriction ──────────────────────────
    "trusted ip ranges configuration": (
        "Trusted IP ranges configuration geofencing location-based access "
        "conditional access network restriction allowlist whitelist "
        "restrict login by location country"
    ),
    "high privilege profile ip restriction": (
        "High privilege profile IP restriction location-based access "
        "geofencing privileged access admin restriction trusted network"
    ),
    "non privilege profile ip restriction": (
        "Non-privilege profile IP restriction location-based access "
        "geofencing network restriction trusted IP"
    ),
    "connected application ip restriction": (
        "Connected application IP restriction geofencing location-based "
        "network restriction OAuth app access control"
    ),
    "external client application- ip restriction enforcement": (
        "External client application IP restriction enforcement geofencing "
        "location-based access network restriction"
    ),
    "login from known ip ranges on every page request": (
        "Login from known IP ranges every page request continuous location "
        "verification geofencing conditional access network"
    ),
    "limit connected apps api access": (
        "Limit connected apps API access allowlisted third-party integration "
        "OAuth restriction API governance"
    ),
    "restrict customers and partners api access": (
        "Restrict customers partners API access third-party integration "
        "external API restriction access control"
    ),
    "limit connected apps to specific profiles or permission sets": (
        "Limit connected apps specific profiles permission sets RBAC "
        "role-based access OAuth app restriction"
    ),
    "oauth connected apps with full access scope": (
        "OAuth connected apps full access scope third-party integration "
        "admin consent API permission restriction"
    ),
    "oauth username-password flows": (
        "OAuth username password flows legacy authentication disable "
        "insecure OAuth flow restriction"
    ),
    "oauth user-agent flow": (
        "OAuth user agent flow implicit flow legacy insecure "
        "restriction OAuth security"
    ),
    "oauth pkce requirement": (
        "OAuth PKCE requirement proof key code exchange secure OAuth "
        "authorization code flow security"
    ),
    "oauth credential flow": (
        "OAuth credential flow client credentials machine-to-machine "
        "API authentication restriction"
    ),
    "connected app uses non expiring refresh tokens": (
        "Connected app non-expiring refresh tokens token expiry "
        "session management OAuth token lifecycle"
    ),
    "external client application- single logout": (
        "External client application single logout SLO SSO federation "
        "session termination"
    ),
    "external client application- secret requirement": (
        "External client application secret requirement OAuth client secret "
        "API authentication credential"
    ),
    "external client application - introspect all tokens": (
        "External client application introspect tokens OAuth token validation "
        "security"
    ),
    "external client application - client credential flow": (
        "External client application client credential flow OAuth machine "
        "API authentication restriction"
    ),
    "named credentials anonymous authentication": (
        "Named credentials anonymous authentication restrict third-party "
        "integration credential management"
    ),
    # ── Salesforce — User Provisioning & Lifecycle ────────────────────────────
    "dormant users": (
        "Dormant users inactive account deprovisioning user lifecycle "
        "account management disable stale accounts"
    ),
    "users with login access to support": (
        "Users with login access to support admin access review "
        "privileged access governance"
    ),
    "admins log-in to other user's account": (
        "Admins login to other user account privileged access audit "
        "admin capability governance logging"
    ),
    "self registration for digital workspace site": (
        "Self-registration digital workspace external user provisioning "
        "user lifecycle community sites"
    ),
    "prevent using standard external profiles for self-registration and user creation": (
        "Prevent standard external profiles self-registration user creation "
        "user lifecycle provisioning governance"
    ),
    "user account provisioning": (
        "User account provisioning deprovisioning lifecycle management "
        "identity standards SCIM automation"
    ),
    # ── Salesforce — Permissions & Role-Based Access ──────────────────────────
    "field-level security for flexcards using soql data sources enforcement": (
        "Field-level security FLS SOQL data sources enforcement least privilege "
        "data access control attribute-based ABAC"
    ),
    "access controls on cached integration procedure metadata enforcement": (
        "Access controls cached integration procedure metadata enforcement "
        "least privilege RBAC permission"
    ),
    "remote action execution to authorized apex classes restriction": (
        "Remote action execution authorized Apex classes restriction "
        "least privilege code execution access control"
    ),
    "require permission to view record names in lookup fields": (
        "Require permission view record names lookup fields least privilege "
        "field-level access control"
    ),
    "role- and attribute-base access controls": (
        "Role attribute-based access controls RBAC ABAC least privilege "
        "identity management standards"
    ),
    # ── Salesforce — Data & Metadata Security ────────────────────────────────
    "restrict access to custom metadata types": (
        "Restrict access custom metadata types data governance access control "
        "least privilege"
    ),
    "restrict access to custom settings": (
        "Restrict access custom settings configuration security least privilege "
        "admin restriction"
    ),
    "disable sosl search on custom settings": (
        "Disable SOSL search custom settings data exposure restriction "
        "access control"
    ),
    "field-level security and encryption controls in data mappers enforcement": (
        "Field-level security encryption controls data mappers enforcement "
        "data protection least privilege OmniStudio"
    ),
    "excessive access to omnistudio data pack attachments": (
        "Excessive access OmniStudio data pack attachments least privilege "
        "data access governance"
    ),
    "permissions for nested integration procedure actions enforcement": (
        "Permissions nested integration procedure actions enforcement "
        "least privilege access control OmniStudio"
    ),
    "disable scale cache to prevent unauthorized execution of data mappers": (
        "Disable scale cache prevent unauthorized execution data mappers "
        "security control access restriction OmniStudio"
    ),
    # ── Salesforce — Network & Protocol Security ─────────────────────────────
    "remote sites protocol (http/s) security": (
        "Remote sites protocol HTTP HTTPS security TLS in-transit encryption "
        "network security remote endpoint"
    ),
    "remote endpoints (remote sites) without tls": (
        "Remote endpoints without TLS insecure HTTP protocol in-transit "
        "encryption network security"
    ),
    "warn on redirection out of salesforce": (
        "Warn redirection out of Salesforce external redirect security "
        "phishing protection"
    ),
    "require httponly attribute": (
        "Require HttpOnly attribute cookie security session security "
        "XSS protection"
    ),
    # ── Salesforce — Community & External Access ──────────────────────────────
    "community sites - guest users public chatter api access": (
        "Community sites guest users public Chatter API access external "
        "user restriction least privilege Digital Experience"
    ),
    "community sites - guest files access": (
        "Community sites guest files access external user restriction "
        "least privilege Digital Experience"
    ),
    "public report folders accessible by all users": (
        "Public report folders accessible all users least privilege "
        "data exposure restriction access control"
    ),
    "public dashboard folders accessible by all users": (
        "Public dashboard folders accessible all users least privilege "
        "data exposure restriction"
    ),
    "customer invitations to private groups": (
        "Customer invitations private groups external access governance "
        "community access control"
    ),
    # ── Salesforce Shield — Encryption at Rest ──────────────────────────────
    "[shield] encryption": (
        "Shield Platform Encryption Salesforce data at rest storage encrypt "
        "field encryption database encryption tenant secret key management "
        "NOT in transit NOT network NOT tls"
    ),
    "[shield] encryption - restrict access to encryption policy settings": (
        "Shield encryption policy settings access control restrict who can "
        "manage encryption configuration at rest storage"
    ),
    "[shield] encryption - encrypt event bus data": (
        "Shield encrypt event bus data at rest storage Salesforce Platform "
        "Encryption data stored NOT in transit NOT network"
    ),
    "[shield] encryption - encrypt search index files": (
        "Shield encrypt search index files at rest stored data Salesforce "
        "Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt field history and feed tracking": (
        "Shield encrypt field history feed tracking at rest stored Salesforce "
        "Platform Encryption NOT in transit"
    ),
    "[shield] encryption - encrypt data with the deterministic": (
        "Shield deterministic encryption at rest data stored field level "
        "Salesforce Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt files and attachments": (
        "Shield encrypt files attachments at rest stored Salesforce Platform "
        "Encryption NOT in transit NOT network"
    ),
    # ── Salesforce — Monitoring & Audit ──────────────────────────────────────
    "[shield] analytics - number of users with admin access to event monitoring": (
        "Shield analytics admin access event monitoring audit log "
        "privileged access logging"
    ),
    "[shield] analytics - number of users with read access to event monitoring": (
        "Shield analytics read access event monitoring audit logging "
        "security monitoring"
    ),
    "connected apps with user interface access": (
        "Connected apps user interface access OAuth third-party "
        "application access governance"
    ),
}


def enrich_policy_from_library(policy_name: str, existing_description: str) -> str:
    """
    Look up the policy name in POLICY_NAME_LIBRARY.
    If found AND the policy has no description (or a very short one),
    return the library description to augment encoding.
    Always appends library text — it never replaces a real description.
    """
    name_lower = policy_name.strip().lower()
    # Try exact match first
    if name_lower in POLICY_NAME_LIBRARY:
        lib_text = POLICY_NAME_LIBRARY[name_lower]
        if existing_description and len(existing_description.strip()) > 20:
            return existing_description + " " + lib_text
        return lib_text
    # Try partial match — if policy name contains a known key phrase
    for key, lib_text in POLICY_NAME_LIBRARY.items():
        if key in name_lower or name_lower in key:
            if existing_description and len(existing_description.strip()) > 20:
                return existing_description + " " + lib_text
            return lib_text
    return existing_description


def expand_concepts(text: str) -> str:
    """
    Expand high-level control concepts into policy-implementation vocabulary.
    Called AFTER expand_synonyms — adds bridging text at the end.
    Example:
      "geofencing must restrict access" →
      "geofencing must restrict access [geofencing location-based access
       conditional access trusted location ip range ...]"
    """
    import re
    t     = text.lower()
    extra = []
    for phrase, expansion in CONCEPT_BRIDGES:
        if re.search(phrase, t, flags=re.IGNORECASE):
            extra.append(expansion)
    if extra:
        return text + " " + " ".join(extra)
    return text


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — CONCEPT BRIDGES
# ═══════════════════════════════════════════════════════════════════════════════
CONCEPT_BRIDGES = [
    # ── Location & Network Access ─────────────────────────────────────────────
    ("geofenc",
     "geofencing location-based access conditional access trusted location "
     "ip range network location restriction country block"),

    ("location-based",
     "location-based access conditional access trusted location ip restriction "
     "named location country-based geofencing"),

    ("country.*block",
     "country block conditional access location policy geofencing ip restriction"),

    ("trusted location",
     "trusted location conditional access named location ip range geofencing"),

    ("network restriction",
     "network restriction ip range location conditional access allowlist"),

    # ── Risk-Based Access ─────────────────────────────────────────────────────
    ("risky sign",
     "risky sign-in risk-based conditional access identity protection "
     "risk policy anomalous login suspicious authentication block"),

    ("risky user",
     "risky user identity protection risk-based access conditional access "
     "compromised account high risk block"),

    ("risk-based access",
     "risk-based access conditional access identity protection sign-in risk "
     "user risk policy"),

    ("high risk",
     "high risk user sign-in risk identity protection conditional access "
     "block remediate"),

    ("compromised account",
     "compromised account risky user identity protection conditional access "
     "block revoke session"),

    ("anomalous login",
     "anomalous login risky sign-in identity protection conditional access "
     "unusual activity suspicious"),

    # ── Identity & Authentication ─────────────────────────────────────────────
    ("step-up auth",
     "step-up authentication mfa challenge conditional access sensitive resource"),

    ("adaptive auth",
     "adaptive authentication risk-based mfa conditional access"),

    ("passwordless",
     "passwordless fido2 security key windows hello authentication"),

    ("continuous auth",
     "continuous authentication session re-evaluation conditional access"),

    # ── Data Governance ───────────────────────────────────────────────────────
    ("data classification",
     "data classification sensitivity label information protection dlp policy"),

    ("sensitivity label",
     "sensitivity label data classification information protection dlp encrypt"),

    ("information barrier",
     "information barrier dlp communication compliance data segmentation"),

    ("data sovereignty",
     "data sovereignty data residency region compliance geographic restriction"),

    # ── Endpoint & Device ─────────────────────────────────────────────────────
    ("unmanaged device",
     "unmanaged device byod conditional access device compliance mdm"),

    ("device compliance",
     "device compliance conditional access managed device intune mdm"),

    ("jailbreak",
     "jailbreak rooted device mdm endpoint compliance block"),

    # ── Threat & Incident ─────────────────────────────────────────────────────
    ("lateral movement",
     "lateral movement privileged access pam session monitoring detection"),

    ("impossible travel",
     "impossible travel risky sign-in identity protection anomaly alert"),

    ("brute force",
     "brute force password lockout account protection smart lockout"),

    ("credential stuffing",
     "credential stuffing password spray smart lockout identity protection"),

    # ── Sharing & Collaboration ───────────────────────────────────────────────
    ("oversharing",
     "oversharing external sharing dlp data classification sensitivity label"),

    ("guest sharing",
     "guest sharing external user access review conditional access"),

    ("email forwarding",
     "email forwarding mailbox rule exfiltration dlp transport rule"),

    # ── Privilege & Admin ─────────────────────────────────────────────────────
    ("standing access",
     "standing access just-in-time pim privileged access time-bound"),

    ("emergency access",
     "emergency access break glass privileged account admin"),

    ("shadow admin",
     "shadow admin privileged account access review role assignment"),

    # ── Compliance ────────────────────────────────────────────────────────────
    ("right to be forgotten",
     "right to be forgotten gdpr data deletion retention policy"),

    ("data minimisation",
     "data minimisation gdpr privacy dlp classification retention"),

    ("cross-border transfer",
     "cross-border transfer data residency gdpr compliance geographic"),

    # ── Explicit in-transit vs at-rest disambiguation ─────────────────────────
    ("in transit",
     "in transit network transport tls ssl https transport layer security "
     "wire encryption channel encryption data moving"),

    ("data in transit",
     "data in transit transport layer security tls ssl https network encryption "
     "data moving data transmitted wire channel"),

    ("transit encrypt",
     "transit encryption tls ssl https network transport security layer "
     "wire channel moving data"),

    ("cryptography and key management",
     "cryptography key management standards tls ssl transport encryption "
     "certificate pki in transit network security cipher"),
]


# ── Vendor Policy Name Library ───────────────────────────────────────────────
# When a policy has NO description (common with OOTB policies), this library
# provides semantic descriptions automatically keyed on the policy name.
# This solves the "short policy name vs long control text" mismatch.
# Add entries for your specific vendor's policy names here.

POLICY_NAME_LIBRARY = {
    # ── Salesforce — Identity & Authentication ────────────────────────────────
    "enable sso": (
        "Enable Single Sign-On SSO SAML federation centralized authentication "
        "identity provider all applications must federate"
    ),
    "enforce authentication through custom domain": (
        "Enforce SSO authentication through custom domain SAML identity provider "
        "federated login prevent direct salesforce login"
    ),
    "disable login with salesforce credentials": (
        "Disable native Salesforce credential login enforce SSO single sign-on "
        "identity provider federated authentication"
    ),
    "mfa": (
        "Multi-factor authentication MFA two-factor step-up enforced all users "
        "login verification second factor"
    ),
    "physical security key authentication": (
        "Physical security key FIDO2 hardware token phishing-resistant MFA "
        "step-up authentication privileged accounts"
    ),
    "enable authenticator passwordless login": (
        "Authenticator passwordless login lightning login FIDO MFA two-factor "
        "authentication step-up"
    ),
    "certificate-based authentication": (
        "Certificate-based authentication PKI x509 mutual TLS strong authentication "
        "MFA alternative"
    ),
    "identity verification with sms": (
        "SMS identity verification two-factor MFA step-up authentication "
        "second factor verification code"
    ),
    "force non-email verification methods": (
        "Force non-email MFA verification methods authenticator app security key "
        "phishing-resistant step-up"
    ),
    "require identity verification for email address change": (
        "Require identity verification MFA step-up for email address change "
        "account modification sensitive change"
    ),
    "email confirmations for email change": (
        "Email confirmation for email address change identity verification "
        "account security external users communities"
    ),
    # ── Salesforce — Session Management ──────────────────────────────────────
    "inactive sessions logout timeout": (
        "Inactive session logout timeout idle session expiry auto-logout "
        "session management controls"
    ),
    "inactive sessions logout": (
        "Inactive session logout timeout idle expiry session management "
        "auto-logout session controls"
    ),
    "profile inactive sessions logout timeout": (
        "Profile-level inactive session logout timeout idle expiry "
        "session management per profile"
    ),
    "session timeouts": (
        "Session timeout idle expiry management controls auto-logout "
        "re-authentication session duration"
    ),
    "enforce session termination on admin password reset": (
        "Enforce session termination terminate all sessions on admin password reset "
        "security incident response revoke session"
    ),
    "lock sessions to the domain in which they were first used": (
        "Lock session to originating domain session security prevent hijacking "
        "session binding"
    ),
    "re-login after login as user": (
        "Re-login after admin login-as-user session security admin access "
        "audit logging"
    ),
    "external client application- required session level": (
        "External client application required session level assurance "
        "MFA session security OAuth"
    ),
    # ── Salesforce — Password & Lockout ──────────────────────────────────────
    "lockout interval": (
        "Lockout interval account lockout duration brute force protection "
        "failed login attempts password policy"
    ),
    "profile lockout interval": (
        "Profile lockout interval per-profile account lockout duration "
        "brute force protection"
    ),
    "invalid login attempts": (
        "Invalid login attempts threshold account lockout brute force protection "
        "failed authentication password policy"
    ),
    "security check": (
        "Security health check password policy settings baseline configuration "
        "security posture assessment"
    ),
    "autocomplete user name": (
        "Autocomplete username disable credential exposure browser autofill "
        "login security"
    ),
    "password reset mechanism": (
        "Password reset mechanism self-service password reset alignment "
        "identity management standards procedures"
    ),
    # ── Salesforce — Access Control & IP Restriction ──────────────────────────
    "trusted ip ranges configuration": (
        "Trusted IP ranges configuration geofencing location-based access "
        "conditional access network restriction allowlist whitelist "
        "restrict login by location country"
    ),
    "high privilege profile ip restriction": (
        "High privilege profile IP restriction location-based access "
        "geofencing privileged access admin restriction trusted network"
    ),
    "non privilege profile ip restriction": (
        "Non-privilege profile IP restriction location-based access "
        "geofencing network restriction trusted IP"
    ),
    "connected application ip restriction": (
        "Connected application IP restriction geofencing location-based "
        "network restriction OAuth app access control"
    ),
    "external client application- ip restriction enforcement": (
        "External client application IP restriction enforcement geofencing "
        "location-based access network restriction"
    ),
    "login from known ip ranges on every page request": (
        "Login from known IP ranges every page request continuous location "
        "verification geofencing conditional access network"
    ),
    "limit connected apps api access": (
        "Limit connected apps API access allowlisted third-party integration "
        "OAuth restriction API governance"
    ),
    "restrict customers and partners api access": (
        "Restrict customers partners API access third-party integration "
        "external API restriction access control"
    ),
    "limit connected apps to specific profiles or permission sets": (
        "Limit connected apps specific profiles permission sets RBAC "
        "role-based access OAuth app restriction"
    ),
    "oauth connected apps with full access scope": (
        "OAuth connected apps full access scope third-party integration "
        "admin consent API permission restriction"
    ),
    "oauth username-password flows": (
        "OAuth username password flows legacy authentication disable "
        "insecure OAuth flow restriction"
    ),
    "oauth user-agent flow": (
        "OAuth user agent flow implicit flow legacy insecure "
        "restriction OAuth security"
    ),
    "oauth pkce requirement": (
        "OAuth PKCE requirement proof key code exchange secure OAuth "
        "authorization code flow security"
    ),
    "oauth credential flow": (
        "OAuth credential flow client credentials machine-to-machine "
        "API authentication restriction"
    ),
    "connected app uses non expiring refresh tokens": (
        "Connected app non-expiring refresh tokens token expiry "
        "session management OAuth token lifecycle"
    ),
    "external client application- single logout": (
        "External client application single logout SLO SSO federation "
        "session termination"
    ),
    "external client application- secret requirement": (
        "External client application secret requirement OAuth client secret "
        "API authentication credential"
    ),
    "external client application - introspect all tokens": (
        "External client application introspect tokens OAuth token validation "
        "security"
    ),
    "external client application - client credential flow": (
        "External client application client credential flow OAuth machine "
        "API authentication restriction"
    ),
    "named credentials anonymous authentication": (
        "Named credentials anonymous authentication restrict third-party "
        "integration credential management"
    ),
    # ── Salesforce — User Provisioning & Lifecycle ────────────────────────────
    "dormant users": (
        "Dormant users inactive account deprovisioning user lifecycle "
        "account management disable stale accounts"
    ),
    "users with login access to support": (
        "Users with login access to support admin access review "
        "privileged access governance"
    ),
    "admins log-in to other user's account": (
        "Admins login to other user account privileged access audit "
        "admin capability governance logging"
    ),
    "self registration for digital workspace site": (
        "Self-registration digital workspace external user provisioning "
        "user lifecycle community sites"
    ),
    "prevent using standard external profiles for self-registration and user creation": (
        "Prevent standard external profiles self-registration user creation "
        "user lifecycle provisioning governance"
    ),
    "user account provisioning": (
        "User account provisioning deprovisioning lifecycle management "
        "identity standards SCIM automation"
    ),
    # ── Salesforce — Permissions & Role-Based Access ──────────────────────────
    "field-level security for flexcards using soql data sources enforcement": (
        "Field-level security FLS SOQL data sources enforcement least privilege "
        "data access control attribute-based ABAC"
    ),
    "access controls on cached integration procedure metadata enforcement": (
        "Access controls cached integration procedure metadata enforcement "
        "least privilege RBAC permission"
    ),
    "remote action execution to authorized apex classes restriction": (
        "Remote action execution authorized Apex classes restriction "
        "least privilege code execution access control"
    ),
    "require permission to view record names in lookup fields": (
        "Require permission view record names lookup fields least privilege "
        "field-level access control"
    ),
    "role- and attribute-base access controls": (
        "Role attribute-based access controls RBAC ABAC least privilege "
        "identity management standards"
    ),
    # ── Salesforce — Data & Metadata Security ────────────────────────────────
    "restrict access to custom metadata types": (
        "Restrict access custom metadata types data governance access control "
        "least privilege"
    ),
    "restrict access to custom settings": (
        "Restrict access custom settings configuration security least privilege "
        "admin restriction"
    ),
    "disable sosl search on custom settings": (
        "Disable SOSL search custom settings data exposure restriction "
        "access control"
    ),
    "field-level security and encryption controls in data mappers enforcement": (
        "Field-level security encryption controls data mappers enforcement "
        "data protection least privilege OmniStudio"
    ),
    "excessive access to omnistudio data pack attachments": (
        "Excessive access OmniStudio data pack attachments least privilege "
        "data access governance"
    ),
    "permissions for nested integration procedure actions enforcement": (
        "Permissions nested integration procedure actions enforcement "
        "least privilege access control OmniStudio"
    ),
    "disable scale cache to prevent unauthorized execution of data mappers": (
        "Disable scale cache prevent unauthorized execution data mappers "
        "security control access restriction OmniStudio"
    ),
    # ── Salesforce — Network & Protocol Security ─────────────────────────────
    "remote sites protocol (http/s) security": (
        "Remote sites protocol HTTP HTTPS security TLS in-transit encryption "
        "network security remote endpoint"
    ),
    "remote endpoints (remote sites) without tls": (
        "Remote endpoints without TLS insecure HTTP protocol in-transit "
        "encryption network security"
    ),
    "warn on redirection out of salesforce": (
        "Warn redirection out of Salesforce external redirect security "
        "phishing protection"
    ),
    "require httponly attribute": (
        "Require HttpOnly attribute cookie security session security "
        "XSS protection"
    ),
    # ── Salesforce — Community & External Access ──────────────────────────────
    "community sites - guest users public chatter api access": (
        "Community sites guest users public Chatter API access external "
        "user restriction least privilege Digital Experience"
    ),
    "community sites - guest files access": (
        "Community sites guest files access external user restriction "
        "least privilege Digital Experience"
    ),
    "public report folders accessible by all users": (
        "Public report folders accessible all users least privilege "
        "data exposure restriction access control"
    ),
    "public dashboard folders accessible by all users": (
        "Public dashboard folders accessible all users least privilege "
        "data exposure restriction"
    ),
    "customer invitations to private groups": (
        "Customer invitations private groups external access governance "
        "community access control"
    ),
    # ── Salesforce Shield — Encryption at Rest ──────────────────────────────
    "[shield] encryption": (
        "Shield Platform Encryption Salesforce data at rest storage encrypt "
        "field encryption database encryption tenant secret key management "
        "NOT in transit NOT network NOT tls"
    ),
    "[shield] encryption - restrict access to encryption policy settings": (
        "Shield encryption policy settings access control restrict who can "
        "manage encryption configuration at rest storage"
    ),
    "[shield] encryption - encrypt event bus data": (
        "Shield encrypt event bus data at rest storage Salesforce Platform "
        "Encryption data stored NOT in transit NOT network"
    ),
    "[shield] encryption - encrypt search index files": (
        "Shield encrypt search index files at rest stored data Salesforce "
        "Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt field history and feed tracking": (
        "Shield encrypt field history feed tracking at rest stored Salesforce "
        "Platform Encryption NOT in transit"
    ),
    "[shield] encryption - encrypt data with the deterministic": (
        "Shield deterministic encryption at rest data stored field level "
        "Salesforce Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt files and attachments": (
        "Shield encrypt files attachments at rest stored Salesforce Platform "
        "Encryption NOT in transit NOT network"
    ),
    # ── Salesforce — Monitoring & Audit ──────────────────────────────────────
    "[shield] analytics - number of users with admin access to event monitoring": (
        "Shield analytics admin access event monitoring audit log "
        "privileged access logging"
    ),
    "[shield] analytics - number of users with read access to event monitoring": (
        "Shield analytics read access event monitoring audit logging "
        "security monitoring"
    ),
    "connected apps with user interface access": (
        "Connected apps user interface access OAuth third-party "
        "application access governance"
    ),
}


def enrich_policy_from_library(policy_name: str, existing_description: str) -> str:
    """
    Look up the policy name in POLICY_NAME_LIBRARY.
    If found AND the policy has no description (or a very short one),
    return the library description to augment encoding.
    Always appends library text — it never replaces a real description.
    """
    name_lower = policy_name.strip().lower()
    # Try exact match first
    if name_lower in POLICY_NAME_LIBRARY:
        lib_text = POLICY_NAME_LIBRARY[name_lower]
        if existing_description and len(existing_description.strip()) > 20:
            return existing_description + " " + lib_text
        return lib_text
    # Try partial match — if policy name contains a known key phrase
    for key, lib_text in POLICY_NAME_LIBRARY.items():
        if key in name_lower or name_lower in key:
            if existing_description and len(existing_description.strip()) > 20:
                return existing_description + " " + lib_text
            return lib_text
    return existing_description


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — KEYWORD GROUPS
# ═══════════════════════════════════════════════════════════════════════════════
KEYWORD_GROUPS = {
    # ── Authentication & Identity ─────────────────────────────────────────────
    "mfa": [
        "mfa","multi-factor","two-factor","2fa","step-up","step up auth",
        "hardware token","fido","fido2","authenticator app","otp",
        "one-time password","totp","phishing-resistant","passwordless",
        "security key","verification code","second factor","strong auth",
        "adaptive auth","risk-based auth","challenge","verify identity"
    ],
    "legacy_auth": [
        "legacy auth","basic auth","smtp auth","imap","pop3","ntlm","kerberos",
        "disable authentication","block protocol","old protocol","legacy protocol",
        "deprecated auth","insecure protocol","cleartext","unencrypted auth"
    ],
    "sso_federation": [
        "sso","single sign-on","saml","saml 2.0","federation","idp",
        "identity provider","conditional access","azure ad","okta","ping",
        "oidc","openid connect","oauth 2.0","identity federation","centralized auth"
    ],
    "password_policy": [
        "password","passphrase","complexity","rotation","expir","minimum length",
        "uppercase","special character","credential","password strength",
        "password reuse","password history","lockout","brute force",
        "account lockout","failed login","password reset","change password"
    ],
    # ── Access & Authorization ────────────────────────────────────────────────
    "access_control": [
        "rbac","least privilege","role-based","permission","authoriz",
        "allowlist","whitelist","ip range","just-in-time","pim","jit",
        "privilege","entitlement","access restriction","access policy",
        "access rights","user rights","group policy","access review",
        "segregation of duties","need to know","zero trust","access management",
        "geofenc","location-based","trusted location","named location",
        "conditional access","country block","network restriction",
        "trusted network","ip address restriction","login ip","ip ranges"
    ],
    "risk_based_access": [
        "risky sign","risky user","risk-based","high risk","identity protection",
        "sign-in risk","user risk","compromised","impossible travel",
        "anomalous login","suspicious login","adaptive auth","step-up",
        "continuous auth","risk policy","risk score","threat detection login",
        "risk remediat","block risky","enforce mfa risky"
    ],
    "privileged_access": [
        "privileged","admin","administrator","root","superuser","elevated",
        "privileged account","service account","break glass","emergency access",
        "standing privilege","time-bound","approval workflow","pam",
        "admin console","admin panel","elevated access"
    ],
    "user_lifecycle": [
        "provisioning","deprovisioning","scim","joiner","mover","leaver",
        "onboard","offboard","account lifecycle","user management",
        "account creation","account deletion","access revocation",
        "terminate access","disable account","role assignment","automate user"
    ],
    "session": [
        "session","timeout","idle","expiry","inactivity","auto-logout",
        "re-authentication","session duration","session management",
        "session token","persistent session","remember me","cookie"
    ],
    # ── Data Protection ───────────────────────────────────────────────────────
    "dlp": [
        "dlp","data loss prevention","sensitive data","pii","phi","pci",
        "classified","confidential","data exfiltration","information barrier",
        "personally identifiable","protected health","cardholder data",
        "sensitive information","data leakage","prevent disclosure",
        "data classification","information protection","sensitivity label"
    ],
    "external_sharing": [
        "external sharing","public link","anonymous access","guest access",
        "forwarding","share externally","data transfer","egress",
        "external user","outside organisation","third party sharing",
        "public access","open access","unrestricted sharing","outbound"
    ],
    # Split into sub-groups — at_rest and in_transit are DIFFERENT controls
    "encryption_at_rest": [
        # Generic at-rest terms — must be SPECIFIC to stored data, not general
        "at rest","storage encrypt","data stored","disk encrypt","database encrypt",
        "encrypted storage","encrypt stored","encrypt database","encrypt file",
        "encrypt volume","transparent data","data at rest","rest encryption",
        "encrypt field","encrypt column",
        # Salesforce Shield Encryption — all at-rest
        "shield encrypt","shield] encrypt","event bus","search index",
        "field history","feed tracking","deterministic","probabilistic",
        "encrypt data with","platform encryption","key management hierarchy",
        "tenant secret","data encryption key","encrypt attachment",
        "encrypt chatter","encrypt files","encrypt custom fields",
        "restrict access to encryption","encryption policy settings",
        # Other vendor at-rest terms
        "volume encrypt","block storage","object storage encrypt",
        "blob encrypt","s3 encrypt","rds encrypt","cmk",
        "customer managed key","bring your own key","byok",
        "database transparent","tde","column level","row level encrypt"
    ],
    "encryption_in_transit": [
        "in transit","tls","ssl","https","transport","network encrypt",
        "data transmitted","encrypt communication","end-to-end","e2e",
        "channel encrypt","transport security","in-flight","in-transit",
        "data in motion","wire encrypt"
    ],
    "encryption_general": [
        "encrypt","cipher","aes","certificate","tokenization","encryption key",
        "cryptograph","key rotation","hsm","pkcs","x509",
        "kms","key management","cryptography","platform encryption"
    ],
    "data_residency": [
        "data residency","data sovereignty","region","country",
        "cross-border","transborder","eu","gdpr transfer","data location",
        "store data","data centre","regional","local storage",
        "geographic restriction","data geography"
    ],
    # ── Logging & Monitoring ──────────────────────────────────────────────────
    "audit_logging": [
        "audit","audit log","audit trail","unified log","log retention",
        "activity log","siem","log streaming","event log","logging",
        "log management","centralized logging","log archive","event record",
        "activity record","retain log","12 month","90 day",
        "immutable log","tamper-proof","non-repudiation"
    ],
    "monitoring_alerting": [
        "monitor","alert","anomaly","suspicious","detect","threat intel",
        "impossible travel","behavioural","unusual activity","real-time",
        "detection","notification","alarm","flag","investigate",
        "security monitoring","continuous monitoring","event correlation"
    ],
    # ── Incident & Threat ─────────────────────────────────────────────────────
    "incident_response": [
        "incident","breach","compromise","response","contain","remediat",
        "session termination","revoke","block user","incident management",
        "security incident","data breach","intrusion","isolate","quarantine",
        "recovery","restore","eradicate","post-incident"
    ],
    "threat_protection": [
        "malware","phishing","safe link","safe attachment","anti-spam",
        "defender","threat protection","sandbox","url scan","antivirus",
        "anti-malware","zero-day","ransomware","spyware","trojan",
        "email security","link protection","attachment scanning"
    ],
    # ── Integration & Apps ────────────────────────────────────────────────────
    "third_party": [
        "third-party","oauth","api access","integration","connector",
        "app permission","marketplace","connected app","admin consent",
        "external application","api key","webhook","plugin","add-on",
        "authorised app","approved app","app review","vendor access"
    ],
    # ── Infrastructure ────────────────────────────────────────────────────────
    "endpoint_device": [
        "device","endpoint","mdm","mobile","jailbreak","compliance device",
        "managed device","byod","remote wipe","device management",
        "intune","device policy","device registration","corporate device"
    ],
    "network_security": [
        "firewall","network","vpn","ip restriction","segmentation",
        "dmz","ingress","egress","private endpoint","network access",
        "network policy","subnet","vlan","network zone"
    ],
    # ── Compliance & Governance ───────────────────────────────────────────────
    "compliance_retention": [
        "compliance","retention","ediscovery","legal hold","gdpr","hipaa",
        "sox","iso 27001","nist csf","regulatory","data residency",
        "pci dss","audit requirement","regulatory requirement",
        "compliance policy","archival","preservation","discovery"
    ],
    "governance": [
        "governance","policy","procedure","standard","framework","review",
        "approval","accountability","ownership","responsibility",
        "risk management","security policy","information security"
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — POLICY NAME LIBRARY
# ═══════════════════════════════════════════════════════════════════════════════
POLICY_NAME_LIBRARY = {
    # ── Salesforce — Identity & Authentication ────────────────────────────────
    "enable sso": (
        "Enable Single Sign-On SSO SAML federation centralized authentication "
        "identity provider all applications must federate"
    ),
    "enforce authentication through custom domain": (
        "Enforce SSO authentication through custom domain SAML identity provider "
        "federated login prevent direct salesforce login"
    ),
    "disable login with salesforce credentials": (
        "Disable native Salesforce credential login enforce SSO single sign-on "
        "identity provider federated authentication"
    ),
    "mfa": (
        "Multi-factor authentication MFA two-factor step-up enforced all users "
        "login verification second factor"
    ),
    "physical security key authentication": (
        "Physical security key FIDO2 hardware token phishing-resistant MFA "
        "step-up authentication privileged accounts"
    ),
    "enable authenticator passwordless login": (
        "Authenticator passwordless login lightning login FIDO MFA two-factor "
        "authentication step-up"
    ),
    "certificate-based authentication": (
        "Certificate-based authentication PKI x509 mutual TLS strong authentication "
        "MFA alternative"
    ),
    "identity verification with sms": (
        "SMS identity verification two-factor MFA step-up authentication "
        "second factor verification code"
    ),
    "force non-email verification methods": (
        "Force non-email MFA verification methods authenticator app security key "
        "phishing-resistant step-up"
    ),
    "require identity verification for email address change": (
        "Require identity verification MFA step-up for email address change "
        "account modification sensitive change"
    ),
    "email confirmations for email change": (
        "Email confirmation for email address change identity verification "
        "account security external users communities"
    ),
    # ── Salesforce — Session Management ──────────────────────────────────────
    "inactive sessions logout timeout": (
        "Inactive session logout timeout idle session expiry auto-logout "
        "session management controls"
    ),
    "inactive sessions logout": (
        "Inactive session logout timeout idle expiry session management "
        "auto-logout session controls"
    ),
    "profile inactive sessions logout timeout": (
        "Profile-level inactive session logout timeout idle expiry "
        "session management per profile"
    ),
    "session timeouts": (
        "Session timeout idle expiry management controls auto-logout "
        "re-authentication session duration"
    ),
    "enforce session termination on admin password reset": (
        "Enforce session termination terminate all sessions on admin password reset "
        "security incident response revoke session"
    ),
    "lock sessions to the domain in which they were first used": (
        "Lock session to originating domain session security prevent hijacking "
        "session binding"
    ),
    "re-login after login as user": (
        "Re-login after admin login-as-user session security admin access "
        "audit logging"
    ),
    "external client application- required session level": (
        "External client application required session level assurance "
        "MFA session security OAuth"
    ),
    # ── Salesforce — Password & Lockout ──────────────────────────────────────
    "lockout interval": (
        "Lockout interval account lockout duration brute force protection "
        "failed login attempts password policy"
    ),
    "profile lockout interval": (
        "Profile lockout interval per-profile account lockout duration "
        "brute force protection"
    ),
    "invalid login attempts": (
        "Invalid login attempts threshold account lockout brute force protection "
        "failed authentication password policy"
    ),
    "security check": (
        "Security health check password policy settings baseline configuration "
        "security posture assessment"
    ),
    "autocomplete user name": (
        "Autocomplete username disable credential exposure browser autofill "
        "login security"
    ),
    "password reset mechanism": (
        "Password reset mechanism self-service password reset alignment "
        "identity management standards procedures"
    ),
    # ── Salesforce — Access Control & IP Restriction ──────────────────────────
    "trusted ip ranges configuration": (
        "Trusted IP ranges configuration geofencing location-based access "
        "conditional access network restriction allowlist whitelist "
        "restrict login by location country"
    ),
    "high privilege profile ip restriction": (
        "High privilege profile IP restriction location-based access "
        "geofencing privileged access admin restriction trusted network"
    ),
    "non privilege profile ip restriction": (
        "Non-privilege profile IP restriction location-based access "
        "geofencing network restriction trusted IP"
    ),
    "connected application ip restriction": (
        "Connected application IP restriction geofencing location-based "
        "network restriction OAuth app access control"
    ),
    "external client application- ip restriction enforcement": (
        "External client application IP restriction enforcement geofencing "
        "location-based access network restriction"
    ),
    "login from known ip ranges on every page request": (
        "Login from known IP ranges every page request continuous location "
        "verification geofencing conditional access network"
    ),
    "limit connected apps api access": (
        "Limit connected apps API access allowlisted third-party integration "
        "OAuth restriction API governance"
    ),
    "restrict customers and partners api access": (
        "Restrict customers partners API access third-party integration "
        "external API restriction access control"
    ),
    "limit connected apps to specific profiles or permission sets": (
        "Limit connected apps specific profiles permission sets RBAC "
        "role-based access OAuth app restriction"
    ),
    "oauth connected apps with full access scope": (
        "OAuth connected apps full access scope third-party integration "
        "admin consent API permission restriction"
    ),
    "oauth username-password flows": (
        "OAuth username password flows legacy authentication disable "
        "insecure OAuth flow restriction"
    ),
    "oauth user-agent flow": (
        "OAuth user agent flow implicit flow legacy insecure "
        "restriction OAuth security"
    ),
    "oauth pkce requirement": (
        "OAuth PKCE requirement proof key code exchange secure OAuth "
        "authorization code flow security"
    ),
    "oauth credential flow": (
        "OAuth credential flow client credentials machine-to-machine "
        "API authentication restriction"
    ),
    "connected app uses non expiring refresh tokens": (
        "Connected app non-expiring refresh tokens token expiry "
        "session management OAuth token lifecycle"
    ),
    "external client application- single logout": (
        "External client application single logout SLO SSO federation "
        "session termination"
    ),
    "external client application- secret requirement": (
        "External client application secret requirement OAuth client secret "
        "API authentication credential"
    ),
    "external client application - introspect all tokens": (
        "External client application introspect tokens OAuth token validation "
        "security"
    ),
    "external client application - client credential flow": (
        "External client application client credential flow OAuth machine "
        "API authentication restriction"
    ),
    "named credentials anonymous authentication": (
        "Named credentials anonymous authentication restrict third-party "
        "integration credential management"
    ),
    # ── Salesforce — User Provisioning & Lifecycle ────────────────────────────
    "dormant users": (
        "Dormant users inactive account deprovisioning user lifecycle "
        "account management disable stale accounts"
    ),
    "users with login access to support": (
        "Users with login access to support admin access review "
        "privileged access governance"
    ),
    "admins log-in to other user's account": (
        "Admins login to other user account privileged access audit "
        "admin capability governance logging"
    ),
    "self registration for digital workspace site": (
        "Self-registration digital workspace external user provisioning "
        "user lifecycle community sites"
    ),
    "prevent using standard external profiles for self-registration and user creation": (
        "Prevent standard external profiles self-registration user creation "
        "user lifecycle provisioning governance"
    ),
    "user account provisioning": (
        "User account provisioning deprovisioning lifecycle management "
        "identity standards SCIM automation"
    ),
    # ── Salesforce — Permissions & Role-Based Access ──────────────────────────
    "field-level security for flexcards using soql data sources enforcement": (
        "Field-level security FLS SOQL data sources enforcement least privilege "
        "data access control attribute-based ABAC"
    ),
    "access controls on cached integration procedure metadata enforcement": (
        "Access controls cached integration procedure metadata enforcement "
        "least privilege RBAC permission"
    ),
    "remote action execution to authorized apex classes restriction": (
        "Remote action execution authorized Apex classes restriction "
        "least privilege code execution access control"
    ),
    "require permission to view record names in lookup fields": (
        "Require permission view record names lookup fields least privilege "
        "field-level access control"
    ),
    "role- and attribute-base access controls": (
        "Role attribute-based access controls RBAC ABAC least privilege "
        "identity management standards"
    ),
    # ── Salesforce — Data & Metadata Security ────────────────────────────────
    "restrict access to custom metadata types": (
        "Restrict access custom metadata types data governance access control "
        "least privilege"
    ),
    "restrict access to custom settings": (
        "Restrict access custom settings configuration security least privilege "
        "admin restriction"
    ),
    "disable sosl search on custom settings": (
        "Disable SOSL search custom settings data exposure restriction "
        "access control"
    ),
    "field-level security and encryption controls in data mappers enforcement": (
        "Field-level security encryption controls data mappers enforcement "
        "data protection least privilege OmniStudio"
    ),
    "excessive access to omnistudio data pack attachments": (
        "Excessive access OmniStudio data pack attachments least privilege "
        "data access governance"
    ),
    "permissions for nested integration procedure actions enforcement": (
        "Permissions nested integration procedure actions enforcement "
        "least privilege access control OmniStudio"
    ),
    "disable scale cache to prevent unauthorized execution of data mappers": (
        "Disable scale cache prevent unauthorized execution data mappers "
        "security control access restriction OmniStudio"
    ),
    # ── Salesforce — Network & Protocol Security ─────────────────────────────
    "remote sites protocol (http/s) security": (
        "Remote sites protocol HTTP HTTPS security TLS in-transit encryption "
        "network security remote endpoint"
    ),
    "remote endpoints (remote sites) without tls": (
        "Remote endpoints without TLS insecure HTTP protocol in-transit "
        "encryption network security"
    ),
    "warn on redirection out of salesforce": (
        "Warn redirection out of Salesforce external redirect security "
        "phishing protection"
    ),
    "require httponly attribute": (
        "Require HttpOnly attribute cookie security session security "
        "XSS protection"
    ),
    # ── Salesforce — Community & External Access ──────────────────────────────
    "community sites - guest users public chatter api access": (
        "Community sites guest users public Chatter API access external "
        "user restriction least privilege Digital Experience"
    ),
    "community sites - guest files access": (
        "Community sites guest files access external user restriction "
        "least privilege Digital Experience"
    ),
    "public report folders accessible by all users": (
        "Public report folders accessible all users least privilege "
        "data exposure restriction access control"
    ),
    "public dashboard folders accessible by all users": (
        "Public dashboard folders accessible all users least privilege "
        "data exposure restriction"
    ),
    "customer invitations to private groups": (
        "Customer invitations private groups external access governance "
        "community access control"
    ),
    # ── Salesforce Shield — Encryption at Rest ──────────────────────────────
    "[shield] encryption": (
        "Shield Platform Encryption Salesforce data at rest storage encrypt "
        "field encryption database encryption tenant secret key management "
        "NOT in transit NOT network NOT tls"
    ),
    "[shield] encryption - restrict access to encryption policy settings": (
        "Shield encryption policy settings access control restrict who can "
        "manage encryption configuration at rest storage"
    ),
    "[shield] encryption - encrypt event bus data": (
        "Shield encrypt event bus data at rest storage Salesforce Platform "
        "Encryption data stored NOT in transit NOT network"
    ),
    "[shield] encryption - encrypt search index files": (
        "Shield encrypt search index files at rest stored data Salesforce "
        "Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt field history and feed tracking": (
        "Shield encrypt field history feed tracking at rest stored Salesforce "
        "Platform Encryption NOT in transit"
    ),
    "[shield] encryption - encrypt data with the deterministic": (
        "Shield deterministic encryption at rest data stored field level "
        "Salesforce Platform Encryption NOT in transit NOT tls"
    ),
    "[shield] encryption - encrypt files and attachments": (
        "Shield encrypt files attachments at rest stored Salesforce Platform "
        "Encryption NOT in transit NOT network"
    ),
    # ── Salesforce — Monitoring & Audit ──────────────────────────────────────
    "[shield] analytics - number of users with admin access to event monitoring": (
        "Shield analytics admin access event monitoring audit log "
        "privileged access logging"
    ),
    "[shield] analytics - number of users with read access to event monitoring": (
        "Shield analytics read access event monitoring audit logging "
        "security monitoring"
    ),
    "connected apps with user interface access": (
        "Connected apps user interface access OAuth third-party "
        "application access governance"
    ),
}
