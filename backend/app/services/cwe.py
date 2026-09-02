"""MITRE CWE weakness classification.

Ships an offline catalogue of the weaknesses FixNex's adapters actually
emit, so classification works with no network access. Unknown identifiers are
still accepted and linked to cwe.mitre.org.
"""
from __future__ import annotations

CWE_CATALOGUE: dict[str, dict[str, str]] = {
    "CWE-20": {"name": "Improper Input Validation", "category": "Input Validation"},
    "CWE-22": {"name": "Path Traversal", "category": "Injection"},
    "CWE-78": {"name": "OS Command Injection", "category": "Injection"},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "category": "Injection"},
    "CWE-89": {"name": "SQL Injection", "category": "Injection"},
    "CWE-90": {"name": "LDAP Injection", "category": "Injection"},
    "CWE-94": {"name": "Code Injection", "category": "Injection"},
    "CWE-98": {"name": "PHP Remote File Inclusion", "category": "Injection"},
    "CWE-119": {"name": "Improper Restriction of Operations within Memory Buffer", "category": "Memory Safety"},
    "CWE-190": {"name": "Integer Overflow or Wraparound", "category": "Memory Safety"},
    "CWE-200": {"name": "Exposure of Sensitive Information to an Unauthorized Actor", "category": "Information Disclosure"},
    "CWE-209": {"name": "Generation of Error Message Containing Sensitive Information", "category": "Information Disclosure"},
    "CWE-256": {"name": "Plaintext Storage of a Password", "category": "Cryptography"},
    "CWE-269": {"name": "Improper Privilege Management", "category": "Access Control"},
    "CWE-284": {"name": "Improper Access Control", "category": "Access Control"},
    "CWE-287": {"name": "Improper Authentication", "category": "Authentication"},
    "CWE-295": {"name": "Improper Certificate Validation", "category": "Cryptography"},
    "CWE-297": {"name": "Improper Validation of Certificate with Host Mismatch", "category": "Cryptography"},
    "CWE-298": {"name": "Improper Validation of Certificate Expiration", "category": "Cryptography"},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "category": "Authentication"},
    "CWE-311": {"name": "Missing Encryption of Sensitive Data", "category": "Cryptography"},
    "CWE-319": {"name": "Cleartext Transmission of Sensitive Information", "category": "Cryptography"},
    "CWE-326": {"name": "Inadequate Encryption Strength", "category": "Cryptography"},
    "CWE-327": {"name": "Use of a Broken or Risky Cryptographic Algorithm", "category": "Cryptography"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "category": "Session Management"},
    "CWE-359": {"name": "Exposure of Private Personal Information", "category": "Information Disclosure"},
    "CWE-384": {"name": "Session Fixation", "category": "Session Management"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "category": "Availability"},
    "CWE-434": {"name": "Unrestricted Upload of File with Dangerous Type", "category": "Input Validation"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "Injection"},
    "CWE-521": {"name": "Weak Password Requirements", "category": "Authentication"},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "category": "Authentication"},
    "CWE-548": {"name": "Exposure of Information Through Directory Listing", "category": "Information Disclosure"},
    "CWE-565": {"name": "Reliance on Cookies without Validation and Integrity Checking", "category": "Session Management"},
    "CWE-601": {"name": "URL Redirection to Untrusted Site (Open Redirect)", "category": "Input Validation"},
    "CWE-611": {"name": "Improper Restriction of XML External Entity Reference (XXE)", "category": "Injection"},
    "CWE-613": {"name": "Insufficient Session Expiration", "category": "Session Management"},
    "CWE-614": {"name": "Sensitive Cookie Without 'Secure' Attribute", "category": "Session Management"},
    "CWE-639": {"name": "Authorization Bypass Through User-Controlled Key (IDOR)", "category": "Access Control"},
    "CWE-668": {"name": "Exposure of Resource to Wrong Sphere", "category": "Network Exposure"},
    "CWE-693": {"name": "Protection Mechanism Failure", "category": "Security Misconfiguration"},
    "CWE-732": {"name": "Incorrect Permission Assignment for Critical Resource", "category": "Access Control"},
    "CWE-778": {"name": "Insufficient Logging", "category": "Logging & Monitoring"},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "category": "Authentication"},
    "CWE-829": {"name": "Inclusion of Functionality from Untrusted Control Sphere", "category": "Supply Chain"},
    "CWE-862": {"name": "Missing Authorization", "category": "Access Control"},
    "CWE-863": {"name": "Incorrect Authorization", "category": "Access Control"},
    "CWE-915": {"name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes", "category": "Input Validation"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "category": "Injection"},
    "CWE-942": {"name": "Permissive Cross-domain Policy with Untrusted Domains", "category": "Security Misconfiguration"},
    "CWE-1004": {"name": "Sensitive Cookie Without 'HttpOnly' Flag", "category": "Session Management"},
    "CWE-1021": {"name": "Improper Restriction of Rendered UI Layers (Clickjacking)", "category": "Security Misconfiguration"},
    "CWE-1275": {"name": "Sensitive Cookie with Improper SameSite Attribute", "category": "Session Management"},
}

# Keyword fallback so a scanner that reports no CWE still gets classified.
_TITLE_HEURISTICS: list[tuple[tuple[str, ...], str]] = [
    (("sql injection", "sqli"), "CWE-89"),
    (("cross-site scripting", "xss"), "CWE-79"),
    (("command injection", "os command"), "CWE-78"),
    (("path traversal", "directory traversal", "lfi"), "CWE-22"),
    (("server-side request forgery", "ssrf"), "CWE-918"),
    (("xml external entity", "xxe"), "CWE-611"),
    (("open redirect",), "CWE-601"),
    (("csrf", "cross-site request forgery"), "CWE-352"),
    (("deserializ",), "CWE-502"),
    (("directory listing", "directory index"), "CWE-548"),
    (("clickjack", "x-frame-options", "frame-ancestors"), "CWE-1021"),
    (("httponly",), "CWE-1004"),
    (("samesite",), "CWE-1275"),
    (("secure attribute", "secure flag"), "CWE-614"),
    (("cors", "cross-origin resource sharing"), "CWE-942"),
    (("hsts", "strict-transport-security", "cleartext"), "CWE-319"),
    (("certificate",), "CWE-295"),
    (("cipher", "tls version", "ssl version", "weak encryption"), "CWE-327"),
    (("information disclosure", "version disclosure", "banner"), "CWE-200"),
    (("default credential", "hard-coded", "hardcoded password"), "CWE-798"),
    (("authentication",), "CWE-287"),
    (("authorization", "access control", "idor"), "CWE-284"),
    (("open port", "exposed service"), "CWE-668"),
    (("content-security-policy", "csp"), "CWE-693"),
]


def normalize_cwe_id(value: str | int | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if not text:
        return None
    if text.startswith("CWE-"):
        text = text[4:]
    if not text.isdigit():
        return None
    return f"CWE-{int(text)}"


def lookup(cwe_id: str | None) -> dict | None:
    normalized = normalize_cwe_id(cwe_id)
    if not normalized:
        return None
    entry = CWE_CATALOGUE.get(normalized)
    number = normalized.split("-")[1]
    return {
        "id": normalized,
        "name": entry["name"] if entry else f"CWE-{number}",
        "category": entry["category"] if entry else "Other",
        "url": f"https://cwe.mitre.org/data/definitions/{number}.html",
        "known": entry is not None,
    }


def infer_from_text(*texts: str | None) -> str | None:
    """Best-effort CWE classification from a finding title / description."""
    haystack = " ".join(t.lower() for t in texts if t)
    if not haystack:
        return None
    for keywords, cwe_id in _TITLE_HEURISTICS:
        if any(keyword in haystack for keyword in keywords):
            return cwe_id
    return None


def category_for(cwe_id: str | None) -> str | None:
    entry = lookup(cwe_id)
    return entry["category"] if entry else None
