"""Shared helpers: domain arithmetic, IP classification, string distance."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public-suffix handling
# ---------------------------------------------------------------------------
# A full Public Suffix List would add a dependency and a 230 KB data file.
# For header forensics a curated list of common multi-label suffixes is
# sufficient and keeps the project dependency-free and offline-capable.
MULTI_LABEL_SUFFIXES = {
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.sg", "edu.sg", "gov.sg",
    "com.my", "edu.my", "gov.my",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
    "com.hk", "org.hk", "gov.hk",
    "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.tw",
    "co.kr", "or.kr", "go.kr",
    "com.pk", "com.bd", "com.np", "com.lk",
    "co.id", "or.id", "ac.id", "go.id",
    "com.ph", "com.vn", "com.sa", "com.eg", "com.ng", "co.ke",
    "gov.it", "edu.it", "gov.es", "gov.pl",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me",
    "zoho.com", "zohomail.in", "gmx.com", "gmx.net", "mail.com", "yandex.com",
    "rediffmail.com", "tutanota.com", "fastmail.com", "hushmail.com",
    "mail.ru", "inbox.com", "ymail.com", "rocketmail.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "temp-mail.org", "dispostable.com", "maildrop.cc",
    "mailnesia.com", "fakeinbox.com", "spam4.me", "emailondeck.com",
}

#: Brands most frequently impersonated in phishing, mapped to legitimate domains.
PROTECTED_BRANDS = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.in"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "outlook.com",
                  "microsoftonline.com", "live.com", "sharepointonline.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com", "amazon.jobs"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com", "fb.com"},
    "instagram": {"instagram.com", "mail.instagram.com"},
    "linkedin": {"linkedin.com", "e.linkedin.com"},
    "whatsapp": {"whatsapp.com", "support.whatsapp.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com", "adobesign.com", "mail.adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "ups": {"ups.com"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net"},
    "icici": {"icicibank.com", "icicibank.net"},
    "sbi": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbicard.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com", "flipkart.net"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "swiggy": {"swiggy.in", "swiggy.com"},
    "zomato": {"zomato.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "github": {"github.com"},
    "slack": {"slack.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "steam": {"steampowered.com", "valvesoftware.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")


# ---------------------------------------------------------------------------
def normalise_domain(domain: Optional[str]) -> str:
    """Lower-case, strip trailing dot / brackets / whitespace."""
    if not domain:
        return ""
    d = domain.strip().strip("<>[]").rstrip(".").lower()
    if d.startswith("@"):
        d = d[1:]
    return d


def org_domain(domain: Optional[str]) -> str:
    """
    Return the organizational domain (registrable domain).

    mail.corp.example.co.in -> example.co.in
    news.paypal.com         -> paypal.com
    """
    d = normalise_domain(domain)
    if not d or "." not in d:
        return d
    labels = d.split(".")
    if len(labels) >= 3:
        last_two = ".".join(labels[-2:])
        if last_two in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_org(a: Optional[str], b: Optional[str]) -> bool:
    """Relaxed-alignment test: do two domains share an organizational domain?"""
    oa, ob = org_domain(a), org_domain(b)
    return bool(oa) and oa == ob


def is_subdomain_of(child: str, parent: str) -> bool:
    c, p = normalise_domain(child), normalise_domain(parent)
    return bool(c) and bool(p) and (c == p or c.endswith("." + p))


def split_address(addr: Optional[str]) -> Tuple[str, str]:
    """Split user@domain into ('user', 'domain'); tolerant of junk input."""
    if not addr:
        return "", ""
    a = addr.strip().strip("<>").strip()
    if "@" not in a:
        return a, ""
    local, _, domain = a.rpartition("@")
    return local.strip(), normalise_domain(domain)


# ---------------------------------------------------------------------------
def is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_reserved
        or obj.is_unspecified
    )


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def extract_ips(text: str) -> List[str]:
    """Pull every syntactically valid IP out of a blob of header text."""
    found: List[str] = []
    for match in IPV4_RE.findall(text or ""):
        if is_valid_ip(match) and match not in found:
            found.append(match)
    for match in IPV6_RE.findall(text or ""):
        if match.count(":") >= 2 and is_valid_ip(match) and match not in found:
            found.append(match)
    return found


# ---------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    """Classic edit distance - used for typosquat detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


#: Characters commonly swapped to build look-alike domains.
HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "|": "l",
})


def deskeleton(domain: str) -> str:
    """Normalise a domain for look-alike comparison (rn->m, 0->o, strip -)."""
    d = normalise_domain(domain).translate(HOMOGLYPH_MAP)
    d = d.replace("rn", "m").replace("vv", "w").replace("-", "")
    return d


def has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in (text or ""))


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in normalise_domain(domain).split("."))


def is_freemail(domain: str) -> bool:
    return org_domain(domain) in FREEMAIL_DOMAINS


def is_disposable(domain: str) -> bool:
    return org_domain(domain) in DISPOSABLE_DOMAINS


def brand_for_domain(domain: str) -> Optional[str]:
    """Return the brand key if `domain` is one of a brand's legitimate domains."""
    od = org_domain(domain)
    for brand, domains in PROTECTED_BRANDS.items():
        if od in domains or domain in domains:
            return brand
    return None


def truncate(text: str, length: int = 160) -> str:
    text = (text or "").replace("\r", " ").replace("\n", " ").strip()
    return text if len(text) <= length else text[: length - 1] + "…"
