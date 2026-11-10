"""
Parser for Authentication-Results / Received-SPF / ARC headers (RFC 8601).

These headers record what the *receiving* mail server concluded at delivery
time. They are valuable independent evidence - but only when they were written
by a trusted boundary MTA, because any upstream party can forge them. The
parser therefore reports every instance separately with its authserv-id.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

from .utils import normalise_domain, truncate

#: method=result pairs, e.g. "dkim=pass", "spf=softfail", "compauth=fail"
_METHOD_RE = re.compile(
    r"\b(?P<method>spf|dkim|dmarc|arc|iprev|auth|dkim-adsp|compauth|bimi)"
    r"\s*=\s*(?P<result>[a-z]+)",
    re.I,
)
#: property values, e.g. "header.d=example.com", "smtp.mailfrom=a@b.com"
_PROPERTY_RE = re.compile(
    r"\b(?P<prop>(?:header|smtp|body|policy)\.[a-z\-]+)\s*=\s*(?P<value>[^\s;,()]+)",
    re.I,
)


@dataclass
class AuthResults:
    authserv_id: str = ""
    raw: str = ""
    methods: Dict[str, str] = field(default_factory=dict)
    properties: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "authserv_id": self.authserv_id,
            "methods": self.methods,
            "properties": self.properties,
            "raw": truncate(self.raw, 300),
        }


def parse_authentication_results(raw: str) -> AuthResults:
    ar = AuthResults(raw=" ".join((raw or "").split()))
    flat = ar.raw

    first = flat.split(";", 1)[0].strip()
    if first and "=" not in first:
        ar.authserv_id = normalise_domain(first.split()[0])

    # Strip parenthesised comments before matching so that prose inside them
    # ("domain of x does not designate...") cannot create phantom results.
    without_comments = re.sub(r"\([^()]*\)", " ", flat)

    for m in _METHOD_RE.finditer(without_comments):
        method = m.group("method").lower()
        result = m.group("result").lower()
        ar.methods.setdefault(method, result)

    for m in _PROPERTY_RE.finditer(without_comments):
        ar.properties.setdefault(m.group("prop").lower(), m.group("value").strip("<>"))
    return ar


def parse_received_spf(raw: str) -> AuthResults:
    """Received-SPF: pass (domain of x designates 1.2.3.4) client-ip=1.2.3.4; ..."""
    ar = AuthResults(raw=" ".join((raw or "").split()))
    flat = ar.raw
    m = re.match(r"\s*([A-Za-z]+)", flat)
    if m:
        ar.methods["spf"] = m.group(1).lower()
    for key in ("client-ip", "envelope-from", "helo", "identity", "receiver"):
        km = re.search(rf"{key}\s*=\s*([^\s;,()]+)", flat, re.I)
        if km:
            ar.properties[key] = km.group(1).strip("<>")
    return ar


def collect(headers_authres: List[str], headers_rxspf: List[str]) -> Dict[str, object]:
    """Build a consolidated view of every authentication verdict in the message."""
    parsed_ar = [parse_authentication_results(h) for h in headers_authres]
    parsed_spf = [parse_received_spf(h) for h in headers_rxspf]

    consolidated: Dict[str, str] = {}
    for ar in parsed_ar:                       # newest header first = closest to recipient
        for method, result in ar.methods.items():
            consolidated.setdefault(method, result)
    for sp in parsed_spf:
        for method, result in sp.methods.items():
            consolidated.setdefault(method, result)

    return {
        "present": bool(parsed_ar or parsed_spf),
        "consolidated": consolidated,
        "authentication_results": [a.to_dict() for a in parsed_ar],
        "received_spf": [s.to_dict() for s in parsed_spf],
        "authserv_ids": [a.authserv_id for a in parsed_ar if a.authserv_id],
    }


def describe(consolidated: Dict[str, str]) -> str:
    if not consolidated:
        return (
            "No Authentication-Results header is present. Either the message never passed "
            "through an authenticating gateway, or the headers were captured before "
            "delivery - the receiving server's own verdict is unavailable."
        )
    parts = [f"{k.upper()}={v}" for k, v in consolidated.items()]
    return "Receiving server recorded: " + ", ".join(parts) + "."
