"""
SPF evaluation - a practical implementation of RFC 7208.

Supported: all, include, a, mx, ip4, ip6, exists, ptr, the redirect= and exp=
modifiers, qualifiers (+ - ~ ?), CIDR dual scopes, macro expansion, the
10-lookup / 2-void-lookup limits and recursion guards.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .dns_utils import DNSLookupLimit, Resolver
from .utils import normalise_domain

PASS, FAIL, SOFTFAIL, NEUTRAL, NONE = "pass", "fail", "softfail", "neutral", "none"
PERMERROR, TEMPERROR = "permerror", "temperror"

QUALIFIERS = {"+": PASS, "-": FAIL, "~": SOFTFAIL, "?": NEUTRAL}

MECHANISM_RE = re.compile(
    r"^(?P<qual>[+\-~?])?"
    r"(?P<name>all|include|a|mx|ptr|ip4|ip6|exists)"
    r"(?::(?P<value>[^/\s]+))?"
    r"(?:/(?P<cidr4>\d{1,3}))?"
    r"(?://(?P<cidr6>\d{1,3}))?$",
    re.I,
)
MODIFIER_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)=(?P<value>.*)$")

MAX_RECURSION = 10


@dataclass
class SPFResult:
    result: str = NONE
    domain: str = ""
    record: str = ""
    matched: str = ""              # the mechanism that decided the outcome
    explanation: str = ""
    lookups_used: int = 0
    warnings: List[str] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)
    checked_ip: str = ""

    @property
    def passed(self) -> bool:
        return self.result == PASS

    def to_dict(self) -> dict:
        return {
            "result": self.result,
            "domain": self.domain,
            "record": self.record,
            "matched_mechanism": self.matched,
            "explanation": self.explanation,
            "lookups_used": self.lookups_used,
            "warnings": self.warnings,
            "trace": self.trace,
            "checked_ip": self.checked_ip,
        }


# ---------------------------------------------------------------------------
# Macro expansion (RFC 7208 §7)
# ---------------------------------------------------------------------------
_MACRO_RE = re.compile(r"%\{(?P<letter>[slodipvh])(?P<digits>\d*)(?P<rev>r?)(?P<delims>[.\-+,/_=]*)\}",
                       re.I)


def expand_macros(text: str, ip: str, sender: str, domain: str, helo: str) -> str:
    if "%" not in text:
        return text

    def ip_nibbles(addr: str) -> str:
        try:
            obj = ipaddress.ip_address(addr)
        except ValueError:
            return addr
        if obj.version == 4:
            return str(obj)
        return ".".join(c for c in obj.exploded.replace(":", ""))

    local, _, sender_domain = sender.partition("@")

    def replace(match: re.Match) -> str:
        letter = match.group("letter").lower()
        values = {
            "s": sender or f"postmaster@{domain}",
            "l": local or "postmaster",
            "o": sender_domain or domain,
            "d": domain,
            "i": ip_nibbles(ip),
            "p": "unknown",
            "v": "in-addr" if ":" not in (ip or "") else "ip6",
            "h": helo or domain,
        }
        value = values.get(letter, "")
        delims = match.group("delims") or "."
        parts = re.split("[" + re.escape(delims) + "]", value)
        if match.group("rev"):
            parts.reverse()
        digits = match.group("digits")
        if digits:
            n = int(digits)
            if n > 0:
                parts = parts[-n:]
        return ".".join(parts)

    out = _MACRO_RE.sub(replace, text)
    return out.replace("%%", "%").replace("%_", " ").replace("%-", "%20")


# ---------------------------------------------------------------------------
def _ip_in(ip_obj, candidate: str, cidr: Optional[int]) -> bool:
    try:
        if cidr is None:
            net = ipaddress.ip_network(candidate.strip() + ("/32" if ip_obj.version == 4 else "/128"),
                                       strict=False)
        else:
            net = ipaddress.ip_network(f"{candidate.strip()}/{cidr}", strict=False)
    except ValueError:
        return False
    if net.version != ip_obj.version:
        return False
    return ip_obj in net


def get_spf_record(resolver: Resolver, domain: str) -> tuple[Optional[str], List[str]]:
    """Fetch and validate the single v=spf1 TXT record for `domain`."""
    warnings: List[str] = []
    try:
        records = resolver.txt(domain)
    except Exception as exc:  # pragma: no cover - defensive
        warnings.append(f"DNS error retrieving SPF for {domain}: {exc}")
        return None, warnings

    spf_records = [r for r in records if r.strip().lower().startswith("v=spf1")]
    if not spf_records:
        return None, warnings
    if len(spf_records) > 1:
        warnings.append(
            f"{domain} publishes {len(spf_records)} SPF records - RFC 7208 §4.5 "
            f"requires exactly one; result is PermError"
        )
        return "MULTIPLE", warnings
    return spf_records[0].strip(), warnings


# ---------------------------------------------------------------------------
def check_spf(
    resolver: Resolver,
    ip: str,
    domain: str,
    sender: str = "",
    helo: str = "",
    _depth: int = 0,
    _result: Optional[SPFResult] = None,
) -> SPFResult:
    """
    Evaluate SPF for (ip, domain).

    `domain` is the MAIL FROM (Return-Path) domain; `helo` is used only for
    macro expansion and for the HELO identity check.
    """
    top = _result is None
    res = _result or SPFResult(domain=domain, checked_ip=ip)
    if top:
        resolver.reset_budget()

    domain = normalise_domain(domain)
    if not domain:
        res.result = NONE
        res.explanation = "No MAIL FROM / Return-Path domain available to check."
        return res

    if not ip:
        res.result = NONE
        res.explanation = "Originating client IP could not be determined from the Received chain."
        return res

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        res.result = PERMERROR
        res.explanation = f"'{ip}' is not a valid IP address."
        return res

    if _depth > MAX_RECURSION:
        res.result = PERMERROR
        res.explanation = "SPF include/redirect recursion limit exceeded."
        return res

    record, warnings = get_spf_record(resolver, domain)
    res.warnings.extend(warnings)

    if record == "MULTIPLE":
        res.result = PERMERROR
        res.explanation = f"{domain} publishes multiple SPF records."
        return res
    if record is None:
        res.result = NONE
        res.explanation = f"{domain} publishes no SPF (v=spf1) record."
        res.trace.append(f"{'  ' * _depth}{domain}: no SPF record")
        return res

    if _depth == 0:
        res.record = record
    res.trace.append(f"{'  ' * _depth}{domain}: {record}")

    terms = record.split()[1:]          # drop the "v=spf1" version token
    redirect: Optional[str] = None
    explanation_macro: Optional[str] = None
    sender = sender or f"postmaster@{domain}"

    for term in terms:
        mod = MODIFIER_RE.match(term)
        if mod and mod.group("name").lower() in ("redirect", "exp"):
            name = mod.group("name").lower()
            if name == "redirect":
                redirect = mod.group("value")
            else:
                explanation_macro = mod.group("value")
            continue

        mech = MECHANISM_RE.match(term)
        if not mech:
            if mod:
                res.warnings.append(f"Unknown SPF modifier ignored: {term}")
                continue
            res.result = PERMERROR
            res.explanation = f"Malformed SPF term '{term}' in {domain}'s record."
            return res

        qualifier = QUALIFIERS.get(mech.group("qual") or "+", PASS)
        name = mech.group("name").lower()
        value = mech.group("value")
        cidr4 = int(mech.group("cidr4")) if mech.group("cidr4") else None
        cidr6 = int(mech.group("cidr6")) if mech.group("cidr6") else None
        cidr = cidr6 if ip_obj.version == 6 else cidr4
        target = normalise_domain(expand_macros(value, ip, sender, domain, helo)) if value else domain

        try:
            matched = False

            if name == "all":
                matched = True

            elif name == "ip4":
                if ip_obj.version == 4:
                    matched = _ip_in(ip_obj, value or "", cidr4)

            elif name == "ip6":
                if ip_obj.version == 6:
                    matched = _ip_in(ip_obj, value or "", cidr6)

            elif name == "a":
                resolver.spend()
                addrs = resolver.a(target) if ip_obj.version == 4 else resolver.aaaa(target)
                if not addrs:
                    resolver.note_void()
                matched = any(_ip_in(ip_obj, a, cidr) for a in addrs)

            elif name == "mx":
                resolver.spend()
                exchanges = resolver.mx(target)
                if not exchanges:
                    resolver.note_void()
                if len(exchanges) > 10:
                    res.warnings.append(
                        f"{target} has {len(exchanges)} MX hosts; RFC 7208 caps MX expansion at 10"
                    )
                    exchanges = exchanges[:10]
                for exch in exchanges:
                    addrs = resolver.a(exch) if ip_obj.version == 4 else resolver.aaaa(exch)
                    if any(_ip_in(ip_obj, a, cidr) for a in addrs):
                        matched = True
                        break

            elif name == "exists":
                resolver.spend()
                addrs = resolver.a(target)
                if not addrs:
                    resolver.note_void()
                matched = bool(addrs)

            elif name == "ptr":
                resolver.spend()
                res.warnings.append(
                    "Record uses the 'ptr' mechanism, deprecated by RFC 7208 §5.5 "
                    "(slow and unreliable)"
                )
                names = resolver.ptr(ip)
                for host in names:
                    host = normalise_domain(host)
                    if host == target or host.endswith("." + target):
                        verify = resolver.a(host) if ip_obj.version == 4 else resolver.aaaa(host)
                        if any(_ip_in(ip_obj, a, None) for a in verify):
                            matched = True
                            break

            elif name == "include":
                resolver.spend()
                inner = SPFResult(domain=target, checked_ip=ip)
                inner = check_spf(resolver, ip, target, sender, helo, _depth + 1, inner)
                res.trace.extend(inner.trace if inner.trace != res.trace else [])
                res.warnings.extend(inner.warnings)
                if inner.result == PASS:
                    matched = True
                elif inner.result in (TEMPERROR,):
                    res.result = TEMPERROR
                    res.explanation = f"include:{target} returned a temporary DNS error."
                    return res
                elif inner.result in (PERMERROR, NONE):
                    res.result = PERMERROR
                    res.explanation = (
                        f"include:{target} has no usable SPF record "
                        f"(RFC 7208 §5.2 makes this a PermError)."
                    )
                    return res

        except DNSLookupLimit as exc:
            res.result = PERMERROR
            res.explanation = str(exc)
            res.lookups_used = resolver.lookup_count
            return res

        if matched:
            res.result = qualifier
            res.matched = term
            res.lookups_used = resolver.lookup_count
            verdict = {
                PASS: "authorised to send",
                FAIL: "explicitly NOT authorised to send",
                SOFTFAIL: "not authorised, but the domain only asks for a soft fail",
                NEUTRAL: "neither authorised nor denied",
            }[qualifier]
            res.explanation = (
                f"IP {ip} matched mechanism '{term}' in {domain}'s SPF record - "
                f"the sender is {verdict}."
            )
            if explanation_macro and qualifier == FAIL:
                res.explanation += f" Domain explanation: {expand_macros(explanation_macro, ip, sender, domain, helo)}"
            return res

    # No mechanism matched -> honour redirect=, else default NEUTRAL.
    if redirect:
        target = normalise_domain(expand_macros(redirect, ip, sender, domain, helo))
        try:
            resolver.spend()
        except DNSLookupLimit as exc:
            res.result = PERMERROR
            res.explanation = str(exc)
            return res
        res.trace.append(f"{'  ' * _depth}redirect={target}")
        redirected = check_spf(resolver, ip, target, sender, helo, _depth + 1, res)
        if redirected.result == NONE:
            redirected.result = PERMERROR
            redirected.explanation = f"redirect={target} points at a domain with no SPF record."
        return redirected

    res.result = NEUTRAL
    res.lookups_used = resolver.lookup_count
    res.explanation = (
        f"No mechanism in {domain}'s SPF record matched {ip} and the record has no "
        f"'all' term, so the result defaults to neutral."
    )
    return res


def summarise_spf(result: SPFResult) -> str:
    """One-line human summary used in reports."""
    headline = {
        PASS: "SPF PASS - the sending IP is authorised by the envelope domain.",
        FAIL: "SPF FAIL - the envelope domain explicitly disowns this sending IP.",
        SOFTFAIL: "SPF SOFTFAIL - the IP is not authorised, but the domain is still in monitoring mode.",
        NEUTRAL: "SPF NEUTRAL - the domain takes no position on this IP.",
        NONE: "SPF NONE - no SPF policy exists for the envelope domain.",
        PERMERROR: "SPF PERMERROR - the SPF record is invalid or exceeds RFC limits.",
        TEMPERROR: "SPF TEMPERROR - a transient DNS failure prevented evaluation.",
    }
    return headline.get(result.result, result.result.upper())
