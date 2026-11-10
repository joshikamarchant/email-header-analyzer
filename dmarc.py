"""
DMARC policy discovery, identifier alignment and policy evaluation (RFC 7489).

DMARC is the layer that actually binds SPF and DKIM to the address the user
sees. A message passes DMARC when **either**:

    SPF passes  AND the MAIL FROM domain aligns with the From domain,  or
    DKIM passes AND the d= domain aligns with the From domain.

"Aligns" means identical (strict, s) or sharing an organizational domain
(relaxed, r - the default).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .dkim_check import DKIMReport, parse_tag_list
from .dns_utils import Resolver
from .spf import SPFResult
from .utils import normalise_domain, org_domain, same_org

VALID_POLICIES = {"none", "quarantine", "reject"}


@dataclass
class DMARCReport:
    found: bool = False
    record: str = ""
    located_at: str = ""           # _dmarc.<domain> that answered
    from_domain: str = ""
    org_domain: str = ""
    policy: str = ""               # p=
    subdomain_policy: str = ""     # sp=
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    rua: str = ""
    ruf: str = ""
    fo: str = "0"

    spf_aligned: bool = False
    spf_alignment_detail: str = ""
    dkim_aligned: bool = False
    dkim_alignment_detail: str = ""
    aligned_dkim_domains: List[str] = field(default_factory=list)

    result: str = "none"           # pass | fail | none | temperror | permerror
    disposition: str = "none"      # what a receiver would do
    explanation: str = ""
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "record": self.record,
            "located_at": self.located_at,
            "from_domain": self.from_domain,
            "org_domain": self.org_domain,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "pct": self.pct,
            "adkim": self.adkim,
            "aspf": self.aspf,
            "rua": self.rua,
            "ruf": self.ruf,
            "spf_aligned": self.spf_aligned,
            "spf_alignment_detail": self.spf_alignment_detail,
            "dkim_aligned": self.dkim_aligned,
            "dkim_alignment_detail": self.dkim_alignment_detail,
            "aligned_dkim_domains": self.aligned_dkim_domains,
            "result": self.result,
            "disposition": self.disposition,
            "explanation": self.explanation,
            "issues": self.issues,
        }


# ---------------------------------------------------------------------------
def lookup_dmarc(resolver: Resolver, from_domain: str) -> tuple[Optional[str], str, List[str]]:
    """
    Find the DMARC record for a domain.

    RFC 7489 §6.6.3: query _dmarc.<domain>; if that yields nothing, fall back
    to _dmarc.<organizational-domain>.
    """
    issues: List[str] = []
    domain = normalise_domain(from_domain)
    if not domain:
        return None, "", issues

    candidates = [domain]
    org = org_domain(domain)
    if org and org != domain:
        candidates.append(org)

    for candidate in candidates:
        name = f"_dmarc.{candidate}"
        records = [r for r in resolver.txt(name) if r.strip().lower().startswith("v=dmarc1")]
        if len(records) > 1:
            issues.append(f"{name} publishes multiple DMARC records; RFC 7489 ignores the domain entirely")
            return None, name, issues
        if records:
            return records[0].strip(), name, issues
    return None, "", issues


def check_alignment(child: str, from_domain: str, mode: str) -> tuple[bool, str]:
    """Strict (s) alignment = exact match; relaxed (r) = shared org domain."""
    child_n, from_n = normalise_domain(child), normalise_domain(from_domain)
    if not child_n or not from_n:
        return False, "one of the identifiers is missing"
    if mode == "s":
        ok = child_n == from_n
        return ok, (
            f"strict mode: {child_n} {'==' if ok else '!='} {from_n}"
        )
    ok = same_org(child_n, from_n)
    return ok, (
        f"relaxed mode: organizational domain {org_domain(child_n)} "
        f"{'==' if ok else '!='} {org_domain(from_n)}"
    )


# ---------------------------------------------------------------------------
def analyse_dmarc(
    resolver: Resolver,
    from_domain: str,
    spf: SPFResult,
    dkim: DKIMReport,
    envelope_domain: str = "",
    check_dns: bool = True,
) -> DMARCReport:
    report = DMARCReport(from_domain=normalise_domain(from_domain))
    report.org_domain = org_domain(from_domain)

    if not from_domain:
        report.result = "permerror"
        report.explanation = "No From domain could be extracted, so DMARC cannot be evaluated."
        return report

    if check_dns:
        record, located, issues = lookup_dmarc(resolver, from_domain)
        report.issues.extend(issues)
        report.located_at = located
    else:
        record = None

    if not record:
        report.found = False
        report.result = "none"
        report.disposition = "none"
        report.explanation = (
            f"{from_domain} publishes no DMARC policy. Receivers therefore have no "
            f"instruction to reject forged mail using this From address, and no alignment "
            f"between the visible sender and the authenticated identity is enforced."
        )
        report.issues.append("Domain has no DMARC record - trivially spoofable in the From header")
        return report

    report.found = True
    report.record = record
    tags = parse_tag_list(record)

    report.policy = (tags.get("p") or "").lower()
    report.subdomain_policy = (tags.get("sp") or "").lower()
    report.adkim = (tags.get("adkim") or "r").lower()
    report.aspf = (tags.get("aspf") or "r").lower()
    report.rua = tags.get("rua", "")
    report.ruf = tags.get("ruf", "")
    report.fo = tags.get("fo", "0")
    try:
        report.pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        report.pct = 100
        report.issues.append(f"Invalid pct= value '{tags.get('pct')}'; assuming 100")

    if report.policy not in VALID_POLICIES:
        report.issues.append(f"Invalid or missing p= tag ('{report.policy}'); record is unusable")
        report.result = "permerror"
        report.explanation = "The DMARC record is malformed: p= must be none, quarantine or reject."
        return report

    if report.policy == "none":
        report.issues.append(
            "Policy is p=none (monitor only) - forged mail is still delivered, "
            "so DMARC provides reporting but no protection"
        )
    if report.pct < 100:
        report.issues.append(
            f"pct={report.pct} applies the policy to only {report.pct}% of failing mail"
        )
    if not report.rua:
        report.issues.append("No rua= aggregate reporting address; the domain gets no visibility")

    # ---------------- alignment ----------------
    spf_domain = envelope_domain or spf.domain
    if spf.result == "pass" and spf_domain:
        report.spf_aligned, report.spf_alignment_detail = check_alignment(
            spf_domain, from_domain, report.aspf
        )
        if not report.spf_aligned:
            report.spf_alignment_detail = (
                f"SPF passed for {spf_domain} but that is NOT aligned with the From "
                f"domain {from_domain} ({report.spf_alignment_detail}). "
                f"This is the classic 'SPF pass on a spoofed From' pattern."
            )
    else:
        report.spf_alignment_detail = (
            f"SPF did not pass ({spf.result}), so it cannot contribute to a DMARC pass."
        )

    dkim_pass_domains = (
        dkim.verified_domains if dkim.result == "pass"
        else ([s.domain for s in dkim.signatures] if dkim.result == "neutral" else [])
    )
    for domain in dkim_pass_domains:
        aligned, detail = check_alignment(domain, from_domain, report.adkim)
        if aligned:
            report.dkim_aligned = True
            report.aligned_dkim_domains.append(domain)
            report.dkim_alignment_detail = f"DKIM d={domain} is aligned with From ({detail})."
            break
    if not report.dkim_aligned:
        if not dkim_pass_domains:
            report.dkim_alignment_detail = (
                f"No DKIM signature passed ({dkim.result}), so DKIM cannot contribute to DMARC."
            )
        else:
            report.dkim_alignment_detail = (
                f"DKIM signed by {', '.join(dkim_pass_domains)}, none of which align with "
                f"the From domain {from_domain} under adkim={report.adkim}."
            )

    # ---------------- verdict ----------------
    spf_leg = spf.result == "pass" and report.spf_aligned
    dkim_leg = report.dkim_aligned and dkim.result in ("pass", "neutral")
    provisional = dkim.result == "neutral" and dkim_leg and not spf_leg

    if spf_leg or dkim_leg:
        report.result = "pass"
        report.disposition = "deliver"
        legs = []
        if spf_leg:
            legs.append("aligned SPF")
        if dkim_leg:
            legs.append("aligned DKIM" + (" (structural, body not supplied)" if provisional else ""))
        report.explanation = (
            f"DMARC PASS via {' and '.join(legs)}. The visible From domain is bound to an "
            f"authenticated identity, so the sender address can be trusted at the domain level."
        )
        if provisional:
            report.result = "pass (provisional)"
            report.explanation += (
                " Note: the DKIM leg was accepted structurally; supply the full raw message "
                "for a cryptographically confirmed result."
            )
    else:
        report.result = "fail"
        effective_policy = report.policy
        if report.subdomain_policy and normalise_domain(from_domain) != report.org_domain:
            effective_policy = report.subdomain_policy
        report.disposition = {
            "reject": "reject",
            "quarantine": "quarantine (spam folder)",
            "none": "deliver (monitoring only)",
        }.get(effective_policy, "deliver")
        report.explanation = (
            f"DMARC FAIL - neither authentication method produced an identifier aligned with "
            f"the From domain {from_domain}. A receiver honouring p={effective_policy} would "
            f"{report.disposition} this message."
        )
    return report


def summarise_dmarc(report: DMARCReport) -> str:
    if not report.found:
        return "DMARC NONE - the From domain publishes no policy."
    if report.result.startswith("pass"):
        return f"DMARC PASS (policy p={report.policy})."
    if report.result == "fail":
        return f"DMARC FAIL against policy p={report.policy} - disposition: {report.disposition}."
    return f"DMARC {report.result.upper()}."
