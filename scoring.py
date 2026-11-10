"""
Risk aggregation.

Two independent measures are produced:

* **Risk score (0-100)** - how much evidence of spoofing/phishing exists.
  Built by summing the weights of every triggered heuristic, then subtracting
  credit for passing authentication, and clamping to [0, 100].

* **Authentication grade (A-F)** - how well the *sending domain* is configured,
  independent of whether this particular message is malicious. A domain with
  p=reject and aligned DKIM earns an A even if the message under test fails,
  because the failure is then strong evidence rather than ambiguity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .heuristics import CRITICAL, GOOD, HIGH, INFO, LOW, MEDIUM, Finding

BANDS = [
    (0, 9, "Authentic", "No spoofing indicators found.",
     "The message authenticates correctly and shows no deceptive characteristics."),
    (10, 24, "Low Risk", "Minor issues only.",
     "Nothing here indicates spoofing, but one or more configuration or hygiene weaknesses "
     "were noted. Normal caution applies."),
    (25, 44, "Suspicious", "Verify before acting.",
     "Several indicators are inconsistent with legitimate mail. Confirm the sender through an "
     "independent channel before trusting the content, clicking links or acting on requests."),
    (45, 69, "Likely Spoofed", "Treat as hostile.",
     "The evidence points to a forged sender. Do not reply, click links, open attachments or "
     "act on any instruction in the message."),
    (70, 100, "Highly Likely Spoofed / Phishing", "Do not engage.",
     "Multiple strong indicators of forgery, including authentication failure and deliberate "
     "deception of the reader. Report to your security team and delete."),
]

SEVERITY_WEIGHT_CAP = {CRITICAL: 34, HIGH: 24, MEDIUM: 14, LOW: 8, INFO: 0, GOOD: 0}

#: Findings that report the *absence* of evidence rather than the presence of
#: deception. A sparse or truncated header paste triggers many of them at once,
#: which must not be allowed to produce a confident "spoofed" verdict: absence
#: of authentication is a weakness, not proof of forgery.
ABSENCE_FINDINGS = {
    "spf_none", "spf_neutral", "spf_temperror", "spf_permerror",
    "dkim_absent", "dmarc_absent", "dmarc_policy_none", "dmarc_partial_pct",
    "authres_missing", "received_missing", "received_single_hop",
    "received_many_hops", "received_long_delay", "origin_unknown",
    "message_id_missing", "from_missing", "return_path_missing",
    "date_unparsable",
}

#: Ceiling applied when no positive indicator of deception was found.
NO_EVIDENCE_CEILING = 44


@dataclass
class Verdict:
    score: int = 0
    raw_score: int = 0
    credit: int = 0
    label: str = ""
    headline: str = ""
    advice: str = ""
    grade: str = "F"
    grade_reason: str = ""
    confidence: str = "medium"
    confidence_reason: str = ""
    capped: bool = False
    counts: Dict[str, int] = field(default_factory=dict)
    top_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "raw_score": self.raw_score,
            "credit": self.credit,
            "label": self.label,
            "headline": self.headline,
            "advice": self.advice,
            "grade": self.grade,
            "grade_reason": self.grade_reason,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "capped_for_insufficient_evidence": self.capped,
            "counts": self.counts,
            "top_reasons": self.top_reasons,
        }


# ---------------------------------------------------------------------------
def grade_domain(spf, dkim, dmarc) -> tuple[str, str]:
    """Rate the sending domain's email-authentication posture."""
    if not dmarc.found:
        if spf.result in ("pass", "fail", "softfail", "neutral"):
            return "D", ("SPF is published but there is no DMARC policy, so nothing stops an "
                         "attacker from forging the From address.")
        return "F", "The domain publishes neither SPF nor DMARC - it is trivially spoofable."

    if dmarc.policy == "reject":
        base, reason = "A", "DMARC is enforced with p=reject, the strongest available posture."
    elif dmarc.policy == "quarantine":
        base, reason = "B", "DMARC is enforced with p=quarantine; failing mail is filtered but not refused."
    else:
        base, reason = "C", "DMARC exists but p=none means failures are only monitored, not blocked."

    if dmarc.pct < 100:
        base = chr(min(ord(base) + 1, ord("F")))
        reason += f" Coverage is reduced to {dmarc.pct}% by pct=."
    if spf.result in ("permerror", "none"):
        base = chr(min(ord(base) + 1, ord("F")))
        reason += " SPF is missing or invalid."
    if dkim.result == "none":
        reason += " No DKIM signature was applied to this message."
    return base, reason


def assess_confidence(context: Dict[str, object]) -> tuple[str, str]:
    dns_live = bool(context.get("dns_live"))
    has_body = bool(context.get("has_body"))
    has_chain = bool(context.get("hop_count"))
    has_ip = bool(context.get("client_ip"))

    if dns_live and has_body and has_chain and has_ip:
        return "high", ("Live DNS was queried, the full message body was available for "
                        "cryptographic DKIM verification, and a complete Received chain with a "
                        "resolvable originating IP was present.")

    gaps: List[str] = []
    if not dns_live:
        gaps.append("DNS answers came from the bundled offline fixture set rather than live "
                    "queries, so published policies may have changed")
    if not has_body:
        gaps.append("only headers were supplied, so DKIM could be audited structurally but not "
                    "verified cryptographically")
    if not has_chain:
        gaps.append("no Received chain was available to attribute the origin")
    if not has_ip:
        gaps.append("the originating IP could not be determined, limiting SPF evaluation")

    level = "low" if len(gaps) >= 3 else "medium"
    return level, "Confidence is reduced because " + "; ".join(gaps) + "."


# ---------------------------------------------------------------------------
def score(findings: List[Finding], spf, dkim, dmarc, context: Dict[str, object]) -> Verdict:
    verdict = Verdict()

    risk = sum(f.score for f in findings if f.score > 0)
    credit = sum(f.score for f in findings if f.score < 0)

    verdict.raw_score = risk

    # Passing authentication only proves the message really came from the
    # domain in the From header. It says nothing about whether that domain is
    # the one the reader believes they are dealing with. So when a CRITICAL
    # identity finding fires - a look-alike domain, an impersonated brand, a
    # display name that hides the real sender - the attacker owns the domain
    # they authenticated, and the authentication credit is worthless.
    critical_identity = [
        f for f in findings if f.severity == CRITICAL and f.category == "identity"
    ]
    high_identity = [
        f for f in findings if f.severity == HIGH and f.category == "identity"
    ]
    # One critical deception, or two independent high-confidence ones
    # (e.g. a brand-impersonating display name *and* a brand-bearing domain),
    # is enough to conclude the authenticated domain is the attacker's own.
    deceptive_identity = bool(critical_identity) or len(high_identity) >= 2

    if deceptive_identity:
        credit = 0
    elif dmarc.result.startswith("pass"):
        # A clean DMARC pass with no deception: damp residual hygiene noise so
        # legitimate ESP mail is not pushed into "suspicious" by cosmetic issues.
        identity_risk = sum(
            f.score for f in findings
            if f.score > 0 and f.category == "identity"
        )
        other_risk = risk - identity_risk
        risk = identity_risk + int(other_risk * 0.4)

    verdict.credit = credit

    total = max(0, min(100, risk + credit))

    # Guard against false confidence. If every point of risk comes from a
    # missing header, a missing policy or an unavailable lookup, then nothing
    # positively indicates forgery - the input is simply incomplete. Cap the
    # verdict so a truncated paste cannot be reported as confirmed spoofing.
    positive_evidence = [
        f for f in findings if f.score > 0 and f.id not in ABSENCE_FINDINGS
    ]
    if not positive_evidence and total > NO_EVIDENCE_CEILING:
        total = NO_EVIDENCE_CEILING
        verdict.capped = True

    verdict.score = total

    for low, high, label, headline, advice in BANDS:
        if low <= total <= high:
            verdict.label, verdict.headline, verdict.advice = label, headline, advice
            break

    if verdict.capped:
        verdict.advice += (
            " Note: every finding here reports something missing rather than "
            "something forged. That usually means the header block is incomplete - "
            "re-export the full original message and analyse it again before drawing "
            "a conclusion."
        )

    verdict.counts = {
        "critical": sum(1 for f in findings if f.severity == CRITICAL),
        "high": sum(1 for f in findings if f.severity == HIGH),
        "medium": sum(1 for f in findings if f.severity == MEDIUM),
        "low": sum(1 for f in findings if f.severity == LOW),
        "info": sum(1 for f in findings if f.severity == INFO),
        "good": sum(1 for f in findings if f.severity == GOOD),
        "total": len(findings),
    }

    verdict.top_reasons = [
        f.title for f in findings if f.severity in (CRITICAL, HIGH)
    ][:5]
    if not verdict.top_reasons:
        verdict.top_reasons = [f.title for f in findings[:3]]

    verdict.grade, verdict.grade_reason = grade_domain(spf, dkim, dmarc)
    verdict.confidence, verdict.confidence_reason = assess_confidence(context)
    return verdict
