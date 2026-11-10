"""
Forensic spoofing heuristics.

Authentication (SPF/DKIM/DMARC) answers "is this domain authorised?".
These heuristics answer the complementary question: "does this message look
like it was crafted to deceive a human reader?" - display-name spoofing,
look-alike domains, Reply-To redirection, forged or missing Received chains,
timestamp inconsistencies and social-engineering cues.

Each check returns zero or more Finding objects carrying a risk weight that
feeds the scoring engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from .utils import (
    EMAIL_RE,
    PROTECTED_BRANDS,
    brand_for_domain,
    deskeleton,
    has_non_ascii,
    is_disposable,
    is_freemail,
    is_private_ip,
    is_punycode,
    levenshtein,
    normalise_domain,
    org_domain,
    same_org,
    split_address,
    truncate,
)

CRITICAL, HIGH, MEDIUM, LOW, INFO, GOOD = "critical", "high", "medium", "low", "info", "good"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, GOOD: 5}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    score: int                       # risk points (negative = reassuring)
    detail: str
    category: str = "heuristic"
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "detail": self.detail,
            "category": self.category,
            "evidence": truncate(self.evidence, 400),
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
URGENCY_PATTERNS = [
    (r"\b(urgent|immediate(ly)?|action required|final (notice|warning)|last warning)\b", "urgency"),
    (r"\b(verify|confirm|validate|update|re-?activate)\s+(your\s+)?(account|identity|details|password|information)\b", "credential lure"),
    (r"\b(suspend|suspended|suspension|deactivat\w+|terminat\w+|clos(e|ure|ing))\b.{0,30}\b(account|access|service)\b", "account threat"),
    (r"\b(unusual|suspicious|unauthori[sz]ed)\s+(sign-?in|login|activity|access)\b", "fake security alert"),
    (r"\b(you'?ve|you have)\s+(won|been selected)\b|\blottery\b|\bprize\b|\bclaim your\b", "advance-fee lure"),
    (r"\b(invoice|payment|refund|wire|transfer|remittance)\b.{0,40}\b(overdue|pending|failed|due|attached)\b", "payment lure"),
    (r"\b(kindly|please)\s+(do\s+)?(the\s+)?needful\b", "BEC phrasing"),
    (r"\b(password|otp|one[- ]time)\s+(will\s+)?expir\w+\b", "expiry pressure"),
    (r"\b(gift\s*card|bitcoin|crypto|usdt)\b", "payment-rail lure"),
    (r"\bare you (available|at your desk|in the office)\b", "BEC opener"),
]

SUSPICIOUS_MAILERS = [
    (r"PHPMailer", "PHPMailer - common in scripted bulk/phishing campaigns"),
    (r"X-PHP-Originating-Script", "message injected by a PHP script, often a compromised web host"),
    (r"\bsendmail\b.*\bwith nullmailer\b", "nullmailer relay"),
    (r"Python.*smtplib|Python-urllib", "sent by a Python script"),
    (r"\bswiftmailer\b|\bphpmail\b", "scripted mailer library"),
    (r"\bmass\s*mailer\b|\bbulk\s*mailer\b", "declared bulk mailer"),
]


# ---------------------------------------------------------------------------
# Identity-consistency checks
# ---------------------------------------------------------------------------
def check_from_header(msg) -> List[Finding]:
    out: List[Finding] = []

    if not msg.from_address:
        out.append(Finding(
            "from_missing", "No usable From address", HIGH, 20,
            "The message has no parsable From header. Every RFC 5322 message must have "
            "exactly one; its absence points to hand-crafted injection.",
            category="identity",
            evidence=msg.get("from") or "(header absent)",
            recommendation="Treat as malformed and do not act on the message.",
        ))
        return out

    if msg.from_count > 1:
        out.append(Finding(
            "from_duplicate", "Multiple From headers present", CRITICAL, 30,
            f"The message carries {msg.from_count} From headers. Mail clients and security "
            f"filters often disagree about which one to display, and attackers exploit that "
            f"gap to show a trusted sender while authentication checks read the other.",
            category="identity",
            evidence=" | ".join(msg.get_all("from")),
            recommendation="Reject outright; this is a known header-injection technique.",
        ))

    if has_non_ascii(msg.from_address):
        out.append(Finding(
            "from_unicode", "Non-ASCII characters in the From address", HIGH, 18,
            "The sender address contains non-ASCII characters, which can render as a "
            "familiar Latin domain while resolving somewhere entirely different "
            "(homograph attack).",
            category="identity",
            evidence=msg.from_address,
            recommendation="Inspect the punycode form of the domain before trusting it.",
        ))

    if is_punycode(msg.from_domain):
        out.append(Finding(
            "from_punycode", "Punycode (xn--) domain in From", HIGH, 20,
            f"The From domain {msg.from_domain} is an internationalised domain name. These "
            f"are legitimate in principle but are heavily abused to imitate well-known brands.",
            category="identity",
            evidence=msg.from_domain,
            recommendation="Decode the domain and confirm it belongs to the claimed organisation.",
        ))

    if is_disposable(msg.from_domain):
        out.append(Finding(
            "from_disposable", "Sender uses a disposable mail provider", HIGH, 18,
            f"{msg.from_domain} is a throwaway mailbox service. No business correspondence "
            f"legitimately originates from one.",
            category="identity",
            evidence=msg.from_domain,
        ))
    return out


def check_display_name(msg) -> List[Finding]:
    """Detect display-name deception - the single most effective phishing trick."""
    out: List[Finding] = []
    display = msg.from_display or ""
    if not display:
        return out

    # 1. Display name embeds an email address different from the real one.
    embedded = EMAIL_RE.findall(display)
    for addr in embedded:
        _, embedded_domain = split_address(addr)
        if embedded_domain and not same_org(embedded_domain, msg.from_domain):
            out.append(Finding(
                "display_name_email_spoof",
                "Display name contains a different email address",
                CRITICAL, 28,
                f"The name shown to the reader is \"{truncate(display, 80)}\", which embeds "
                f"{addr}. The message actually comes from {msg.from_address}. Most mail "
                f"clients show only the display name, so the reader sees a sender that is "
                f"not the real one.",
                category="identity",
                evidence=f"From: {msg.get('from')}",
                recommendation="Always compare the display name with the real address before replying.",
            ))
            break

    # 2. Display name claims a brand the sending domain does not own.
    lowered = display.lower()
    for brand, legit_domains in PROTECTED_BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", lowered):
            if org_domain(msg.from_domain) not in legit_domains:
                severity = CRITICAL if is_freemail(msg.from_domain) else HIGH
                out.append(Finding(
                    "display_name_brand_impersonation",
                    f"Display name impersonates {brand.title()}",
                    severity, 30,
                    f"The sender presents itself as \"{truncate(display, 80)}\" but the mail "
                    f"originates from {msg.from_domain}, which is not a domain operated by "
                    f"{brand.title()} (legitimate: {', '.join(sorted(legit_domains)[:3])}).",
                    category="identity",
                    evidence=f"From: {msg.get('from')}",
                    recommendation=f"Reach {brand.title()} through their official app or website, never this message.",
                ))
            break

    # 3. Display name is itself a domain that disagrees with the real one.
    bare_domain = re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", display.strip())
    if bare_domain and not same_org(display.strip(), msg.from_domain):
        out.append(Finding(
            "display_name_domain_mismatch",
            "Display name is a domain that does not match the sender",
            HIGH, 18,
            f"The display name reads \"{display.strip()}\" while the actual sending domain is "
            f"{msg.from_domain}.",
            category="identity",
            evidence=f"From: {msg.get('from')}",
        ))

    if has_non_ascii(display) and re.search(r"[Ѐ-ӿͰ-Ͽ]", display):
        out.append(Finding(
            "display_name_homoglyph",
            "Display name mixes Cyrillic/Greek letters with Latin",
            HIGH, 16,
            "Characters from other alphabets are being used to imitate Latin letters, a "
            "standard technique for evading keyword-based brand-protection filters.",
            category="identity",
            evidence=display,
        ))
    return out


def check_lookalike_domain(msg) -> List[Finding]:
    """Typosquatting / brand-containment detection against the protected brand list."""
    out: List[Finding] = []
    domain = org_domain(msg.from_domain)
    if not domain or brand_for_domain(domain):
        return out

    label = domain.split(".")[0]
    skeleton = deskeleton(label)

    for brand, legit_domains in PROTECTED_BRANDS.items():
        if skeleton == brand or label == brand:
            out.append(Finding(
                "lookalike_exact_label",
                f"Sending domain reuses the {brand.title()} brand name",
                CRITICAL, 30,
                f"The domain {msg.from_domain} uses the label \"{label}\" but is not one of "
                f"{brand.title()}'s real domains ({', '.join(sorted(legit_domains)[:3])}). "
                f"Registering brand-named domains on an unrelated TLD is the cheapest form "
                f"of impersonation.",
                category="identity",
                evidence=msg.from_domain,
                recommendation="Verify the exact domain against the brand's published sender domains.",
            ))
            return out

        for legit in legit_domains:
            legit_label = legit.split(".")[0]
            distance = levenshtein(deskeleton(label), deskeleton(legit_label))
            if 0 < distance <= 2 and len(legit_label) >= 5:
                out.append(Finding(
                    "lookalike_typosquat",
                    f"Sending domain closely resembles {legit}",
                    CRITICAL, 30,
                    f"{msg.from_domain} is {distance} character edit(s) away from the legitimate "
                    f"domain {legit}. At a glance the two are nearly indistinguishable.",
                    category="identity",
                    evidence=f"{msg.from_domain} vs {legit} (edit distance {distance})",
                    recommendation="Read the domain character by character; treat as hostile until proven otherwise.",
                ))
                return out

        # Brand name embedded as a sub-label: paypal-security-update.com
        if re.search(rf"(^|[.\-]){re.escape(brand)}([.\-]|$)", label) and len(brand) >= 5:
            out.append(Finding(
                "lookalike_brand_in_label",
                f"Brand name '{brand}' embedded in an unrelated domain",
                HIGH, 24,
                f"The domain {msg.from_domain} contains the brand \"{brand}\" but is not "
                f"operated by it. Attackers register names like this so the brand appears in "
                f"the address bar and the From line.",
                category="identity",
                evidence=msg.from_domain,
            ))
            return out
    return out


def check_return_path(msg, dmarc) -> List[Finding]:
    out: List[Finding] = []
    if not msg.return_path_domain:
        if msg.hops:
            out.append(Finding(
                "return_path_missing", "No Return-Path / envelope sender", MEDIUM, 8,
                "The envelope sender could not be determined, so SPF has nothing to validate "
                "against. Delivered mail normally carries a Return-Path added by the final MTA.",
                category="identity",
                evidence="(Return-Path absent)",
            ))
        return out

    if not same_org(msg.return_path_domain, msg.from_domain):
        aligned_by_dkim = bool(dmarc and dmarc.dkim_aligned)
        severity = MEDIUM if aligned_by_dkim else HIGH
        score = 6 if aligned_by_dkim else 14
        out.append(Finding(
            "return_path_mismatch",
            "Envelope sender does not match the visible From domain",
            severity, score,
            f"Mail was actually sent on behalf of {msg.return_path_domain} while the reader "
            f"sees {msg.from_domain}. This is normal for mailing lists and ESPs that sign with "
            f"an aligned DKIM key, but on its own it means SPF authenticates a domain the "
            f"recipient never sees."
            + (" Here DKIM alignment compensates." if aligned_by_dkim else
               " No aligned DKIM signature compensates for it here."),
            category="identity",
            evidence=f"Return-Path: {msg.return_path} | From: {msg.from_address}",
        ))
    return out


def check_reply_to(msg) -> List[Finding]:
    out: List[Finding] = []
    if not msg.reply_to_domain:
        return out
    if same_org(msg.reply_to_domain, msg.from_domain):
        return out

    freemail = is_freemail(msg.reply_to_domain)
    corporate_from = not is_freemail(msg.from_domain)
    severity = CRITICAL if (freemail and corporate_from) else HIGH
    score = 24 if (freemail and corporate_from) else 16

    detail = (
        f"Replies to this message go to {msg.reply_to} instead of {msg.from_address}. "
        f"Reply-To redirection is the mechanism behind business-email-compromise: the victim "
        f"sees a trusted sender, hits reply, and the conversation silently moves to an "
        f"attacker-controlled mailbox."
    )
    if freemail and corporate_from:
        detail += (
            f" The redirect points at a free webmail provider ({msg.reply_to_domain}) while "
            f"the sender claims to be a corporate domain - a textbook BEC signature."
        )

    out.append(Finding(
        "reply_to_mismatch", "Reply-To redirects to a different domain",
        severity, score, detail,
        category="identity",
        evidence=f"Reply-To: {msg.get('reply-to')} | From: {msg.from_address}",
        recommendation="Before replying, delete the Reply-To and type the known-good address manually.",
    ))
    return out


def check_message_id(msg) -> List[Finding]:
    out: List[Finding] = []
    if not msg.message_id:
        out.append(Finding(
            "message_id_missing", "No Message-ID header", MEDIUM, 10,
            "Every MTA stamps a Message-ID. Its absence suggests the message was injected "
            "directly by a script rather than submitted through a normal mail server.",
            category="forensics",
            evidence="(Message-ID absent)",
        ))
        return out

    if msg.message_id_domain and msg.from_domain:
        if not same_org(msg.message_id_domain, msg.from_domain):
            relay_ok = any(
                same_org(msg.message_id_domain, h.by_host) for h in msg.hops if h.by_host
            )
            if not relay_ok:
                out.append(Finding(
                    "message_id_mismatch",
                    "Message-ID domain unrelated to the sender",
                    LOW, 7,
                    f"The Message-ID was generated by {msg.message_id_domain} but the message "
                    f"claims to come from {msg.from_domain}, and no relay in the chain belongs "
                    f"to that domain either. Forged mail often carries a Message-ID that gives "
                    f"away the real origin.",
                    category="forensics",
                    evidence=f"Message-ID: <{msg.message_id}>",
                ))
    return out


# ---------------------------------------------------------------------------
# Transport-path checks
# ---------------------------------------------------------------------------
def check_received_chain(msg) -> List[Finding]:
    out: List[Finding] = []

    if not msg.hops:
        out.append(Finding(
            "received_missing", "No Received headers at all", HIGH, 22,
            "A delivered message always accumulates at least one Received header. With none "
            "present the message was either fabricated wholesale or the headers were trimmed "
            "before capture.",
            category="transport",
            evidence="(no Received headers)",
            recommendation="Re-export the message using 'Show original' / 'View source' to get the full chain.",
        ))
        return out

    if len(msg.hops) == 1:
        out.append(Finding(
            "received_single_hop", "Single-hop delivery path", LOW, 5,
            "Only one Received header is present. Direct-to-MX delivery is normal for some "
            "small senders but is also what a script sending straight to the victim's mail "
            "server produces.",
            category="transport",
            evidence=truncate(msg.hops[0].raw, 200),
        ))

    if len(msg.hops) > 12:
        out.append(Finding(
            "received_many_hops", f"Unusually long relay chain ({len(msg.hops)} hops)",
            LOW, 4,
            "Long chains can indicate open-relay laundering used to obscure the true origin.",
            category="transport",
            evidence=f"{len(msg.hops)} Received headers",
        ))

    # Clock inconsistency: time must not run backwards down the chain.
    for hop in msg.hops:
        if hop.delay_seconds is not None and hop.delay_seconds < -120:
            out.append(Finding(
                "received_time_reversal",
                "Received timestamps run backwards",
                HIGH, 18,
                f"Hop #{hop.index} is timestamped {abs(hop.delay_seconds):.0f} seconds BEFORE "
                f"the hop that supposedly preceded it. Genuine chains move forward in time; "
                f"reversal means at least one Received header was fabricated or inserted.",
                category="transport",
                evidence=truncate(hop.raw, 200),
            ))
            break

    slow = [h for h in msg.hops if h.delay_seconds and h.delay_seconds > 86400]
    if slow:
        out.append(Finding(
            "received_long_delay", "Very large delay between relays", LOW, 3,
            f"Hop #{slow[0].index} sat for {slow[0].delay_seconds / 3600:.1f} hours. Usually "
            f"a queue or greylisting artefact, occasionally a replayed message.",
            category="transport",
            evidence=truncate(slow[0].raw, 200),
        ))

    # Originating IP sanity
    if msg.client_ip and is_private_ip(msg.client_ip):
        out.append(Finding(
            "origin_private_ip", "Message originates from a private IP range", MEDIUM, 10,
            f"The earliest external hop reports {msg.client_ip}, which is an RFC 1918 / "
            f"loopback address. For externally received mail this usually means the real "
            f"origin is hidden or the Received chain was forged.",
            category="transport",
            evidence=f"client IP {msg.client_ip} ({msg.client_ip_source})",
        ))
    elif not msg.client_ip:
        out.append(Finding(
            "origin_unknown", "Originating IP could not be determined", MEDIUM, 10,
            "No usable sender IP appears anywhere in the Received chain, so SPF cannot be "
            "evaluated and the sender's network cannot be attributed.",
            category="transport",
            evidence="(no IP found in Received chain)",
        ))

    # HELO plausibility
    first = msg.hops[0]
    if first.from_host and first.from_rdns:
        if not same_org(first.from_host, first.from_rdns):
            out.append(Finding(
                "helo_rdns_mismatch", "HELO name disagrees with reverse DNS",
                MEDIUM, 9,
                f"The sending host announced itself as \"{first.from_host}\" but its IP "
                f"resolves to \"{first.from_rdns}\". Well-run mail servers make these agree; "
                f"a mismatch is common in botnet and spoofed traffic.",
                category="transport",
                evidence=truncate(first.raw, 200),
            ))
    if first.from_host and msg.from_domain and first.from_host.lower() in ("localhost", "user", "unknown", "[127.0.0.1]"):
        out.append(Finding(
            "helo_generic", f"Generic HELO name '{first.from_host}'", MEDIUM, 10,
            "The first hop identified itself with a placeholder hostname, typical of "
            "a script or malware-infected host rather than a configured mail server.",
            category="transport",
            evidence=truncate(first.raw, 200),
        ))
    return out


def check_dates(msg) -> List[Finding]:
    out: List[Finding] = []
    if not msg.date_header:
        if msg.get("date"):
            out.append(Finding(
                "date_unparsable", "Date header is malformed", LOW, 6,
                "The Date header does not parse as a valid RFC 5322 timestamp, which points "
                "to hand-assembled headers.",
                category="forensics",
                evidence=msg.get("date"),
            ))
        return out

    now = datetime.now(timezone.utc)
    if msg.date_header > now + timedelta(hours=24):
        out.append(Finding(
            "date_future", "Date header is in the future", MEDIUM, 10,
            f"The message claims to have been written on {msg.date_header.isoformat()}, which "
            f"is later than the present. Spammers do this to keep the message pinned to the "
            f"top of the inbox.",
            category="forensics",
            evidence=msg.get("date"),
        ))

    if msg.hops:
        stamps = [h.timestamp for h in msg.hops if h.timestamp]
        if stamps:
            first_relay = min(stamps)
            drift = (first_relay - msg.date_header).total_seconds()
            if drift < -3600:
                out.append(Finding(
                    "date_after_transit", "Composed after it was relayed", HIGH, 14,
                    f"The Date header is {abs(drift) / 3600:.1f} hours later than the first "
                    f"Received timestamp - the message claims to have been written after it "
                    f"was already in transit, which is impossible.",
                    category="forensics",
                    evidence=f"Date: {msg.get('date')} | first relay: {first_relay.isoformat()}",
                ))
            elif drift > 86400 * 3:
                out.append(Finding(
                    "date_stale", "Date far older than the transit path", LOW, 5,
                    f"The Date header predates the first relay by {drift / 86400:.1f} days, "
                    f"which can indicate a replayed or re-sent message.",
                    category="forensics",
                    evidence=f"Date: {msg.get('date')}",
                ))
    return out


# ---------------------------------------------------------------------------
# Content / tooling cues
# ---------------------------------------------------------------------------
def check_subject(msg) -> List[Finding]:
    out: List[Finding] = []
    subject = msg.subject or ""
    if not subject:
        return out

    hits = []
    for pattern, label in URGENCY_PATTERNS:
        if re.search(pattern, subject, re.I):
            hits.append(label)
    if hits:
        score = min(14, 6 + 3 * (len(hits) - 1))
        out.append(Finding(
            "subject_social_engineering",
            "Subject uses pressure / credential-harvesting language",
            MEDIUM, score,
            f"The subject matches known phishing patterns ({', '.join(sorted(set(hits)))}). "
            f"Manufactured urgency is designed to stop the reader from checking the sender.",
            category="content",
            evidence=f"Subject: {truncate(subject, 150)}",
            recommendation="Never act on urgency in an email; verify through an independent channel.",
        ))

    if has_non_ascii(subject) and re.search(r"[Ѐ-ӿ]", subject):
        out.append(Finding(
            "subject_homoglyph", "Cyrillic characters in the subject", LOW, 6,
            "Mixed-script text in the subject is frequently used to slip past keyword filters.",
            category="content",
            evidence=truncate(subject, 150),
        ))
    return out


def check_mailer(msg) -> List[Finding]:
    out: List[Finding] = []
    blob = " ".join(f"{k}: {v}" for k, v in msg.headers)
    for pattern, reason in SUSPICIOUS_MAILERS:
        m = re.search(pattern, blob, re.I)
        if m:
            out.append(Finding(
                "suspicious_mailer", "Sent by a scripted mailer", MEDIUM, 11,
                f"Header evidence indicates {reason}. Legitimate corporate mail is normally "
                f"sent by a mail client or an established ESP.",
                category="content",
                evidence=truncate(m.group(0), 200),
            ))
            break

    if msg.get("x-php-originating-script"):
        out.append(Finding(
            "php_script_origin", "Message generated by a PHP script", HIGH, 14,
            f"X-PHP-Originating-Script reveals the message was emitted by a web script "
            f"({truncate(msg.get('x-php-originating-script'), 80)}). This header is the "
            f"classic fingerprint of mail sent through a compromised website.",
            category="content",
            evidence=msg.get("x-php-originating-script"),
        ))

    bulk = msg.get("precedence").lower()
    if bulk in ("bulk", "junk") and not msg.get("list-unsubscribe"):
        out.append(Finding(
            "bulk_without_unsubscribe", "Bulk mail with no unsubscribe mechanism", LOW, 4,
            "The sender marks the message as bulk but offers no List-Unsubscribe header, "
            "which legitimate bulk senders are expected to provide.",
            category="content",
            evidence=f"Precedence: {bulk}",
        ))
    return out


def check_authres_consistency(msg, authres, spf, dmarc) -> List[Finding]:
    """Compare the receiving server's recorded verdict with our own evaluation."""
    out: List[Finding] = []
    consolidated = authres.get("consolidated", {})

    if not authres.get("present"):
        out.append(Finding(
            "authres_missing", "No Authentication-Results header", LOW, 5,
            "The receiving server did not record an authentication verdict, so the only "
            "evidence available is what this tool can re-derive from DNS. Mail delivered by "
            "any major provider normally carries this header.",
            category="authentication",
            evidence="(Authentication-Results absent)",
        ))
        return out

    recorded_spf = consolidated.get("spf")
    if recorded_spf and spf.result != "none" and recorded_spf != spf.result:
        out.append(Finding(
            "authres_spf_disagreement",
            "Recorded SPF verdict differs from re-evaluation",
            MEDIUM, 8,
            f"The receiving server recorded spf={recorded_spf} but re-checking the current DNS "
            f"gives {spf.result}. This can simply mean the SPF record changed since delivery, "
            f"or that the Authentication-Results header was forged upstream.",
            category="authentication",
            evidence=f"recorded: spf={recorded_spf}; re-evaluated: spf={spf.result}",
        ))

    recorded_dmarc = consolidated.get("dmarc")
    if recorded_dmarc in ("fail", "softfail"):
        out.append(Finding(
            "authres_dmarc_fail", "Receiving server recorded a DMARC failure", HIGH, 20,
            f"The delivering mail server itself concluded dmarc={recorded_dmarc}. That is a "
            f"first-hand verdict from the infrastructure that handled the message.",
            category="authentication",
            evidence=truncate(" | ".join(msg.get_all("authentication-results")), 300),
        ))

    if consolidated.get("compauth") == "fail":
        out.append(Finding(
            "compauth_fail", "Microsoft composite authentication failed", HIGH, 18,
            "Exchange Online's composite authentication (compauth) rejected the sender "
            "identity, which combines SPF, DKIM, DMARC and its own reputation signals.",
            category="authentication",
            evidence=truncate(" | ".join(msg.get_all("authentication-results")), 300),
        ))

    if consolidated.get("dkim") == "fail":
        out.append(Finding(
            "authres_dkim_fail", "Receiving server recorded a DKIM failure", HIGH, 16,
            "The delivering server could not validate the DKIM signature, meaning the message "
            "was altered after signing or the signature was fabricated.",
            category="authentication",
            evidence=truncate(" | ".join(msg.get_all("authentication-results")), 300),
        ))
    return out


# ---------------------------------------------------------------------------
# Authentication -> findings
# ---------------------------------------------------------------------------
def findings_from_spf(spf) -> List[Finding]:
    table = {
        "fail": (CRITICAL, 26, "SPF FAIL - sending IP is not authorised",
                 "The envelope domain's SPF record explicitly states that this IP may not send "
                 "mail on its behalf. Combined with a failed DMARC alignment this is direct "
                 "evidence of spoofing."),
        "softfail": (HIGH, 15, "SPF SOFTFAIL - sending IP is not authorised (soft)",
                     "The IP falls outside the authorised set, but the domain publishes ~all so "
                     "receivers are asked to accept and mark rather than reject."),
        "neutral": (MEDIUM, 8, "SPF NEUTRAL - domain takes no position",
                    "The SPF record explicitly declines to say whether this IP is allowed, which "
                    "provides no protection at all."),
        "none": (MEDIUM, 10, "SPF NONE - no SPF record published",
                 "The envelope domain publishes no SPF policy, so anyone on the internet can "
                 "send mail claiming to be from it without failing this check."),
        "permerror": (MEDIUM, 10, "SPF PERMERROR - record is invalid",
                      "The SPF record is syntactically broken or exceeds the RFC 7208 lookup "
                      "limits, so receivers cannot evaluate it and attackers benefit from the "
                      "ambiguity."),
        "temperror": (LOW, 5, "SPF TEMPERROR - evaluation could not complete",
                      "A transient DNS failure prevented evaluation; re-run the check."),
    }
    if spf.result == "pass":
        return [Finding(
            "spf_pass", "SPF PASS", GOOD, -8,
            spf.explanation, category="authentication",
            evidence=f"record: {truncate(spf.record, 200)}",
        )]
    if spf.result not in table:
        return []
    severity, score, title, detail = table[spf.result]
    return [Finding(
        f"spf_{spf.result}", title, severity, score,
        f"{detail} {spf.explanation}",
        category="authentication",
        evidence=f"domain: {spf.domain}; record: {truncate(spf.record, 200) or '(none)'}",
        recommendation="Confirm the sender through a channel that does not involve this email.",
    )]


def findings_from_dkim(dkim) -> List[Finding]:
    out: List[Finding] = []
    if dkim.result == "none":
        out.append(Finding(
            "dkim_absent", "No DKIM signature", MEDIUM, 12,
            dkim.explanation,
            category="authentication",
            evidence="(no DKIM-Signature header)",
        ))
        return out

    if dkim.result == "fail":
        out.append(Finding(
            "dkim_fail", "DKIM verification failed", CRITICAL, 24,
            dkim.explanation,
            category="authentication",
            evidence="; ".join(i for s in dkim.signatures for i in s.issues)[:400],
            recommendation="Treat the content as untrusted - it does not match what the signer approved.",
        ))
    elif dkim.result == "pass":
        out.append(Finding(
            "dkim_pass", "DKIM signature verified", GOOD, -10,
            dkim.explanation, category="authentication",
            evidence=f"signing domain(s): {', '.join(dkim.verified_domains)}",
        ))

    for sig in dkim.signatures:
        for issue in sig.issues:
            if "RFC 8301 prohibits SHA-1" in issue:
                out.append(Finding(
                    "dkim_weak_algorithm", "DKIM uses deprecated SHA-1", MEDIUM, 8,
                    issue, category="authentication", evidence=f"a={sig.algorithm}",
                ))
            elif "REVOKED" in issue:
                out.append(Finding(
                    "dkim_key_revoked", "DKIM key has been revoked", HIGH, 18,
                    issue, category="authentication", evidence=sig.key_record,
                ))
            elif "l=" in issue and "append" in issue:
                out.append(Finding(
                    "dkim_length_limit", "DKIM signature covers only part of the body",
                    MEDIUM, 10, issue, category="authentication",
                    evidence=f"l={sig.body_length_limit}",
                ))
            elif "requires From to be signed" in issue:
                out.append(Finding(
                    "dkim_from_unsigned", "DKIM does not sign the From header", HIGH, 16,
                    issue, category="authentication", evidence=f"h={':'.join(sig.signed_headers)}",
                ))
            elif "No DKIM public key published" in issue:
                out.append(Finding(
                    "dkim_no_key", "DKIM selector does not exist in DNS", HIGH, 18,
                    issue, category="authentication",
                    evidence=f"{sig.selector}._domainkey.{sig.domain}",
                ))
    return out


def findings_from_dmarc(dmarc) -> List[Finding]:
    out: List[Finding] = []
    if not dmarc.found:
        out.append(Finding(
            "dmarc_absent", "No DMARC policy published", HIGH, 16,
            dmarc.explanation,
            category="authentication",
            evidence=f"_dmarc.{dmarc.from_domain} and _dmarc.{dmarc.org_domain} both empty",
            recommendation="Domain owners should publish at least p=none with rua= to gain visibility.",
        ))
        return out

    if dmarc.result == "fail":
        severity = CRITICAL if dmarc.policy in ("reject", "quarantine") else HIGH
        score = 34 if dmarc.policy == "reject" else (30 if dmarc.policy == "quarantine" else 24)
        out.append(Finding(
            "dmarc_fail", f"DMARC FAIL against p={dmarc.policy}", severity, score,
            dmarc.explanation + " "
            + dmarc.spf_alignment_detail + " " + dmarc.dkim_alignment_detail,
            category="authentication",
            evidence=f"record: {truncate(dmarc.record, 200)}",
            recommendation="This is the strongest single indicator that the From address is forged.",
        ))
    elif dmarc.result.startswith("pass"):
        out.append(Finding(
            "dmarc_pass", "DMARC PASS", GOOD, -22 if dmarc.result == "pass" else -14,
            dmarc.explanation, category="authentication",
            evidence=f"record: {truncate(dmarc.record, 200)}",
        ))

    if dmarc.found and dmarc.policy == "none":
        out.append(Finding(
            "dmarc_policy_none", "DMARC is in monitor-only mode (p=none)", MEDIUM, 9,
            f"{dmarc.from_domain} publishes DMARC but instructs receivers to take no action on "
            f"failures. Forged mail using this domain still reaches inboxes.",
            category="authentication",
            evidence=truncate(dmarc.record, 200),
        ))

    if dmarc.found and 0 < dmarc.pct < 100:
        out.append(Finding(
            "dmarc_partial_pct", f"DMARC policy applies to only {dmarc.pct}% of mail",
            LOW, 5,
            f"pct={dmarc.pct} means {100 - dmarc.pct}% of failing messages bypass the policy.",
            category="authentication",
            evidence=truncate(dmarc.record, 200),
        ))
    return out


# ---------------------------------------------------------------------------
def run_all(msg, spf, dkim, dmarc, authres) -> List[Finding]:
    """Execute every check and return the combined, severity-sorted findings."""
    findings: List[Finding] = []
    findings += findings_from_spf(spf)
    findings += findings_from_dkim(dkim)
    findings += findings_from_dmarc(dmarc)
    findings += check_from_header(msg)
    findings += check_display_name(msg)
    findings += check_lookalike_domain(msg)
    findings += check_return_path(msg, dmarc)
    findings += check_reply_to(msg)
    findings += check_message_id(msg)
    findings += check_received_chain(msg)
    findings += check_dates(msg)
    findings += check_subject(msg)
    findings += check_mailer(msg)
    findings += check_authres_consistency(msg, authres, spf, dmarc)

    # De-duplicate by id, keeping the highest-scoring instance.
    unique: dict = {}
    for f in findings:
        if f.id not in unique or abs(f.score) > abs(unique[f.id].score):
            unique[f.id] = f
    result = list(unique.values())
    result.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -abs(f.score)))
    return result
