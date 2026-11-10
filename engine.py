"""Orchestration: raw headers in, structured spoofing report out."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import authres as authres_mod
from .dkim_check import analyse_dkim
from .dmarc import analyse_dmarc, summarise_dmarc
from .dns_utils import Resolver
from .heuristics import CRITICAL, HIGH, run_all
from .parser import parse_message
from .scoring import score
from .spf import check_spf, summarise_spf
from .utils import org_domain


class Analyzer:
    """Re-usable analyzer. One instance may process many messages."""

    def __init__(
        self,
        dns_mode: str = "auto",
        fixtures_path: Optional[str] = None,
        check_dns: bool = True,
        timeout: float = 5.0,
        nameservers: Optional[List[str]] = None,
    ) -> None:
        self.dns_mode = dns_mode
        self.fixtures_path = fixtures_path
        self.check_dns = check_dns
        self.timeout = timeout
        self.nameservers = nameservers

    # ------------------------------------------------------------------ #
    def analyze(self, raw: str) -> Dict[str, object]:
        started = datetime.now(timezone.utc)
        resolver = Resolver(
            mode=self.dns_mode,
            fixtures_path=self.fixtures_path,
            timeout=self.timeout,
            nameservers=self.nameservers,
        )

        msg = parse_message(raw)

        # ---------------- SPF ----------------
        envelope_domain = msg.return_path_domain or msg.from_domain
        if self.check_dns:
            spf = check_spf(
                resolver,
                ip=msg.client_ip,
                domain=envelope_domain,
                sender=msg.return_path or msg.from_address,
                helo=msg.helo,
            )
        else:
            from .spf import SPFResult

            spf = SPFResult(result="none", domain=envelope_domain,
                            explanation="DNS checks were disabled (--no-dns).")

        # ---------------- DKIM ----------------
        dkim = analyse_dkim(
            resolver,
            raw_message=msg.raw,
            signatures_raw=msg.get_all("dkim-signature"),
            from_domain=msg.from_domain,
            has_body=msg.has_body,
            check_dns=self.check_dns,
        )

        # ---------------- DMARC ----------------
        dmarc = analyse_dmarc(
            resolver,
            from_domain=msg.from_domain,
            spf=spf,
            dkim=dkim,
            envelope_domain=envelope_domain,
            check_dns=self.check_dns,
        )

        # ---------------- recorded verdicts ----------------
        recorded = authres_mod.collect(
            msg.get_all("authentication-results"),
            msg.get_all("received-spf"),
        )

        # ---------------- heuristics + scoring ----------------
        findings = run_all(msg, spf, dkim, dmarc, recorded)

        dns_live = any(q["source"] == "live" and not q["error"] for q in resolver.query_log)
        verdict = score(findings, spf, dkim, dmarc, {
            "dns_live": dns_live,
            "has_body": msg.has_body,
            "hop_count": len(msg.hops),
            "client_ip": msg.client_ip,
        })

        elapsed = (datetime.now(timezone.utc) - started).total_seconds()

        return {
            "meta": {
                "tool": "Email Header Analyzer for Spoofing Detection",
                "version": "1.0.0",
                "analyzed_at": started.isoformat(),
                "duration_seconds": round(elapsed, 3),
                "dns": resolver.describe(),
                "dns_live": dns_live,
                "full_message_supplied": msg.has_body,
            },
            "message": msg.to_dict(),
            "identities": {
                "visible_from": msg.from_address,
                "visible_from_domain": msg.from_domain,
                "visible_from_org": org_domain(msg.from_domain),
                "envelope_from": msg.return_path,
                "envelope_from_domain": envelope_domain,
                "reply_to": msg.reply_to,
                "dkim_domains": [s.domain for s in dkim.signatures if s.domain],
                "originating_ip": msg.client_ip,
                "originating_ip_source": msg.client_ip_source,
                "helo": msg.helo,
            },
            "authentication": {
                "spf": spf.to_dict(),
                "spf_summary": summarise_spf(spf),
                "dkim": dkim.to_dict(),
                "dkim_summary": dkim.explanation,
                "dmarc": dmarc.to_dict(),
                "dmarc_summary": summarise_dmarc(dmarc),
                "recorded_by_receiver": recorded,
                "recorded_summary": authres_mod.describe(recorded.get("consolidated", {})),
            },
            "findings": [f.to_dict() for f in findings],
            "verdict": verdict.to_dict(),
            "recommendations": build_recommendations(findings, verdict, dmarc),
        }


def build_recommendations(findings, verdict, dmarc) -> Dict[str, List[str]]:
    """Split actionable advice for the recipient and for the domain owner."""
    recipient: List[str] = []
    owner: List[str] = []

    severe = [f for f in findings if f.severity in (CRITICAL, HIGH)]
    if verdict.score >= 45:
        recipient.append(
            "Do not reply, click any link, open attachments, or act on instructions in this "
            "message."
        )
        recipient.append(
            "Report it to your IT/security team and preserve the original headers as evidence."
        )
    elif verdict.score >= 25:
        recipient.append(
            "Verify the sender through a known-good channel (phone, official app, a previously "
            "trusted address) before acting."
        )
    else:
        recipient.append(
            "No action required beyond normal caution; the message authenticates as claimed."
        )

    for f in severe:
        if f.recommendation and f.recommendation not in recipient:
            recipient.append(f.recommendation)

    if not dmarc.found:
        owner.append(
            f"Publish a DMARC record at _dmarc.{dmarc.from_domain} starting with "
            f"'v=DMARC1; p=none; rua=mailto:dmarc@{dmarc.from_domain}' to gain visibility, "
            f"then move to p=quarantine and p=reject."
        )
    elif dmarc.policy == "none":
        owner.append(
            "Move the DMARC policy from p=none to p=quarantine and then p=reject once "
            "aggregate reports show all legitimate sources aligned."
        )
    if any(f.id in ("spf_none", "spf_permerror") for f in findings):
        owner.append(
            "Publish or repair the SPF record; keep it under the 10 DNS-lookup limit and end "
            "it with -all once every legitimate sender is listed."
        )
    if any(f.id in ("dkim_absent", "dkim_no_key") for f in findings):
        owner.append("Enable DKIM signing with a 2048-bit key and ensure the selector resolves.")
    if any(f.id == "dkim_weak_algorithm" for f in findings):
        owner.append("Re-key DKIM to rsa-sha256; SHA-1 signatures are deprecated by RFC 8301.")

    return {"recipient": recipient[:6], "domain_owner": owner[:5]}


def analyze(
    raw: str,
    dns_mode: str = "auto",
    fixtures_path: Optional[str] = None,
    check_dns: bool = True,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """Convenience wrapper: analyse one raw header block."""
    return Analyzer(
        dns_mode=dns_mode,
        fixtures_path=fixtures_path,
        check_dns=check_dns,
        timeout=timeout,
    ).analyze(raw)
