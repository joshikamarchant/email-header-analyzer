"""Human-readable rendering of an analysis report (terminal + plain text)."""

from __future__ import annotations

import os
import sys
from typing import Dict, List

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "critical": "\033[97;41m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
    "good": "\033[92m",
}
BAND_COLORS = {
    "Authentic": "\033[92m",
    "Low Risk": "\033[96m",
    "Suspicious": "\033[93m",
    "Likely Spoofed": "\033[91m",
    "Highly Likely Spoofed / Phishing": "\033[97;41m",
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH    ",
    "medium": "MEDIUM  ",
    "low": "LOW     ",
    "info": "INFO    ",
    "good": "PASS    ",
}


def _supports_colour() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{RESET}" if enabled and colour else text


def _wrap(text: str, width: int = 78, indent: str = "    ") -> str:
    import textwrap

    return "\n".join(
        textwrap.fill(para, width=width, initial_indent=indent, subsequent_indent=indent)
        for para in (text or "").split("\n")
    )


def _bar(value: int, width: int = 40) -> str:
    filled = round(width * max(0, min(100, value)) / 100)
    return "█" * filled + "░" * (width - filled)


def render_text(report: Dict, colour: bool = None, verbose: bool = False) -> str:
    use_colour = _supports_colour() if colour is None else colour
    out: List[str] = []
    add = out.append

    verdict = report["verdict"]
    message = report["message"]
    ident = report["identities"]
    auth = report["authentication"]

    band_colour = BAND_COLORS.get(verdict["label"], "")

    add("=" * 80)
    add(_c("  EMAIL HEADER ANALYSIS - SPOOFING DETECTION REPORT", BOLD, use_colour))
    add("=" * 80)
    add("")

    # ---------------- verdict ----------------
    add(f"  VERDICT      {_c(verdict['label'].upper(), band_colour + BOLD, use_colour)}")
    add(f"  RISK SCORE   {verdict['score']:>3}/100  {_c(_bar(verdict['score']), band_colour, use_colour)}")
    add(f"  DOMAIN GRADE {verdict['grade']}   (sender authentication posture)")
    add(f"  CONFIDENCE   {verdict['confidence'].upper()}")
    add("")
    add(_wrap(verdict["advice"]))
    add("")
    if verdict["top_reasons"]:
        add("  Principal reasons:")
        for reason in verdict["top_reasons"]:
            add(f"    - {reason}")
        add("")

    # ---------------- identities ----------------
    add("-" * 80)
    add(_c("  1. SENDER IDENTITIES", BOLD, use_colour))
    add("-" * 80)
    rows = [
        ("Visible From (what the user sees)", ident["visible_from"] or "(none)"),
        ("Display name", message["from_display"] or "(none)"),
        ("Envelope From (Return-Path)", ident["envelope_from"] or "(none)"),
        ("Reply-To", ident["reply_to"] or "(not set)"),
        ("DKIM signing domain(s)", ", ".join(ident["dkim_domains"]) or "(none)"),
        ("Originating IP", f"{ident['originating_ip'] or '(unknown)'}  [{ident['originating_ip_source']}]"),
        ("HELO / EHLO announced", ident["helo"] or "(none)"),
        ("Subject", message["subject"] or "(none)"),
        ("Date", message["date"] or "(none)"),
        ("Message-ID", message["message_id"] or "(none)"),
    ]
    for label, value in rows:
        add(f"  {label:<34} {value}")
    add("")

    # ---------------- authentication ----------------
    add("-" * 80)
    add(_c("  2. AUTHENTICATION RESULTS", BOLD, use_colour))
    add("-" * 80)

    spf = auth["spf"]
    add(f"  {_c('SPF  ', BOLD, use_colour)} {spf['result'].upper()}")
    add(_wrap(spf["explanation"]))
    if spf["record"]:
        add(_wrap(f"Record: {spf['record']}", indent="      "))
    if spf["matched_mechanism"]:
        add(f"      Matched mechanism: {spf['matched_mechanism']}  "
            f"(DNS lookups used: {spf['lookups_used']}/10)")
    for warning in spf["warnings"]:
        add(_wrap(f"! {warning}", indent="      "))
    add("")

    dkim = auth["dkim"]
    add(f"  {_c('DKIM ', BOLD, use_colour)} {dkim['result'].upper()}"
        f"{'  (cryptographically verified)' if dkim['cryptographic'] else '  (structural audit only)'}")
    add(_wrap(dkim["explanation"]))
    for sig in dkim["signatures"]:
        add(f"      Signature #{sig['index']}: d={sig['domain']} s={sig['selector']} "
            f"a={sig['algorithm']} key={sig['key_bits'] or '?'} bits "
            f"{'[key found]' if sig['key_found'] else '[NO KEY IN DNS]'}")
        if sig["signed_headers"]:
            add(f"        signs: {':'.join(sig['signed_headers'])}")
        for issue in sig["issues"]:
            add(_wrap(f"! {issue}", indent="        "))
    add("")

    dmarc = auth["dmarc"]
    add(f"  {_c('DMARC', BOLD, use_colour)} {dmarc['result'].upper()}")
    add(_wrap(dmarc["explanation"]))
    if dmarc["found"]:
        add(f"      Policy: p={dmarc['policy']}"
            + (f" sp={dmarc['subdomain_policy']}" if dmarc["subdomain_policy"] else "")
            + f" pct={dmarc['pct']} adkim={dmarc['adkim']} aspf={dmarc['aspf']}")
        add(f"      Found at: {dmarc['located_at']}")
        add(_wrap(f"SPF alignment:  {dmarc['spf_alignment_detail']}", indent="      "))
        add(_wrap(f"DKIM alignment: {dmarc['dkim_alignment_detail']}", indent="      "))
    for issue in dmarc["issues"]:
        add(_wrap(f"! {issue}", indent="      "))
    add("")

    add(f"  {_c('RECEIVER', BOLD, use_colour)}")
    add(_wrap(auth["recorded_summary"]))
    add("")

    # ---------------- transport path ----------------
    add("-" * 80)
    add(_c("  3. DELIVERY PATH", BOLD, use_colour))
    add("-" * 80)
    if not message["hops"]:
        add("  No Received headers present.")
    for hop in message["hops"]:
        delay = ""
        if hop["delay_seconds"] is not None:
            delay = f"  (+{hop['delay_seconds']:.0f}s)" if hop["delay_seconds"] >= 0 \
                else f"  ({hop['delay_seconds']:.0f}s BACKWARDS)"
        add(f"  Hop {hop['index']}{delay}")
        add(f"    from {hop['from_host'] or '?'}"
            + (f" ({hop['from_rdns']})" if hop["from_rdns"] else "")
            + (f" [{hop['from_ip']}]" if hop["from_ip"] else ""))
        add(f"    by   {hop['by_host'] or '?'}"
            + (f" with {hop['protocol']}" if hop["protocol"] else ""))
        if hop["timestamp"]:
            add(f"    at   {hop['timestamp']}")
    add("")

    # ---------------- findings ----------------
    add("-" * 80)
    counts = verdict["counts"]
    add(_c(f"  4. FINDINGS  ({counts['critical']} critical, {counts['high']} high, "
           f"{counts['medium']} medium, {counts['low']} low, {counts['good']} passing)",
           BOLD, use_colour))
    add("-" * 80)
    for finding in report["findings"]:
        if finding["severity"] == "good" and not verbose:
            continue
        tag = SEVERITY_LABEL.get(finding["severity"], finding["severity"].upper())
        sign = "+" if finding["score"] > 0 else ""
        add(f"  [{_c(tag, COLORS.get(finding['severity'], ''), use_colour)}] "
            f"{finding['title']}  ({sign}{finding['score']})")
        add(_wrap(finding["detail"]))
        if finding["evidence"]:
            add(_wrap(f"Evidence: {finding['evidence']}", indent="      "))
        add("")

    if verbose:
        add("-" * 80)
        add(_c("  PASSING CHECKS", BOLD, use_colour))
        add("-" * 80)
        for finding in report["findings"]:
            if finding["severity"] == "good":
                add(f"  [{_c('PASS', COLORS['good'], use_colour)}] {finding['title']}")
                add(_wrap(finding["detail"]))
                add("")

    # ---------------- recommendations ----------------
    add("-" * 80)
    add(_c("  5. RECOMMENDED ACTIONS", BOLD, use_colour))
    add("-" * 80)
    add("  For the recipient:")
    for item in report["recommendations"]["recipient"]:
        add(_wrap(f"- {item}", indent="    "))
    if report["recommendations"]["domain_owner"]:
        add("")
        add("  For the domain owner:")
        for item in report["recommendations"]["domain_owner"]:
            add(_wrap(f"- {item}", indent="    "))
    add("")

    meta = report["meta"]
    dns = meta["dns"]
    add("-" * 80)
    add(f"  DNS: {dns['queries']} queries ({dns['live_answers']} live, "
        f"{dns['fixture_answers']} from offline fixtures) | mode={dns['mode']}")
    add(f"  Analysed in {meta['duration_seconds']}s by {meta['tool']} v{meta['version']}")
    if not meta["full_message_supplied"]:
        add("  Note: headers only - paste the complete raw email for cryptographic DKIM "
            "verification.")
    add("=" * 80)
    return "\n".join(out)
