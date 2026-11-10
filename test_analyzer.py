"""
Test suite for the Email Header Analyzer.

Everything runs against the bundled DNS fixtures (dns_mode="offline"), so the
suite is deterministic and needs no internet access.

    pytest -v
"""

from __future__ import annotations

import glob
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.dkim_check import analyse_dkim, parse_tag_list
from analyzer.dmarc import analyse_dmarc, check_alignment, lookup_dmarc
from analyzer.dns_utils import DNSLookupLimit, Resolver
from analyzer.engine import Analyzer
from analyzer.heuristics import run_all
from analyzer.parser import parse_message, parse_received, repair_headers
from analyzer.spf import check_spf, expand_macros
from analyzer.utils import (
    deskeleton,
    is_freemail,
    is_private_ip,
    levenshtein,
    org_domain,
    same_org,
    split_address,
)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(BASE, "samples")


@pytest.fixture
def resolver():
    return Resolver(mode="offline")


@pytest.fixture
def analyzer():
    return Analyzer(dns_mode="offline")


def sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


# ===========================================================================
# utils
# ===========================================================================
class TestUtils:
    @pytest.mark.parametrize("domain,expected", [
        ("mail.google.com", "google.com"),
        ("google.com", "google.com"),
        ("news.corp.example.co.in", "example.co.in"),
        ("bbc.co.uk", "bbc.co.uk"),
        ("a.b.c.bbc.co.uk", "bbc.co.uk"),
        ("sub.example.com.au", "example.com.au"),
        ("localhost", "localhost"),
        ("", ""),
    ])
    def test_org_domain(self, domain, expected):
        assert org_domain(domain) == expected

    def test_same_org_relaxed_alignment(self):
        assert same_org("mail.paypal.com", "paypal.com")
        assert same_org("a.example.co.in", "b.example.co.in")
        assert not same_org("paypal.com", "paypal-secure.com")
        assert not same_org("", "paypal.com")

    def test_split_address(self):
        assert split_address("Bob <bob@Example.COM>") == ("Bob <bob", "example.com")
        assert split_address("bob@example.com") == ("bob", "example.com")
        assert split_address(None) == ("", "")

    def test_private_ip(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("10.0.0.5")
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("not-an-ip")

    def test_levenshtein(self):
        assert levenshtein("paypal", "paypal") == 0
        assert levenshtein("paypal", "paypa1") == 1
        assert levenshtein("", "abc") == 3

    def test_deskeleton_normalises_homoglyphs(self):
        assert deskeleton("paypa1") == "paypal"
        assert deskeleton("rnicrosoft") == "microsoft"
        assert deskeleton("g00gle") == "google"

    def test_freemail(self):
        assert is_freemail("gmail.com")
        assert is_freemail("mail.yahoo.com")        # matched via organizational domain
        assert not is_freemail("examplebank.in")


# ===========================================================================
# parser
# ===========================================================================
class TestParser:
    def test_refolds_broken_continuations(self):
        broken = "Received: from a.example.com\n(a.example.com [1.2.3.4])\nby b.example.com;\nFrom: x@y.com"
        fixed = repair_headers(broken)
        msg = parse_message(fixed)
        assert msg.count("received") == 1
        assert "1.2.3.4" in msg.get("received")

    def test_strips_quote_markers(self):
        quoted = "> From: a@b.com\n> Subject: hi\n> To: c@d.com"
        msg = parse_message(quoted)
        assert msg.from_address == "a@b.com"
        assert msg.subject == "hi"

    def test_parse_received_components(self):
        raw = ("from mail.example.com (mail.example.com [203.0.113.5]) "
               "by mx.test.in with ESMTPS id ABC for <u@test.in>; "
               "Mon, 03 Nov 2026 02:41:11 +0530")
        hop = parse_received(raw, 1)
        assert hop.from_host == "mail.example.com"
        assert hop.from_ip == "203.0.113.5"
        assert hop.by_host == "mx.test.in"
        assert hop.protocol.startswith("ESMTP")
        assert hop.recipient == "u@test.in"
        assert hop.timestamp is not None

    def test_hop_ordering_is_chronological(self):
        msg = parse_message(sample("05_forged_received_chain.eml"))
        assert len(msg.hops) == 2
        assert msg.hops[0].index == 1
        # bottom-most header is the oldest hop
        assert msg.hops[0].from_host == "localhost"

    def test_client_ip_prefers_authentication_results(self):
        msg = parse_message(sample("01_legit_google_alert.eml"))
        assert msg.client_ip == "209.85.220.69"
        assert "client-ip" in msg.client_ip_source

    def test_decodes_mime_encoded_display_name(self):
        raw = "From: =?utf-8?B?UGF5UGFsIFNlcnZpY2U=?= <a@b.com>\nTo: c@d.com"
        msg = parse_message(raw)
        assert msg.from_display == "PayPal Service"

    def test_extracts_all_identities(self):
        msg = parse_message(sample("04_bec_ceo_fraud.eml"))
        assert msg.from_domain == "northwind-industries.com"
        assert msg.reply_to_domain == "gmail.com"
        assert msg.return_path_domain == "northwind-industries.com"

    def test_headers_only_has_no_body(self):
        assert parse_message(sample("02_spoofed_paypal_dmarc_reject.eml")).has_body is False


# ===========================================================================
# SPF
# ===========================================================================
class TestSPF:
    def test_ip4_mechanism_pass(self, resolver):
        r = check_spf(resolver, "103.21.244.17", "examplebank.in")
        assert r.result == "pass"
        assert r.matched.startswith("ip4:")

    def test_all_mechanism_fail(self, resolver):
        r = check_spf(resolver, "185.234.218.37", "paypal.com")
        assert r.result == "fail"
        assert r.matched == "-all"

    def test_include_chain_resolves(self, resolver):
        r = check_spf(resolver, "209.85.220.69", "gaia.bounces.google.com")
        assert r.result == "pass"
        assert r.lookups_used >= 2          # include:_spf.google.com -> _netblocks

    def test_softfail_from_tilde_all(self, resolver):
        r = check_spf(resolver, "103.89.12.45", "northwind-industries.com")
        assert r.result == "softfail"

    def test_mx_mechanism(self, resolver):
        r = check_spf(resolver, "136.143.188.10", "sfo-campus.in")
        assert r.result == "pass"
        assert r.matched == "mx"

    def test_mx_mechanism_non_matching_ip_fails(self, resolver):
        r = check_spf(resolver, "91.200.12.44", "sfo-campus.in")
        assert r.result == "fail"

    def test_no_record_yields_none(self, resolver):
        r = check_spf(resolver, "1.2.3.4", "campus-itdesk.com")
        assert r.result == "none"

    def test_missing_ip_yields_none(self, resolver):
        assert check_spf(resolver, "", "paypal.com").result == "none"

    def test_invalid_ip_is_permerror(self, resolver):
        assert check_spf(resolver, "999.999.1.1", "paypal.com").result == "permerror"

    def test_lookup_budget_is_enforced(self):
        r = Resolver(mode="offline")
        r.reset_budget()
        with pytest.raises(DNSLookupLimit):
            for _ in range(12):
                r.spend()

    @pytest.mark.parametrize("template,expected", [
        ("%{d}", "example.com"),
        ("%{i}", "1.2.3.4"),
        ("%{o}", "example.com"),
        ("%{l}", "alice"),
    ])
    def test_macro_expansion(self, template, expected):
        assert expand_macros(template, "1.2.3.4", "alice@example.com",
                             "example.com", "helo.example.com") == expected


# ===========================================================================
# DKIM
# ===========================================================================
class TestDKIM:
    def test_tag_list_parsing(self):
        tags = parse_tag_list("v=1; a=rsa-sha256; d=example.com; s=sel")
        assert tags["a"] == "rsa-sha256"
        assert tags["d"] == "example.com"

    def test_no_signature_is_none(self, resolver):
        report = analyse_dkim(resolver, "", [], "example.com")
        assert report.result == "none"

    def test_published_key_is_found_and_sized(self, resolver):
        sig = ("v=1; a=rsa-sha256; c=relaxed/relaxed; d=brightlearn.io; s=s1; "
               "h=from:to:subject:date:message-id; bh=AAAA; b=BBBB")
        report = analyse_dkim(resolver, "", [sig], "brightlearn.io")
        assert report.signatures[0].key_found
        assert report.signatures[0].key_bits == 2048

    def test_weak_key_is_reported(self, resolver):
        sig = ("v=1; a=rsa-sha256; c=relaxed/relaxed; d=icici-netbanking-secure.com; "
               "s=s1; h=from:to:subject:date; bh=AAAA; b=BBBB")
        report = analyse_dkim(resolver, "", [sig], "icici-netbanking-secure.com")
        assert report.signatures[0].key_bits == 1024
        assert any("1024 bits" in i for i in report.signatures[0].issues)

    def test_missing_from_in_h_tag_is_flagged(self, resolver):
        sig = "v=1; a=rsa-sha256; d=brightlearn.io; s=s1; h=to:subject; bh=AAAA; b=BBBB"
        report = analyse_dkim(resolver, "", [sig], "brightlearn.io")
        assert any("requires From to be signed" in i for i in report.signatures[0].issues)

    def test_sha1_is_flagged(self, resolver):
        sig = "v=1; a=rsa-sha1; d=brightlearn.io; s=s1; h=from:to; bh=AAAA; b=BBBB"
        report = analyse_dkim(resolver, "", [sig], "brightlearn.io")
        assert any("SHA-1" in i for i in report.signatures[0].issues)

    def test_body_length_limit_is_flagged(self, resolver):
        sig = "v=1; a=rsa-sha256; d=brightlearn.io; s=s1; h=from; l=100; bh=A; b=B"
        report = analyse_dkim(resolver, "", [sig], "brightlearn.io")
        assert any("l=100" in i for i in report.signatures[0].issues)

    def test_unknown_selector_fails(self, resolver):
        sig = "v=1; a=rsa-sha256; d=example.org; s=nosuch; h=from; bh=A; b=B"
        report = analyse_dkim(resolver, "", [sig], "example.org")
        assert report.result == "fail"

    def test_missing_required_tag_fails(self, resolver):
        report = analyse_dkim(resolver, "", ["v=1; a=rsa-sha256; s=s1; h=from; bh=A"],
                              "brightlearn.io")
        assert report.result == "fail"


# ===========================================================================
# DMARC
# ===========================================================================
class TestDMARC:
    def test_record_lookup(self, resolver):
        record, name, _ = lookup_dmarc(resolver, "paypal.com")
        assert record and "p=reject" in record
        assert name == "_dmarc.paypal.com"

    def test_organizational_domain_fallback(self, resolver):
        record, name, _ = lookup_dmarc(resolver, "accounts.google.com")
        assert record is not None
        assert name == "_dmarc.google.com"

    def test_missing_record(self, resolver):
        record, _, _ = lookup_dmarc(resolver, "campus-itdesk.com")
        assert record is None

    @pytest.mark.parametrize("child,parent,mode,expected", [
        ("mail.example.com", "example.com", "r", True),
        ("mail.example.com", "example.com", "s", False),
        ("example.com", "example.com", "s", True),
        ("sendgrid.net", "brightlearn.io", "r", False),
    ])
    def test_alignment_modes(self, child, parent, mode, expected):
        assert check_alignment(child, parent, mode)[0] is expected

    def test_pass_via_aligned_spf(self, resolver):
        spf = check_spf(resolver, "209.85.220.69", "gaia.bounces.google.com")
        dkim = analyse_dkim(resolver, "", [], "accounts.google.com")
        report = analyse_dmarc(resolver, "accounts.google.com", spf, dkim,
                               envelope_domain="gaia.bounces.google.com")
        assert report.result.startswith("pass")
        assert report.spf_aligned

    def test_fail_when_nothing_aligns(self, resolver):
        spf = check_spf(resolver, "185.234.218.37", "paypal.com")
        dkim = analyse_dkim(resolver, "", [], "paypal.com")
        report = analyse_dmarc(resolver, "paypal.com", spf, dkim, envelope_domain="paypal.com")
        assert report.result == "fail"
        assert report.policy == "reject"
        assert report.disposition == "reject"

    def test_no_policy_is_none(self, resolver):
        spf = check_spf(resolver, "91.200.12.44", "sfo-campus.in")
        dkim = analyse_dkim(resolver, "", [], "sfo-campus.in")
        report = analyse_dmarc(resolver, "sfo-campus.in", spf, dkim)
        assert report.result == "none"
        assert not report.found


# ===========================================================================
# Heuristics
# ===========================================================================
class TestHeuristics:
    def _ids(self, analyzer, filename):
        report = analyzer.analyze(sample(filename))
        return {f["id"] for f in report["findings"]}, report

    def test_reply_to_redirection_detected(self, analyzer):
        ids, _ = self._ids(analyzer, "04_bec_ceo_fraud.eml")
        assert "reply_to_mismatch" in ids

    def test_brand_impersonation_detected(self, analyzer):
        ids, _ = self._ids(analyzer, "03_lookalike_domain_authenticated.eml")
        assert "display_name_brand_impersonation" in ids
        assert "lookalike_brand_in_label" in ids

    def test_time_reversal_detected(self, analyzer):
        ids, _ = self._ids(analyzer, "05_forged_received_chain.eml")
        assert "received_time_reversal" in ids

    def test_php_script_origin_detected(self, analyzer):
        ids, _ = self._ids(analyzer, "05_forged_received_chain.eml")
        assert "php_script_origin" in ids

    def test_urgency_subject_detected(self, analyzer):
        ids, _ = self._ids(analyzer, "02_spoofed_paypal_dmarc_reject.eml")
        assert "subject_social_engineering" in ids

    def test_clean_message_has_no_critical_findings(self, analyzer):
        _, report = self._ids(analyzer, "08_legit_strict_alignment.eml")
        assert report["verdict"]["counts"]["critical"] == 0

    def test_display_name_embedded_address(self):
        raw = ('From: "support@paypal.com" <attacker@evil.tk>\n'
               "To: v@example.com\nSubject: hello")
        msg = parse_message(raw)
        from analyzer.heuristics import check_display_name
        ids = {f.id for f in check_display_name(msg)}
        assert "display_name_email_spoof" in ids

    def test_duplicate_from_header(self):
        raw = "From: a@good.com\nFrom: b@evil.com\nTo: v@example.com"
        msg = parse_message(raw)
        from analyzer.heuristics import check_from_header
        ids = {f.id for f in check_from_header(msg)}
        assert "from_duplicate" in ids


# ===========================================================================
# End-to-end regression over the sample corpus
# ===========================================================================
EXPECTED = {
    "01_legit_google_alert.eml":            ("Authentic", "pass", "pass"),
    "02_spoofed_paypal_dmarc_reject.eml":   ("Highly Likely Spoofed / Phishing", "fail", "fail"),
    "03_lookalike_domain_authenticated.eml": ("Likely Spoofed", "pass", "pass"),
    "04_bec_ceo_fraud.eml":                 ("Highly Likely Spoofed / Phishing", "softfail", "fail"),
    "05_forged_received_chain.eml":         ("Highly Likely Spoofed / Phishing", "none", "none"),
    "06_legit_newsletter_esp.eml":          ("Authentic", "pass", "pass"),
    "07_internal_spoof_no_dmarc.eml":       ("Likely Spoofed", "fail", "none"),
    "08_legit_strict_alignment.eml":        ("Authentic", "pass", "pass"),
}


class TestEndToEnd:
    @pytest.mark.parametrize("filename,expected", sorted(EXPECTED.items()))
    def test_sample_classification(self, analyzer, filename, expected):
        label, spf_result, dmarc_result = expected
        report = analyzer.analyze(sample(filename))
        assert report["verdict"]["label"] == label, (
            f"{filename}: got {report['verdict']['label']} "
            f"(score {report['verdict']['score']})"
        )
        assert report["authentication"]["spf"]["result"] == spf_result
        assert report["authentication"]["dmarc"]["result"].startswith(dmarc_result)

    def test_every_sample_file_is_covered(self):
        on_disk = {os.path.basename(p) for p in glob.glob(os.path.join(SAMPLES, "*.eml"))}
        assert on_disk == set(EXPECTED)

    def test_report_is_json_serialisable(self, analyzer):
        report = analyzer.analyze(sample("02_spoofed_paypal_dmarc_reject.eml"))
        assert json.loads(json.dumps(report, default=str))["verdict"]["score"] == 100

    def test_report_structure(self, analyzer):
        report = analyzer.analyze(sample("01_legit_google_alert.eml"))
        for key in ("meta", "message", "identities", "authentication",
                    "findings", "verdict", "recommendations"):
            assert key in report

    def test_empty_input_does_not_crash(self, analyzer):
        report = analyzer.analyze("Subject: nothing here")
        assert report["verdict"]["score"] >= 0

    def test_sparse_input_is_capped_for_lack_of_evidence(self, analyzer):
        """Missing headers must never produce a confident 'spoofed' verdict."""
        report = analyzer.analyze("From: a@b.com\nTo: c@d.com\nSubject: Quarterly report")
        v = report["verdict"]
        assert v["capped_for_insufficient_evidence"] is True
        assert v["score"] <= 44
        assert "incomplete" in v["advice"]

    def test_real_evidence_is_not_capped(self, analyzer):
        report = analyzer.analyze(sample("05_forged_received_chain.eml"))
        assert report["verdict"]["capped_for_insufficient_evidence"] is False
        assert report["verdict"]["score"] == 100

    def test_garbage_input_does_not_crash(self, analyzer):
        report = analyzer.analyze("!!! not an email at all \x00\x01 ???")
        assert "verdict" in report

    def test_no_dns_mode_runs_heuristics_only(self):
        a = Analyzer(dns_mode="offline", check_dns=False)
        report = a.analyze(sample("02_spoofed_paypal_dmarc_reject.eml"))
        assert report["authentication"]["spf"]["result"] == "none"
        assert report["verdict"]["score"] > 0

    def test_spoofed_scores_above_legitimate(self, analyzer):
        spoofed = analyzer.analyze(sample("02_spoofed_paypal_dmarc_reject.eml"))
        legit = analyzer.analyze(sample("08_legit_strict_alignment.eml"))
        assert spoofed["verdict"]["score"] > legit["verdict"]["score"] + 50


# ===========================================================================
# Web layer
# ===========================================================================
class TestWebApp:
    @pytest.fixture
    def client(self):
        from app import app as flask_app

        flask_app.config.update(TESTING=True, DNS_MODE="offline")
        with flask_app.test_client() as c:
            yield c

    def test_home_page_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Email Header Analyzer" in resp.data

    def test_sample_route_loads_headers(self, client):
        resp = client.get("/sample/02_spoofed_paypal_dmarc_reject.eml")
        assert resp.status_code == 200
        assert b"paypal" in resp.data.lower()

    def test_sample_route_rejects_traversal(self, client):
        assert client.get("/sample/..%2F..%2Fetc%2Fpasswd").status_code in (404, 400)

    def test_post_renders_verdict(self, client):
        resp = client.post("/", data={"headers": sample("02_spoofed_paypal_dmarc_reject.eml")})
        assert resp.status_code == 200
        assert b"Highly Likely Spoofed" in resp.data

    def test_post_empty_shows_error(self, client):
        resp = client.post("/", data={"headers": "   "})
        assert b"Paste the raw email headers first" in resp.data

    def test_json_api(self, client):
        resp = client.post("/api/analyze",
                           json={"headers": sample("04_bec_ceo_fraud.eml")})
        assert resp.status_code == 200
        assert resp.get_json()["verdict"]["score"] > 50

    def test_json_api_rejects_empty(self, client):
        assert client.post("/api/analyze", json={"headers": ""}).status_code == 400

    def test_text_api(self, client):
        resp = client.post("/api/analyze.txt",
                           json={"headers": sample("01_legit_google_alert.eml")})
        assert resp.status_code == 200
        assert b"EMAIL HEADER ANALYSIS" in resp.data

    def test_samples_listing(self, client):
        assert len(client.get("/api/samples").get_json()) == 8
