"""
DKIM analysis (RFC 6376 + RFC 8301 crypto hardening).

Two levels of analysis are performed depending on what the user supplies:

  * Headers only  -> structural audit of each DKIM-Signature plus a DNS lookup
                     of the published public key (selector, algorithm, key size,
                     revocation, flags). Cryptographic verification is impossible
                     because the body hash (bh=) cannot be recomputed without
                     the body.
  * Full message  -> everything above, plus a real cryptographic verification
                     using dkimpy.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .dns_utils import Resolver
from .utils import is_subdomain_of, normalise_domain, truncate

try:  # optional, used only when a full message body is present
    import dkim as dkimpy

    _HAVE_DKIMPY = True
except Exception:  # pragma: no cover
    _HAVE_DKIMPY = False

try:
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


WEAK_ALGORITHMS = {"rsa-sha1", "sha1"}
REQUIRED_SIGNED_HEADERS = {"from"}
RECOMMENDED_SIGNED_HEADERS = {"from", "to", "subject", "date", "message-id"}


@dataclass
class DKIMSignature:
    index: int
    raw: str
    tags: Dict[str, str] = field(default_factory=dict)
    domain: str = ""
    selector: str = ""
    algorithm: str = ""
    canonicalization: str = ""
    signed_headers: List[str] = field(default_factory=list)
    identity: str = ""
    body_length_limit: Optional[int] = None
    timestamp: Optional[int] = None
    expiry: Optional[int] = None

    key_found: bool = False
    key_record: str = ""
    key_type: str = ""
    key_bits: Optional[int] = None
    key_revoked: bool = False
    key_testing: bool = False
    key_strict_subdomain: bool = False

    verified: Optional[bool] = None      # None = not cryptographically checked
    verify_detail: str = ""
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "domain": self.domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "identity": self.identity,
            "body_length_limit": self.body_length_limit,
            "timestamp": self.timestamp,
            "expiry": self.expiry,
            "key_found": self.key_found,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "key_revoked": self.key_revoked,
            "key_testing": self.key_testing,
            "verified": self.verified,
            "verify_detail": self.verify_detail,
            "issues": self.issues,
            "raw": truncate(self.raw, 300),
        }


@dataclass
class DKIMReport:
    signatures: List[DKIMSignature] = field(default_factory=list)
    result: str = "none"            # pass | fail | neutral | none | policy
    verified_domains: List[str] = field(default_factory=list)
    explanation: str = ""
    cryptographic: bool = False     # True when a real signature check ran

    def to_dict(self) -> dict:
        return {
            "result": self.result,
            "cryptographic": self.cryptographic,
            "verified_domains": self.verified_domains,
            "explanation": self.explanation,
            "signatures": [s.to_dict() for s in self.signatures],
        }


# ---------------------------------------------------------------------------
def parse_tag_list(value: str) -> Dict[str, str]:
    """Parse a DKIM/DMARC style 'k=v; k=v' tag list."""
    tags: Dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, val = part.partition("=")
        tags[key.strip().lower()] = val.strip()
    return tags


def _rsa_key_bits(b64: str) -> Optional[int]:
    """Determine RSA modulus size from a base64 SubjectPublicKeyInfo blob."""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", b64) + "===")
    except Exception:
        return None
    if _HAVE_CRYPTO:
        try:
            key = load_der_public_key(der)
            return getattr(key, "key_size", None)
        except Exception:
            pass
    # Fallback: approximate from DER length (SPKI overhead ~ 24-38 bytes).
    approx = (len(der) - 38) * 8
    for standard in (512, 768, 1024, 1280, 1536, 2048, 3072, 4096):
        if abs(approx - standard) <= 160:
            return standard
    return None


def lookup_dkim_key(resolver: Resolver, selector: str, domain: str) -> Dict[str, object]:
    """Fetch and parse `<selector>._domainkey.<domain>`."""
    name = f"{selector}._domainkey.{domain}"
    records = resolver.txt(name)
    dkim_records = [r for r in records if "p=" in r or r.strip().lower().startswith("v=dkim1")]
    if not dkim_records:
        return {"found": False, "record": "", "name": name}

    record = dkim_records[0]
    tags = parse_tag_list(record)
    p = tags.get("p", "")
    flags = {f.strip().lower() for f in tags.get("t", "").split(":") if f.strip()}
    return {
        "found": True,
        "name": name,
        "record": record,
        "key_type": (tags.get("k") or "rsa").lower(),
        "p": p,
        "revoked": p == "",
        "testing": "y" in flags,
        "strict_subdomain": "s" in flags,
        "bits": _rsa_key_bits(p) if p and (tags.get("k", "rsa").lower() == "rsa") else None,
        "hash_algos": tags.get("h", ""),
        "service": tags.get("s", "*"),
    }


# ---------------------------------------------------------------------------
def analyse_signature(
    resolver: Resolver,
    raw: str,
    index: int,
    from_domain: str,
    check_dns: bool = True,
) -> DKIMSignature:
    sig = DKIMSignature(index=index, raw=raw)
    sig.tags = parse_tag_list(re.sub(r"\s+", "", raw))

    tags = sig.tags
    sig.domain = normalise_domain(tags.get("d", ""))
    sig.selector = tags.get("s", "")
    sig.algorithm = (tags.get("a", "") or "").lower()
    sig.canonicalization = (tags.get("c", "simple/simple") or "").lower()
    sig.identity = tags.get("i", "")
    sig.signed_headers = [h.strip().lower() for h in (tags.get("h", "") or "").split(":") if h.strip()]

    for key, attr in (("l", "body_length_limit"), ("t", "timestamp"), ("x", "expiry")):
        if tags.get(key, "").isdigit():
            setattr(sig, attr, int(tags[key]))

    # ---------------- structural validation ----------------
    if tags.get("v", "1") != "1":
        sig.issues.append(f"Unsupported DKIM version v={tags.get('v')}")
    if not sig.domain:
        sig.issues.append("Missing required d= (signing domain) tag")
    if not sig.selector:
        sig.issues.append("Missing required s= (selector) tag")
    if not tags.get("b"):
        sig.issues.append("Missing required b= (signature) tag")
    if not tags.get("bh"):
        sig.issues.append("Missing required bh= (body hash) tag")

    if sig.algorithm in WEAK_ALGORITHMS:
        sig.issues.append(
            f"Signature uses {sig.algorithm}; RFC 8301 prohibits SHA-1 because it is "
            f"collision-prone and forgeable"
        )
    elif sig.algorithm and sig.algorithm not in ("rsa-sha256", "ed25519-sha256"):
        sig.issues.append(f"Unrecognised signing algorithm a={sig.algorithm}")

    missing_required = REQUIRED_SIGNED_HEADERS - set(sig.signed_headers)
    if sig.signed_headers and missing_required:
        sig.issues.append(
            f"h= does not cover {', '.join(sorted(missing_required))}; RFC 6376 §5.4 "
            f"requires From to be signed, otherwise the sender can be swapped freely"
        )
    missing_recommended = RECOMMENDED_SIGNED_HEADERS - set(sig.signed_headers) - missing_required
    if sig.signed_headers and missing_recommended:
        sig.issues.append(
            f"h= omits {', '.join(sorted(missing_recommended))}; those headers can be "
            f"altered or added without breaking the signature"
        )

    if sig.body_length_limit is not None:
        sig.issues.append(
            f"l={sig.body_length_limit} caps the signed body length - an attacker can append "
            f"arbitrary content below that offset and the signature still validates"
        )

    now = int(time.time())
    if sig.expiry is not None and sig.expiry < now:
        sig.issues.append("Signature has expired (x= is in the past)")
    if sig.timestamp is not None and sig.timestamp > now + 3600:
        sig.issues.append("Signature timestamp t= is in the future")

    if sig.identity:
        ident_domain = normalise_domain(sig.identity.split("@")[-1])
        if ident_domain and sig.domain and not is_subdomain_of(ident_domain, sig.domain):
            sig.issues.append(
                f"Agent identity i={sig.identity} is outside the signing domain d={sig.domain}"
            )

    # ---------------- public key ----------------
    if check_dns and sig.domain and sig.selector:
        key = lookup_dkim_key(resolver, sig.selector, sig.domain)
        sig.key_found = bool(key.get("found"))
        if sig.key_found:
            sig.key_record = str(key.get("record", ""))
            sig.key_type = str(key.get("key_type", ""))
            sig.key_bits = key.get("bits")  # type: ignore[assignment]
            sig.key_revoked = bool(key.get("revoked"))
            sig.key_testing = bool(key.get("testing"))
            sig.key_strict_subdomain = bool(key.get("strict_subdomain"))

            if sig.key_revoked:
                sig.issues.append(
                    f"Public key at {key['name']} has an empty p= tag - the key is REVOKED, "
                    f"so no signature from it can be valid"
                )
            if sig.key_testing:
                sig.issues.append(
                    "Key publishes t=y (testing mode); receivers are told to ignore "
                    "DKIM failures for this domain"
                )
            if sig.key_bits and sig.key_bits < 1024:
                sig.issues.append(
                    f"RSA key is only {sig.key_bits} bits; RFC 8301 sets a 1024-bit floor "
                    f"and recommends 2048"
                )
            elif sig.key_bits and sig.key_bits < 2048:
                sig.issues.append(
                    f"RSA key is {sig.key_bits} bits; 2048 bits is the current recommendation"
                )
        else:
            sig.issues.append(
                f"No DKIM public key published at {sig.selector}._domainkey.{sig.domain} - "
                f"the selector does not exist, which is typical of a fabricated signature"
            )

    if from_domain and sig.domain and not is_subdomain_of(from_domain, sig.domain) \
            and normalise_domain(sig.domain) != normalise_domain(from_domain):
        sig.issues.append(
            f"Signing domain d={sig.domain} differs from the From domain {from_domain} "
            f"(third-party signature - relevant to DMARC alignment)"
        )
    return sig


# ---------------------------------------------------------------------------
def analyse_dkim(
    resolver: Resolver,
    raw_message: str,
    signatures_raw: List[str],
    from_domain: str,
    has_body: bool = False,
    check_dns: bool = True,
) -> DKIMReport:
    report = DKIMReport()

    if not signatures_raw:
        report.result = "none"
        report.explanation = (
            "The message carries no DKIM-Signature header, so nothing about it is "
            "cryptographically authenticated. Legitimate bulk mail from any major "
            "provider is almost always DKIM-signed."
        )
        return report

    for i, raw in enumerate(signatures_raw, 1):
        report.signatures.append(
            analyse_signature(resolver, raw, i, from_domain, check_dns=check_dns)
        )

    # ---------------- cryptographic verification ----------------
    if has_body and _HAVE_DKIMPY:
        report.cryptographic = True
        payload = raw_message.encode("utf-8", "replace")
        for sig in report.signatures:
            try:
                ok = dkimpy.verify(payload, idx=sig.index - 1)
                sig.verified = bool(ok)
                sig.verify_detail = (
                    "Signature verified: body hash and header hash both match the published key."
                    if ok else
                    "Signature verification FAILED: the content or headers were altered after "
                    "signing, or the key does not match."
                )
            except Exception as exc:
                sig.verified = False
                sig.verify_detail = f"Verification error: {type(exc).__name__}: {exc}"
            if not sig.verified:
                sig.issues.append("Cryptographic verification failed")

        passed = [s for s in report.signatures if s.verified]
        report.verified_domains = [s.domain for s in passed]
        if passed:
            report.result = "pass"
            report.explanation = (
                f"{len(passed)} of {len(report.signatures)} DKIM signature(s) verified "
                f"cryptographically (signing domain: {', '.join(report.verified_domains)})."
            )
        else:
            report.result = "fail"
            report.explanation = (
                "Every DKIM signature failed cryptographic verification - the message was "
                "modified in transit or the signature was forged."
            )
        return report

    # ---------------- structural verdict (headers-only input) ----------------
    fatal = [s for s in report.signatures if not s.key_found or s.key_revoked]
    broken = [s for s in report.signatures if any("Missing required" in i for i in s.issues)]

    if broken:
        report.result = "fail"
        report.explanation = (
            "A DKIM-Signature header is structurally invalid (required tags missing), "
            "so it cannot verify under any circumstances."
        )
    elif fatal and check_dns:
        report.result = "fail"
        report.explanation = (
            "The selector referenced by the signature has no usable public key in DNS, "
            "so the signature cannot be validated by any receiver."
        )
    else:
        report.result = "neutral"
        report.verified_domains = [s.domain for s in report.signatures if s.domain]
        report.explanation = (
            "Signature structure and published key look sane, but cryptographic "
            "verification needs the full message body (headers alone do not contain the "
            "content that bh= hashes). Paste the complete raw email for a hard pass/fail."
        )
    return report
