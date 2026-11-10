"""
DNS resolution layer.

Supports three modes so the project is demonstrable even without internet:

  live     - always query real DNS servers (dnspython)
  offline  - never touch the network; answer only from a JSON fixture file
  auto     - try live DNS first, fall back to fixtures on failure (default)

Every lookup is cached for the lifetime of the resolver so that SPF's
10-lookup limit is measured fairly and repeated queries are cheap.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # pragma: no cover - import guard
    import dns.resolver
    import dns.exception

    _HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAVE_DNSPYTHON = False


DEFAULT_FIXTURES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "dns_fixtures.json",
)


class DNSLookupLimit(Exception):
    """Raised when the RFC 7208 DNS lookup budget is exhausted."""


@dataclass
class DNSResult:
    """Outcome of a single DNS query."""

    name: str
    rtype: str
    records: List[str] = field(default_factory=list)
    source: str = "live"          # live | fixture | cache
    error: Optional[str] = None   # NXDOMAIN, NoAnswer, Timeout, ...

    @property
    def found(self) -> bool:
        return bool(self.records)


class Resolver:
    """DNS front-end with caching, fixtures and a lookup budget."""

    #: Hard ceiling on DNS-consuming mechanisms, per RFC 7208 section 4.6.4
    SPF_LOOKUP_LIMIT = 10
    #: Ceiling on "void" (empty / NXDOMAIN) lookups, RFC 7208 section 4.6.4
    SPF_VOID_LIMIT = 2

    def __init__(
        self,
        mode: str = "auto",
        fixtures_path: Optional[str] = None,
        timeout: float = 5.0,
        nameservers: Optional[List[str]] = None,
    ) -> None:
        if mode not in ("auto", "live", "offline"):
            raise ValueError("mode must be auto, live or offline")
        self.mode = mode
        self.timeout = timeout
        self.cache: Dict[str, DNSResult] = {}
        self.query_log: List[Dict[str, str]] = []
        self.lookup_count = 0
        self.void_count = 0

        self.fixtures: Dict[str, Dict[str, List[str]]] = {}
        path = fixtures_path or DEFAULT_FIXTURES
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.fixtures = json.load(fh)
            except (OSError, ValueError):
                self.fixtures = {}

        self._resolver = None
        if _HAVE_DNSPYTHON and mode != "offline":
            try:
                self._resolver = dns.resolver.Resolver()
                self._resolver.lifetime = timeout
                self._resolver.timeout = timeout
                if nameservers:
                    self._resolver.nameservers = nameservers
            except Exception:
                self._resolver = None

    # ------------------------------------------------------------------ #
    # budget helpers
    # ------------------------------------------------------------------ #
    def reset_budget(self) -> None:
        """Reset the SPF lookup counters (call once per SPF evaluation)."""
        self.lookup_count = 0
        self.void_count = 0

    def spend(self, n: int = 1) -> None:
        """Consume part of the SPF DNS-lookup budget."""
        self.lookup_count += n
        if self.lookup_count > self.SPF_LOOKUP_LIMIT:
            raise DNSLookupLimit(
                f"exceeded {self.SPF_LOOKUP_LIMIT} DNS lookups "
                f"(RFC 7208 §4.6.4) - possible SPF record abuse or misconfiguration"
            )

    def note_void(self) -> None:
        self.void_count += 1
        if self.void_count > self.SPF_VOID_LIMIT:
            raise DNSLookupLimit(
                f"exceeded {self.SPF_VOID_LIMIT} void DNS lookups (RFC 7208 §4.6.4)"
            )

    # ------------------------------------------------------------------ #
    # core query
    # ------------------------------------------------------------------ #
    def query(self, name: str, rtype: str) -> DNSResult:
        name = name.strip().rstrip(".").lower()
        rtype = rtype.upper()
        key = f"{rtype}:{name}"

        if key in self.cache:
            cached = self.cache[key]
            return DNSResult(name, rtype, list(cached.records), "cache", cached.error)

        result: Optional[DNSResult] = None

        if self.mode in ("auto", "live") and self._resolver is not None:
            result = self._query_live(name, rtype)

        if (result is None or (not result.found and self.mode == "auto")) and self.mode != "live":
            fixture = self._query_fixture(name, rtype)
            if fixture.found:
                result = fixture
        if result is None:
            result = self._query_fixture(name, rtype)

        self.cache[key] = result
        self.query_log.append(
            {
                "name": name,
                "type": rtype,
                "source": result.source,
                "records": "; ".join(result.records)[:300],
                "error": result.error or "",
            }
        )
        return result

    def _query_live(self, name: str, rtype: str) -> Optional[DNSResult]:
        try:
            answers = self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DNSResult(name, rtype, [], "live", "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return DNSResult(name, rtype, [], "live", "NoAnswer")
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            # Network unavailable -> let caller fall back to fixtures
            return DNSResult(name, rtype, [], "live", type(exc).__name__)
        except Exception as exc:  # pragma: no cover - defensive
            return DNSResult(name, rtype, [], "live", type(exc).__name__)

        records: List[str] = []
        for rdata in answers:
            if rtype == "TXT":
                # TXT strings may be split into <=255 byte chunks; rejoin them.
                parts = [
                    p.decode("utf-8", "replace") if isinstance(p, bytes) else str(p)
                    for p in rdata.strings
                ]
                records.append("".join(parts))
            elif rtype == "MX":
                records.append(str(rdata.exchange).rstrip("."))
            else:
                records.append(str(rdata).rstrip("."))
        return DNSResult(name, rtype, records, "live", None if records else "NoAnswer")

    def _query_fixture(self, name: str, rtype: str) -> DNSResult:
        table = self.fixtures.get(rtype, {})
        recs = table.get(name)
        if recs is None:
            return DNSResult(name, rtype, [], "fixture", "NXDOMAIN")
        return DNSResult(name, rtype, list(recs), "fixture", None)

    # ------------------------------------------------------------------ #
    # typed convenience wrappers
    # ------------------------------------------------------------------ #
    def txt(self, name: str) -> List[str]:
        return self.query(name, "TXT").records

    def a(self, name: str) -> List[str]:
        return self.query(name, "A").records

    def aaaa(self, name: str) -> List[str]:
        return self.query(name, "AAAA").records

    def mx(self, name: str) -> List[str]:
        return self.query(name, "MX").records

    def ptr(self, ip: str) -> List[str]:
        try:
            import ipaddress

            rev = ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return []
        return self.query(rev, "PTR").records

    # ------------------------------------------------------------------ #
    def describe(self) -> Dict[str, object]:
        live = sum(1 for q in self.query_log if q["source"] == "live")
        fixture = sum(1 for q in self.query_log if q["source"] == "fixture")
        return {
            "mode": self.mode,
            "queries": len(self.query_log),
            "live_answers": live,
            "fixture_answers": fixture,
            "log": self.query_log,
        }
