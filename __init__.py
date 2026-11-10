"""
Email Header Analyzer for Spoofing Detection
============================================

A self-contained toolkit that parses raw RFC 5322 email headers and evaluates
sender authenticity using SPF (RFC 7208), DKIM (RFC 6376) and DMARC (RFC 7489),
combined with a set of forensic spoofing heuristics.

Public entry point:

    >>> from analyzer import analyze
    >>> report = analyze(raw_headers)
    >>> report["verdict"]["label"]
    'Likely Spoofed'
"""

from .engine import analyze, Analyzer  # noqa: F401

__version__ = "1.0.0"
__all__ = ["analyze", "Analyzer", "__version__"]
