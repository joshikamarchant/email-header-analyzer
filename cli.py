"""
Command-line interface.

    python -m analyzer.cli samples/spoofed_paypal.eml
    python -m analyzer.cli --json message.eml > report.json
    cat message.eml | python -m analyzer.cli -
    python -m analyzer.cli --batch samples/            # analyse a whole folder
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from .engine import Analyzer
from .report import render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="email-header-analyzer",
        description="Analyse raw email headers for sender spoofing using SPF, DKIM, "
                    "DMARC and forensic heuristics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s message.eml
  %(prog)s - < message.eml
  %(prog)s --json message.eml
  %(prog)s --batch samples/ --summary
  %(prog)s --dns-mode offline samples/spoofed_paypal.eml
""",
    )
    p.add_argument("path", nargs="?", default="-",
                   help="file containing the raw headers, or '-' for stdin")
    p.add_argument("--batch", metavar="DIR",
                   help="analyse every .eml/.txt file in a directory")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--summary", action="store_true",
                   help="one line per message (useful with --batch)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="include passing checks in the report")
    p.add_argument("--dns-mode", choices=["auto", "live", "offline"], default="auto",
                   help="auto (default): live DNS, falling back to bundled fixtures")
    p.add_argument("--no-dns", action="store_true",
                   help="skip all DNS lookups; run heuristics only")
    p.add_argument("--fixtures", metavar="FILE", help="path to a DNS fixture JSON file")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds")
    p.add_argument("--no-colour", action="store_true", help="disable ANSI colour")
    p.add_argument("--fail-threshold", type=int, default=45, metavar="N",
                   help="exit with status 2 when the risk score is >= N (default 45)")
    return p


def read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def summary_line(path: str, report: dict) -> str:
    v = report["verdict"]
    auth = report["authentication"]
    return (
        f"{v['score']:>3}  {v['label']:<34} "
        f"SPF={auth['spf']['result']:<9} "
        f"DKIM={auth['dkim']['result']:<8} "
        f"DMARC={auth['dmarc']['result']:<18} "
        f"{os.path.basename(path)}"
    )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    analyzer = Analyzer(
        dns_mode=args.dns_mode,
        fixtures_path=args.fixtures,
        check_dns=not args.no_dns,
        timeout=args.timeout,
    )

    targets = []
    if args.batch:
        for pattern in ("*.eml", "*.txt", "*.msg"):
            targets.extend(sorted(glob.glob(os.path.join(args.batch, pattern))))
        if not targets:
            print(f"No .eml/.txt files found in {args.batch}", file=sys.stderr)
            return 1
    else:
        targets = [args.path]

    worst = 0
    reports = []

    if args.batch and args.summary:
        print(f"{'RISK':>4}  {'VERDICT':<34} {'SPF':<13} {'DKIM':<13} {'DMARC':<24} FILE")
        print("-" * 120)

    for path in targets:
        try:
            raw = read_input(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 1
        if not raw.strip():
            print(f"error: {path} is empty", file=sys.stderr)
            return 1

        report = analyzer.analyze(raw)
        report["meta"]["source"] = path
        reports.append(report)
        worst = max(worst, int(report["verdict"]["score"]))

        if args.json:
            continue
        if args.summary:
            print(summary_line(path, report))
        else:
            if len(targets) > 1:
                print(f"\n\n### {path}\n")
            print(render_text(report,
                              colour=False if args.no_colour else None,
                              verbose=args.verbose))

    if args.json:
        payload = reports[0] if len(reports) == 1 else reports
        print(json.dumps(payload, indent=2, default=str))

    return 2 if worst >= args.fail_threshold else 0


if __name__ == "__main__":
    sys.exit(main())
