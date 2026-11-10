#!/usr/bin/env python3
"""
Flask web front-end for the Email Header Analyzer.

    python app.py                 # http://127.0.0.1:5000
    python app.py --port 8080 --dns-mode offline

Routes
------
GET  /                  analysis form
POST /                  analyse pasted headers and render the report
GET  /sample/<name>     load a bundled sample into the form
POST /api/analyze       JSON API  {"headers": "..."} -> full report object
GET  /api/samples       list bundled samples
"""

from __future__ import annotations

import argparse
import glob
import json
import os

from flask import Flask, Response, jsonify, render_template, request

from analyzer.engine import Analyzer
from analyzer.report import render_text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
MAX_INPUT_BYTES = 1_000_000          # 1 MB guard on pasted input

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024

# Configured in main(); defaults keep the module importable for tests.
app.config["DNS_MODE"] = "auto"
app.config["CHECK_DNS"] = True
app.config["DNS_TIMEOUT"] = 5.0


def get_analyzer() -> Analyzer:
    return Analyzer(
        dns_mode=app.config["DNS_MODE"],
        check_dns=app.config["CHECK_DNS"],
        timeout=app.config["DNS_TIMEOUT"],
    )


def list_samples():
    out = []
    for path in sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.eml"))):
        name = os.path.basename(path)
        label = (
            name.split("_", 1)[1].rsplit(".", 1)[0].replace("_", " ").title()
            if "_" in name else name
        )
        out.append({"file": name, "label": label})
    return out


def load_sample(name: str) -> str:
    safe = os.path.basename(name)
    path = os.path.join(SAMPLES_DIR, safe)
    if not path.startswith(SAMPLES_DIR) or not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    headers_text = ""
    report = None
    error = None

    if request.method == "POST":
        headers_text = request.form.get("headers", "")
        if len(headers_text.encode("utf-8")) > MAX_INPUT_BYTES:
            error = "Input too large - paste headers only (under 1 MB)."
        elif not headers_text.strip():
            error = "Paste the raw email headers first."
        elif ":" not in headers_text:
            error = ("That does not look like email headers. Use 'Show original' "
                     "(Gmail) or 'View message source' (Outlook) and paste the result.")
        else:
            try:
                report = get_analyzer().analyze(headers_text)
            except Exception as exc:  # pragma: no cover - surfaced to the user
                error = f"Analysis failed: {type(exc).__name__}: {exc}"

    return render_template(
        "index.html",
        headers_text=headers_text,
        report=report,
        error=error,
        samples=list_samples(),
        dns_mode=app.config["DNS_MODE"],
    )


@app.route("/sample/<name>")
def sample(name: str):
    text = load_sample(name)
    if not text:
        return render_template("index.html", headers_text="", report=None,
                               error=f"Sample '{name}' not found.",
                               samples=list_samples(),
                               dns_mode=app.config["DNS_MODE"]), 404
    return render_template("index.html", headers_text=text, report=None, error=None,
                           samples=list_samples(), dns_mode=app.config["DNS_MODE"])


@app.route("/api/samples")
def api_samples():
    return jsonify(list_samples())


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    raw = payload.get("headers") or request.form.get("headers") or ""
    if not raw.strip():
        return jsonify({"error": "no headers supplied"}), 400
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        return jsonify({"error": "input too large"}), 413
    try:
        return jsonify(get_analyzer().analyze(raw))
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.route("/api/analyze.txt", methods=["POST"])
def api_analyze_text():
    raw = (request.get_json(silent=True) or {}).get("headers") or request.form.get("headers", "")
    if not raw.strip():
        return Response("no headers supplied", status=400, mimetype="text/plain")
    report = get_analyzer().analyze(raw)
    return Response(render_text(report, colour=False, verbose=True), mimetype="text/plain")


@app.template_filter("severity_class")
def severity_class(value: str) -> str:
    return {
        "critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
        "low": "sev-low", "info": "sev-info", "good": "sev-good",
    }.get(value, "sev-info")


@app.template_filter("band_class")
def band_class(label: str) -> str:
    return {
        "Authentic": "band-ok",
        "Low Risk": "band-low",
        "Suspicious": "band-warn",
        "Likely Spoofed": "band-bad",
        "Highly Likely Spoofed / Phishing": "band-critical",
    }.get(label, "band-low")


@app.template_filter("result_class")
def result_class(value: str) -> str:
    v = (value or "").lower()
    if v.startswith("pass"):
        return "res-pass"
    if v in ("fail", "permerror"):
        return "res-fail"
    if v in ("softfail", "neutral", "temperror"):
        return "res-warn"
    return "res-none"


@app.template_filter("tojson_pretty")
def tojson_pretty(value) -> str:
    return json.dumps(value, indent=2, default=str)


# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Email Header Analyzer - web interface")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--dns-mode", choices=["auto", "live", "offline"], default="auto")
    p.add_argument("--no-dns", action="store_true", help="heuristics only, no DNS")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()

    app.config["DNS_MODE"] = args.dns_mode
    app.config["CHECK_DNS"] = not args.no_dns
    app.config["DNS_TIMEOUT"] = args.timeout

    print(f"  Email Header Analyzer  ->  http://{args.host}:{args.port}")
    print(f"  DNS mode: {args.dns_mode}{'  (lookups disabled)' if args.no_dns else ''}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
