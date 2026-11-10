#!/usr/bin/env python3
"""
Generate samples/dns_fixtures.json.

The fixture file lets the analyzer run with reproducible DNS answers when the
machine has no internet access (lab demo, offline viva, CI). Real RSA keypairs
are generated so that DKIM key-size reporting is genuine rather than faked.

Run:  python tools/generate_fixtures.py
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "samples", "dns_fixtures.json")


def make_key(bits: int = 2048) -> str:
    """Return the base64 SubjectPublicKeyInfo of a fresh RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def main() -> None:
    k2048_google = make_key(2048)
    k2048_brightlearn = make_key(2048)
    k1024_attacker = make_key(1024)       # attacker cuts corners -> weak key finding
    k2048_examplebank = make_key(2048)

    txt = {
        # ---------------- Google (legitimate sample) ----------------
        "google.com": ["v=spf1 include:_spf.google.com ~all"],
        "_spf.google.com": [
            "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com "
            "include:_netblocks3.google.com ~all"
        ],
        "_netblocks.google.com": [
            "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 "
            "ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 "
            "ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ~all"
        ],
        "_netblocks2.google.com": ["v=spf1 ip6:2a00:1450:4000::/36 ip6:2607:f8b0:4000::/36 ~all"],
        "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ip4:142.250.0.0/15 ~all"],
        "gaia.bounces.google.com": ["v=spf1 include:_spf.google.com ~all"],
        "_dmarc.google.com": [
            "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
        ],
        "20230601._domainkey.accounts.google.com": [
            f"v=DKIM1; k=rsa; p={k2048_google}"
        ],

        # ---------------- PayPal (impersonated, p=reject) ----------------
        "paypal.com": ["v=spf1 ip4:66.211.168.0/22 ip4:173.0.84.0/24 ip4:64.4.240.0/21 -all"],
        "_dmarc.paypal.com": [
            "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:dk@bounce.paypal.com; fo=1"
        ],

        # ---------------- Attacker domain that authenticates correctly ----------------
        "icici-netbanking-secure.com": ["v=spf1 ip4:45.133.1.0/24 -all"],
        "_dmarc.icici-netbanking-secure.com": [
            "v=DMARC1; p=quarantine; rua=mailto:reports@icici-netbanking-secure.com"
        ],
        "s1._domainkey.icici-netbanking-secure.com": [
            f"v=DKIM1; k=rsa; p={k1024_attacker}"
        ],

        # ---------------- BEC target domain (p=none) ----------------
        "northwind-industries.com": ["v=spf1 include:_spf.google.com ~all"],
        "_dmarc.northwind-industries.com": [
            "v=DMARC1; p=none; rua=mailto:dmarc@northwind-industries.com"
        ],

        # ---------------- ESP / alignment demo ----------------
        "brightlearn.io": ["v=spf1 include:sendgrid.net -all"],
        "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ip4:168.245.0.0/17 -all"],
        "_dmarc.brightlearn.io": [
            "v=DMARC1; p=quarantine; adkim=r; aspf=r; pct=100; "
            "rua=mailto:dmarc@brightlearn.io"
        ],
        "s1._domainkey.brightlearn.io": [f"v=DKIM1; k=rsa; p={k2048_brightlearn}"],

        # ---------------- Campus domain: SPF -all but no DMARC ----------------
        "sfo-campus.in": ["v=spf1 mx ip4:103.21.58.0/24 -all"],

        # ---------------- Clean reference domain ----------------
        "examplebank.in": ["v=spf1 ip4:103.21.244.0/24 -all"],
        "_dmarc.examplebank.in": [
            "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@examplebank.in"
        ],
        "mail2024._domainkey.examplebank.in": [f"v=DKIM1; k=rsa; p={k2048_examplebank}"],
    }

    a = {
        "mx.zoho.in": ["136.143.188.10"],
        "aspmx.l.google.com": ["142.250.27.26"],
        "icici-netbanking-secure.com": ["45.133.1.88"],
    }

    mx = {
        "sfo-campus.in": ["mx.zoho.in"],
        "northwind-industries.com": ["aspmx.l.google.com"],
    }

    ptr = {
        "37.218.234.185.in-addr.arpa": ["mail.vps-cheap-host.ru"],
        "45.12.89.103.in-addr.arpa": ["dynamic-103-89-12-45.broadband.example.net"],
    }

    fixtures = {"TXT": txt, "A": a, "MX": mx, "AAAA": {}, "PTR": ptr}

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(fixtures, fh, indent=2, sort_keys=True)
    print(f"wrote {OUT}")
    print(f"  TXT={len(txt)}  A={len(a)}  MX={len(mx)}  PTR={len(ptr)}")


if __name__ == "__main__":
    main()
