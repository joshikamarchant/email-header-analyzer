# Email Header Analyzer for Spoofing Detection

A forensic tool that parses raw email headers and decides whether the sender is
genuine, using the three internet email-authentication standards — **SPF**
(RFC 7208), **DKIM** (RFC 6376) and **DMARC** (RFC 7489) — combined with a
layer of header-forensics heuristics that catch attacks which pass
authentication.

Everything is free and open source. No API keys, no paid services, no accounts.

```
RISK  VERDICT                            SPF        DKIM     DMARC       FILE
  0   Authentic                          pass       neutral  pass        01_legit_google_alert.eml
100   Highly Likely Spoofed / Phishing   fail       none     fail        02_spoofed_paypal_dmarc_reject.eml
 65   Likely Spoofed                     pass       neutral  pass        03_lookalike_domain_authenticated.eml
100   Highly Likely Spoofed / Phishing   softfail   none     fail        04_bec_ceo_fraud.eml
100   Highly Likely Spoofed / Phishing   none       none     none        05_forged_received_chain.eml
  0   Authentic                          pass       neutral  pass        06_legit_newsletter_esp.eml
 59   Likely Spoofed                     fail       none     none        07_internal_spoof_no_dmarc.eml
  0   Authentic                          pass       neutral  pass        08_legit_strict_alignment.eml
```

---

## Quick start

```bash
# 1. install dependencies
pip install -r requirements.txt

# 2. run the web interface
python app.py
#    -> open http://127.0.0.1:5000

# 3. or use the command line
python -m analyzer.cli samples/02_spoofed_paypal_dmarc_reject.eml

# 4. run the whole bundled corpus
python -m analyzer.cli --batch samples/ --summary

# 5. run the tests (87 tests, no internet needed)
pytest -v
```

No internet connection? Everything still works:

```bash
python app.py --dns-mode offline
python -m analyzer.cli --batch samples/ --summary --dns-mode offline
```

---

## What problem this solves

SMTP, designed in 1982, has no built-in way to prove who sent a message. The
`From:` address a mail client displays is just text the sender typed — it is
trivially forgeable. Phishing and business-email-compromise attacks live in
exactly that gap.

Three DNS-published standards were layered on top of SMTP to close it:

| Standard | What it authenticates | Weakness on its own |
|---|---|---|
| **SPF** | The IP address that connected, against the **envelope** sender (`Return-Path`) | The recipient never sees the envelope sender — SPF can pass while the visible `From:` is forged |
| **DKIM** | A cryptographic signature over selected headers and the body, tied to a domain (`d=`) | The signing domain need not be the `From:` domain |
| **DMARC** | Binds SPF or DKIM to the **visible** `From:` domain (*alignment*), and publishes a policy | Only works if the domain owner publishes a record, and `p=none` enforces nothing |

This tool evaluates all three, checks DMARC alignment explicitly, and then adds
what authentication cannot see: *is this message designed to deceive a human?*

---

## How it works

```
                    ┌──────────────────────────────────────────┐
  raw headers ─────►│  parser.py                               │
                    │  • repairs pasted/folded/quoted headers  │
                    │  • reconstructs the Received hop chain   │
                    │  • extracts every sender identity        │
                    └───────────────┬──────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
   ┌─────────────┐          ┌──────────────┐          ┌──────────────┐
   │   spf.py    │          │ dkim_check.py│          │  authres.py  │
   │ RFC 7208    │          │  RFC 6376    │          │  RFC 8601    │
   │ evaluator   │          │  audit+verify│          │ what the     │
   └──────┬──────┘          └──────┬───────┘          │ receiver said│
          │                        │                  └──────┬───────┘
          └────────────┬───────────┘                         │
                       ▼                                     │
                ┌─────────────┐                              │
                │  dmarc.py   │  identifier alignment         │
                │  RFC 7489   │  + policy evaluation          │
                └──────┬──────┘                              │
                       │                                     │
                       ▼                                     ▼
                ┌──────────────────────────────────────────────┐
                │  heuristics.py  — 60 forensic findings       │
                │  display-name spoofing · look-alike domains  │
                │  Reply-To redirection · forged hop chains    │
                │  timestamp contradictions · lure language    │
                └────────────────────┬─────────────────────────┘
                                     ▼
                           ┌──────────────────┐
                           │   scoring.py     │  risk 0–100
                           │                  │  domain grade A–F
                           └────────┬─────────┘  confidence
                                    ▼
                     CLI report · Web report · JSON API
```

### The key insight the scoring encodes

Passing authentication proves only that the message really came from the domain
in the `From:` header. It says **nothing** about whether that domain is the one
the reader thinks they are dealing with.

Sample `03_lookalike_domain_authenticated.eml` demonstrates this: the attacker
registered `icici-netbanking-secure.com`, published a valid SPF record, signed
with DKIM, and set up DMARC. **SPF, DKIM and DMARC all pass.** Any tool that
stops at authentication reports it as clean. This analyzer scores it 65 /
*Likely Spoofed*, because the brand-impersonating display name and the
brand-bearing domain label cancel the authentication credit entirely.

---

## Project layout

```
email-header-analyzer/
├── analyzer/
│   ├── __init__.py          public API: analyze()
│   ├── parser.py            RFC 5322 parsing, Received-chain reconstruction
│   ├── spf.py               RFC 7208 evaluator (all mechanisms, macros, limits)
│   ├── dkim_check.py        RFC 6376 signature audit + crypto verification
│   ├── dmarc.py             RFC 7489 policy discovery + identifier alignment
│   ├── authres.py           RFC 8601 Authentication-Results parsing
│   ├── heuristics.py        forensic spoofing checks
│   ├── scoring.py           risk aggregation, grading, confidence
│   ├── engine.py            orchestration
│   ├── dns_utils.py         caching resolver: live / offline / auto
│   ├── report.py            terminal report rendering
│   └── cli.py               command-line interface
├── templates/index.html     web interface
├── static/style.css
├── samples/                 8 annotated test cases + DNS fixtures
├── tests/test_analyzer.py   87 tests
├── tools/generate_fixtures.py
├── docs/PROJECT_REPORT.md   full write-up for submission
├── app.py                   Flask server
└── requirements.txt
```

---

## Using it

### Web interface

```bash
python app.py                       # http://127.0.0.1:5000
python app.py --port 8080 --debug
python app.py --dns-mode offline    # lab demo without internet
```

Paste headers into the box, or click one of the eight bundled test cases.

**Getting the headers out of your mail client**

| Client | Steps |
|---|---|
| Gmail (web) | open the message → **⋮** → *Show original* → copy everything |
| Outlook (desktop) | open the message → *File* → *Properties* → *Internet headers* |
| Outlook (web) | **⋯** → *View* → *View message details* |
| Thunderbird | select the message → **Ctrl+U** |
| Apple Mail | *View* → *Message* → *All Headers* (⇧⌘H) |
| Yahoo Mail | **⋯** → *View raw message* |

### Command line

```bash
python -m analyzer.cli message.eml              # full report
python -m analyzer.cli - < message.eml          # read stdin
python -m analyzer.cli --json message.eml       # machine-readable
python -m analyzer.cli --verbose message.eml    # include passing checks
python -m analyzer.cli --batch inbox/ --summary # one line per message
python -m analyzer.cli --no-dns message.eml     # heuristics only
```

Exit status is `2` when the risk score reaches `--fail-threshold` (default 45),
so it can be dropped straight into a shell pipeline or CI job.

### JSON API

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H 'Content-Type: application/json' \
     -d '{"headers": "From: a@b.com\nSubject: hi"}' | jq .verdict
```

### As a library

```python
from analyzer import analyze

report = analyze(open("message.eml").read())
print(report["verdict"]["label"], report["verdict"]["score"])

for finding in report["findings"]:
    if finding["severity"] in ("critical", "high"):
        print(finding["title"], "-", finding["detail"])
```

---

## DNS modes

| Mode | Behaviour | Use for |
|---|---|---|
| `auto` *(default)* | query live DNS; fall back to bundled fixtures on failure | normal use |
| `live` | live DNS only | real investigations |
| `offline` | bundled fixtures only — fully reproducible, no network | lab demo, viva, CI |

Fixtures live in `samples/dns_fixtures.json` and are regenerated with
`python tools/generate_fixtures.py` (it mints real RSA keypairs, so the reported
DKIM key sizes are genuine).

---

## Detection coverage

Sixty distinct findings are implemented across five categories.

**Authentication (25 findings)** — SPF pass/fail/softfail/neutral/none/permerror
with full mechanism evaluation and RFC lookup limits; DKIM structural audit
(required tags, SHA-1 use, unsigned `From`, `l=` body-length truncation,
expired signatures, revoked and undersized keys, missing selectors) plus real
cryptographic verification when a full message is supplied; DMARC policy
discovery with organizational-domain fallback, strict/relaxed alignment for both
SPF and DKIM, `pct=` and `sp=` handling, and disposition prediction.

**Identity deception (15 findings)** — display name embedding a different address;
display name impersonating one of 40+ protected brands; look-alike domains by
edit distance and homoglyph normalisation (`paypa1`, `rnicrosoft`, `g00gle`);
brand names embedded in unrelated domains; punycode and mixed-script addresses;
Return-Path / From divergence; Reply-To redirection (weighted higher when it
points at free webmail from a corporate sender); duplicate `From:` headers;
disposable-mailbox senders.

**Transport and timeline forensics (15 findings)** — missing or single-hop Received chains;
timestamps that run backwards; `Date` later than the first relay; private-IP
origins; HELO vs reverse-DNS disagreement; generic HELO names; Message-ID domain
unrelated to sender; abnormally long relay chains.

**Content and tooling (5 findings)** — urgency, credential-harvesting and
BEC-opener language in the subject; PHP-script origin headers; scripted mailer
fingerprints; bulk mail without `List-Unsubscribe`.

---

## Interpreting the output

| Risk | Verdict | Meaning |
|---|---|---|
| 0–9 | Authentic | Authenticates correctly, no deceptive characteristics |
| 10–24 | Low Risk | Hygiene or configuration weaknesses only |
| 25–44 | Suspicious | Verify the sender through an independent channel |
| 45–69 | Likely Spoofed | Treat as hostile |
| 70–100 | Highly Likely Spoofed / Phishing | Do not engage; report it |

**Insufficient-evidence cap.** If every finding reports something *missing*
(no SPF record, no DKIM, no Received chain) rather than something *forged*, the
score is capped at 44 and flagged. A truncated header paste should never be
reported as confirmed spoofing — absence of authentication is a weakness, not
proof of forgery.

The **domain grade (A–F)** is a separate axis: it rates how well the sending
domain is configured, regardless of this particular message. **Confidence**
reports how much evidence was actually available — it drops when DNS was
unreachable, the body was not supplied, or no Received chain was present.

---

## Known limitations

* **DKIM cryptographic verification requires the full raw message.** Headers
  alone cannot be verified because `bh=` hashes the body. With headers only the
  tool performs a structural audit and reports `neutral` rather than claiming a
  pass it cannot prove.
* **SPF is evaluated against current DNS**, not DNS as it was at delivery time.
  A record changed since then will produce a different answer; the tool flags
  disagreements with the recorded `Authentication-Results`.
* **`Authentication-Results` headers can be forged** by any host upstream of the
  trusted boundary MTA. They are reported as evidence, never trusted blindly.
* **The public-suffix handling is a curated list**, not the full Public Suffix
  List, so organizational-domain extraction can be wrong for unusual TLDs.
* **The brand list is finite** (40+ entries). Impersonation of a brand not on
  the list is caught only by the generic checks.
* **Heuristics are probabilistic.** A legitimate message sent through an unusual
  path can score as suspicious; the per-finding detail is there so a human can
  judge, and the tool is an aid to that judgement, not a replacement for it.

---

## Testing

```bash
pytest -v                      # 87 tests
pytest -v -k TestSPF           # one group
pytest --tb=short -q
```

The suite runs entirely against offline fixtures and covers utilities, parsing,
SPF mechanism evaluation, DKIM auditing, DMARC alignment, every heuristic, the
eight end-to-end sample classifications, and all web routes (including a path
traversal attempt against the sample loader).

---

## Ethics and scope

This is a **defensive** tool. It analyses messages you have already received to
determine whether they are forged. It does not send email, does not forge
headers, and contains nothing that helps anyone construct a spoofed message.
Use it on your own mail, or on mail you are authorised to investigate.

---

## References

1. RFC 5322 — *Internet Message Format*
2. RFC 7208 — *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1*
3. RFC 6376 — *DomainKeys Identified Mail (DKIM) Signatures*
4. RFC 8301 — *Cryptographic Algorithm and Key Usage Update to DKIM*
5. RFC 7489 — *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*
6. RFC 8601 — *Message Header Field for Indicating Message Authentication Status*
7. RFC 7960 — *Interoperability Issues between DMARC and Indirect Email Flows*
