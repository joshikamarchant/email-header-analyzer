# Email Header Analyzer for Spoofing Detection
### Authentication analysis using SPF, DKIM and DMARC with forensic header heuristics

---

## Abstract

Simple Mail Transfer Protocol has no native mechanism for proving the identity
of a sender. The `From:` address displayed by every mail client is unverified
text supplied by whoever sent the message, which makes email impersonation
cheap and effective — it remains the initial access vector in the majority of
reported phishing and business-email-compromise incidents.

Three standards layered on top of SMTP address this: SPF authorises sending IP
addresses, DKIM cryptographically signs messages, and DMARC binds the results of
the first two to the address the reader actually sees. This project implements
all three as a working analysis tool, and then goes one step further: it adds a
layer of forensic heuristics that examine the message the way an investigator
would, catching attacks that satisfy every authentication check.

The resulting system accepts raw email headers through a web interface, a
command-line tool or a JSON API, and returns a risk score from 0 to 100, a
verdict band, a per-check explanation of the reasoning, and recommended actions
for both the recipient and the domain owner. It was validated against a corpus
of eight annotated messages representing distinct spoofing techniques and
classified all eight correctly, with 87 automated tests covering the
implementation. The tool uses only free and open-source components and runs
fully offline when required.

---

## 1. Introduction

### 1.1 The trust problem in email

When SMTP was specified in 1982, the internet was a small network of mutually
trusting research institutions. The protocol therefore distinguishes two sender
identities and verifies neither:

* the **envelope sender**, given in the SMTP `MAIL FROM` command and recorded in
  the `Return-Path:` header — used for bounces, and never shown to the reader;
* the **header sender**, the `From:` field inside the message — what every mail
  client displays.

Nothing requires these to match, and nothing requires either to be true. An
attacker with a mail client and a rented server can set both to
`service@paypal.com` in under a minute.

### 1.2 Why this matters

Impersonation underpins the highest-impact categories of email attack:

* **Credential phishing** — a message that appears to come from a bank or a
  service provider drives the victim to a cloned login page.
* **Business email compromise** — a message appearing to come from a senior
  executive instructs the finance team to make an urgent payment. The display
  name carries the authority; a `Reply-To:` header silently diverts the
  conversation to the attacker.
* **Internal spoofing** — a message from "HR" to all staff, sent from outside
  the organisation entirely.

### 1.3 Motivation for this project

Most freely available header analysers are formatters: they pretty-print the
`Received:` chain and echo whatever the `Authentication-Results:` header says.
That is useful but insufficient, for two reasons.

First, `Authentication-Results:` is just another header. Any host upstream of
the receiving boundary MTA can write one, so a tool that merely repeats it can
be lied to directly.

Second — and more importantly — authentication passing does not mean the message
is safe. An attacker who registers their own domain can publish a perfectly
valid SPF record, sign with DKIM and configure DMARC. Every check passes,
because the attacker genuinely owns the domain they are authenticating. What
makes the message an attack is that the domain *looks like* somebody else's.
Authentication cannot see that; a human can, and so can a heuristic.

This project therefore independently re-derives all three authentication results
from DNS, and combines them with a deception-detection layer.

---

## 2. Objectives

1. Parse raw RFC 5322 headers robustly, including the malformed state they
   arrive in after being copied out of a webmail interface.
2. Reconstruct the `Received:` relay chain and identify the true originating IP.
3. Implement SPF evaluation per RFC 7208, including mechanism resolution, macro
   expansion and the DNS lookup limits.
4. Audit DKIM signatures per RFC 6376 and RFC 8301, and verify them
   cryptographically when the full message is available.
5. Implement DMARC policy discovery and identifier alignment per RFC 7489.
6. Detect spoofing techniques that survive authentication: display-name
   deception, look-alike domains, `Reply-To` redirection, fabricated relay
   chains and timestamp contradictions.
7. Aggregate all evidence into an explainable risk score — every point of risk
   must be attributable to a named, documented check.
8. Deliver it through a web interface, a CLI and an API, at zero cost, with no
   external service dependencies, and with a reproducible offline mode.

---

## 3. Background

### 3.1 SPF — Sender Policy Framework (RFC 7208)

The domain owner publishes a DNS TXT record listing the hosts permitted to send
mail for the domain:

```
examplebank.in.   TXT   "v=spf1 ip4:103.21.244.0/24 include:_spf.google.com -all"
```

The receiver takes the IP that connected and the **envelope** sender domain, and
evaluates the mechanisms left to right. The first match decides the result; its
qualifier determines which (`+` pass, `-` fail, `~` softfail, `?` neutral).
Mechanisms that require DNS (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`)
are capped at ten lookups in total to prevent amplification abuse.

**The gap:** SPF validates the envelope sender. The reader never sees it. A
message can pass SPF for `bounces@attacker.com` while displaying
`service@paypal.com`.

### 3.2 DKIM — DomainKeys Identified Mail (RFC 6376)

The sending server adds a signature over a chosen set of headers and the body:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=examplebank.in;
    s=mail2024; h=from:to:subject:date; bh=<body hash>; b=<signature>
```

The receiver fetches the public key from `<selector>._domainkey.<d>` and
verifies. A valid signature proves the message was authorised by the operator of
`d=` and has not been modified in transit.

**The gaps:** the signing domain need not match the `From:` domain; headers not
listed in `h=` are unprotected (if `From` is absent from `h=`, the sender can be
swapped freely); and an `l=` tag limits how much of the body is covered, letting
an attacker append arbitrary content below the signed offset.

### 3.3 DMARC — Domain-based Message Authentication (RFC 7489)

DMARC is the layer that closes both gaps. The domain owner publishes:

```
_dmarc.examplebank.in.  TXT  "v=DMARC1; p=reject; adkim=s; aspf=s;
                               rua=mailto:dmarc@examplebank.in"
```

A message passes DMARC when **either** condition holds:

```
(SPF  = pass  AND  envelope domain aligns with the From domain)
                 OR
(DKIM = pass  AND  the d= domain aligns with the From domain)
```

**Alignment** is the critical concept. In *relaxed* mode (`r`, the default) two
domains align if they share an organizational domain — `mail.paypal.com` aligns
with `paypal.com`. In *strict* mode (`s`) they must match exactly.

The `p=` tag tells receivers what to do on failure: `none` (monitor only),
`quarantine` (spam folder) or `reject` (refuse at SMTP time).

### 3.4 What none of them cover

All three answer: *is this message authorised by the domain in the From header?*

None answers: *is that domain the one the reader believes they are dealing
with?* A message from `icici-netbanking-secure.com` with a display name of
"ICICI Bank Alerts" passes every check — and is a phishing attack. Closing that
gap is the contribution of the heuristic layer described in section 5.4.

---

## 4. Comparison with existing tools

| Capability | Typical online header analysers | MXToolbox header analyser | **This project** |
|---|---|---|---|
| Pretty-prints `Received:` chain | Yes | Yes | Yes |
| Echoes `Authentication-Results` | Yes | Yes | Yes, *and flags disagreement* |
| Re-derives SPF independently from DNS | Rarely | Partially | Yes, full RFC 7208 evaluator |
| Checks DMARC **alignment** explicitly | Rarely | Partially | Yes, both legs, strict and relaxed |
| Audits DKIM structure (`h=`, `l=`, key size) | No | No | Yes |
| Detects look-alike / typosquat domains | No | No | Yes |
| Detects display-name and `Reply-To` deception | No | No | Yes |
| Detects fabricated `Received:` chains | No | No | Yes |
| Explainable per-check scoring | No | No | Yes |
| Works offline / reproducibly | No | No | Yes |
| Cost | Free, data leaves your machine | Free tier | Free, fully local |

A practical point for anyone analysing a real phishing message: online
analysers require pasting the headers of a potentially sensitive message into a
third-party website. This tool runs locally.

---

## 5. System design

### 5.1 Architecture

```
                    ┌──────────────────────────────────────────┐
  raw headers ─────►│  parser.py                               │
                    │  repair → parse → reconstruct hop chain  │
                    │  → extract every sender identity         │
                    └───────────────┬──────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
   ┌─────────────┐          ┌──────────────┐          ┌──────────────┐
   │   spf.py    │          │ dkim_check.py│          │  authres.py  │
   │  RFC 7208   │          │   RFC 6376   │          │   RFC 8601   │
   └──────┬──────┘          └──────┬───────┘          └──────┬───────┘
          └────────────┬───────────┘                         │
                       ▼                                     │
                ┌─────────────┐                              │
                │  dmarc.py   │ alignment + policy            │
                └──────┬──────┘                              │
                       └──────────────┬──────────────────────┘
                                      ▼
                      ┌───────────────────────────────┐
                      │  heuristics.py (60 findings)  │
                      └───────────────┬───────────────┘
                                      ▼
                            ┌──────────────────┐
                            │   scoring.py     │
                            └────────┬─────────┘
                                     ▼
                     CLI report · Web report · JSON API
```

All DNS traffic passes through `dns_utils.Resolver`, which caches every answer,
enforces the SPF lookup budget, and can serve answers from a bundled fixture
file so the entire system runs deterministically without a network.

### 5.2 Module responsibilities

| Module | Lines | Responsibility |
|---|---:|---|
| `parser.py` | 378 | Header repair, RFC 5322 parsing, `Received:` decomposition, identity extraction |
| `spf.py` | 385 | RFC 7208 evaluator: mechanisms, qualifiers, macros, lookup limits, recursion |
| `dkim_check.py` | 381 | Signature tag audit, public-key retrieval and sizing, cryptographic verification |
| `dmarc.py` | 284 | Policy discovery with organizational fallback, alignment, disposition |
| `heuristics.py` | 843 | Forensic deception checks |
| `utils.py` | 246 | Organizational domains, edit distance, homoglyph normalisation, brand table |
| `dns_utils.py` | 229 | Caching resolver, three DNS modes, lookup budget |
| `report.py` | 234 | Terminal rendering |
| `engine.py` | 207 | Orchestration and report assembly |
| `scoring.py` | 195 | Risk aggregation, domain grading, confidence |
| `cli.py` | 136 | Command-line interface |
| `authres.py` | 113 | `Authentication-Results` / `Received-SPF` parsing |
| `app.py` | 200 | Flask web interface and JSON API |
| `tests/` | 488 | 87 automated tests |

**Total: ~4,300 lines of Python.**

### 5.3 Parsing: handling real-world input

Headers pasted out of a browser are rarely well-formed. Continuation lines lose
their leading whitespace, quote markers (`> `) are prepended, line endings are
inconsistent. `repair_headers()` normalises line endings, strips quote markers
when the majority of lines carry them, and re-folds continuation lines that lost
their indentation, before the standard library parser is given the text.

Reconstructing the delivery path matters because `Received:` headers are
*prepended* by each relay — the bottom-most header is the oldest. The parser
reverses them into chronological order, computes inter-hop delays, and selects
the originating IP by priority: a `client-ip=` recorded by the receiving MTA
first, then the oldest hop carrying a public address, then any hop at all.

### 5.4 The heuristic layer

Each check returns zero or more `Finding` objects carrying an identifier, a
severity, a risk weight, a plain-language explanation, the evidence it was drawn
from, and a recommendation. Sixty distinct findings are implemented across five
categories — 25 authentication, 15 identity, 15 transport and timeline, 5
content and tooling:

**Identity deception.** A display name containing an email address different
from the real sender. A display name claiming one of 40+ protected brands while
the domain does not belong to that brand. Look-alike domains, detected by
normalising homoglyphs (`0→o`, `1→l`, `rn→m`, `vv→w`) and then computing edit
distance against known brand domains — so `paypa1.com` and `rnicrosoft.com` are
both caught. Brand names embedded as labels in unrelated domains
(`paypal-security-update.com`). Punycode and mixed-script addresses.
`Return-Path` / `From` divergence. `Reply-To` redirection, weighted higher when
it points at free webmail from an apparently corporate sender. Duplicate `From:`
headers — a header-injection technique where the client displays one and the
filter reads the other.

**Transport forensics.** Missing `Received:` chains. Timestamps that run
backwards down the chain, which is physically impossible and therefore proves
fabrication. A `Date:` header later than the first relay timestamp. Private-IP
origins. HELO names that disagree with reverse DNS. Generic HELO names
(`localhost`, `unknown`). Message-ID domains unrelated to the sender.

**Content and tooling.** Subject lines matching ten categories of
social-engineering pattern — manufactured urgency, credential lures, account
threats, fake security alerts, payment lures, BEC openers. PHP originating-script
headers, which fingerprint mail sent through a compromised website. Scripted
mailer signatures.

**Cross-verification.** Comparison of the receiving server's recorded verdict
against this tool's independent re-evaluation, flagging disagreement.

### 5.5 Scoring

Risk points are summed, authentication passes contribute negative credit, and
the result is clamped to 0–100. Two refinements proved necessary during
development:

**Damping.** A message with a clean DMARC pass and no identity deception has its
non-identity risk scaled to 40%, so legitimate mail sent through an email service
provider is not pushed into "suspicious" by cosmetic findings such as an
unaligned `Return-Path`.

**Credit suppression.** This is the central rule. When a critical identity
finding fires — or two independent high-severity ones — all authentication credit
is set to zero. The reasoning: if the message impersonates a brand or uses a
look-alike domain, then the domain that passed authentication is the attacker's
own, and passing authentication for your own domain proves nothing about
trustworthiness. Without this rule the project would mark sample 03 as merely
"suspicious"; with it, the sample is correctly classified as "likely spoofed".

**Insufficient-evidence cap.** Findings are divided into those reporting the
*presence* of deception and those reporting the *absence* of evidence (no SPF
record, no DKIM signature, no Received chain, no Message-ID). A sparse or
truncated header paste triggers many absence findings simultaneously; before
this rule was added, pasting four header lines produced a score of 95 and a
verdict of "Highly Likely Spoofed". If no positive indicator fires, the score is
now capped at 44 and the verdict carries an explicit note that the input appears
incomplete. Absence of authentication is a weakness, not proof of forgery, and
the tool must not overstate what it knows.

Two further axes are reported separately. The **domain grade (A–F)** rates the
sending domain's authentication posture independently of this message — so the
spoofed PayPal sample earns an A, because `paypal.com` is correctly configured
with `p=reject`; the grade is what made the forgery detectable. **Confidence**
reports how much evidence was actually available, dropping when DNS was
unreachable, no body was supplied for DKIM verification, or no relay chain was
present.

---

## 6. Algorithms

### 6.1 SPF evaluation

```
function check_spf(ip, domain, sender, helo, depth):
    if depth > 10: return PERMERROR
    records ← TXT(domain) filtered to those starting "v=spf1"
    if count = 0: return NONE
    if count > 1: return PERMERROR          # RFC 7208 §4.5

    for each term in record, left to right:
        if term is a modifier (redirect= / exp=): remember it; continue
        qualifier ← leading [+-~?], default '+'
        switch mechanism:
            all                  → match
            ip4 / ip6            → match if ip ∈ network
            a / mx               → spend 1 lookup; resolve; match if ip ∈ results
            exists               → spend 1 lookup; match if any A record exists
            ptr                  → spend 1 lookup; reverse then forward-confirm
            include:<d>          → spend 1 lookup
                                   r ← check_spf(ip, d, ..., depth+1)
                                   pass → match
                                   none/permerror → return PERMERROR
                                   temperror → return TEMPERROR
        if match: return qualifier          # first match wins

    if redirect present: return check_spf(ip, redirect_target, ..., depth+1)
    return NEUTRAL
```

The lookup budget is enforced centrally in the resolver: `spend()` raises once
ten DNS-consuming mechanisms have been used, and `note_void()` raises after two
empty results, exactly as RFC 7208 §4.6.4 requires. Exceeding either is reported
as `permerror` with an explanation, because an over-long SPF record is itself a
security weakness — receivers cannot evaluate it, and the ambiguity favours the
attacker.

### 6.2 DMARC alignment and evaluation

```
function analyse_dmarc(from_domain, spf_result, dkim_result):
    record ← TXT("_dmarc." + from_domain)
    if none: record ← TXT("_dmarc." + organizational_domain(from_domain))
    if none: return NONE                      # no policy at all

    parse p, sp, pct, adkim, aspf, rua, ruf

    spf_leg  ← spf_result = pass
               AND aligned(envelope_domain, from_domain, mode=aspf)
    dkim_leg ← any signed domain d where
               dkim verifies AND aligned(d, from_domain, mode=adkim)

    if spf_leg OR dkim_leg: return PASS
    effective ← sp if from_domain is a subdomain and sp is set, else p
    return FAIL with disposition = effective

function aligned(child, parent, mode):
    if mode = 's': return child = parent
    return organizational_domain(child) = organizational_domain(parent)
```

Organizational-domain extraction uses a curated list of multi-label public
suffixes (`co.in`, `co.uk`, `com.au`, …) so that `a.b.example.co.in` correctly
reduces to `example.co.in` rather than `co.in`.

### 6.3 Look-alike domain detection

```
function is_lookalike(domain):
    label ← first label of organizational domain
    skeleton ← label with homoglyphs normalised
               (0→o, 1→l, 3→e, 5→s, rn→m, vv→w, hyphens removed)

    for each brand, legitimate_domains in BRAND_TABLE:
        if organizational domain ∈ legitimate_domains: return CLEAN

        if skeleton = brand:                       → CRITICAL (brand name reused)

        for each legit in legitimate_domains:
            if 0 < edit_distance(skeleton, skeleton(legit_label)) ≤ 2
               and |legit_label| ≥ 5:              → CRITICAL (typosquat)

        if brand appears as a dot/hyphen-delimited
           token inside label and |brand| ≥ 5:     → HIGH (brand embedded)
```

The `|brand| ≥ 5` and `|legit_label| ≥ 5` guards exist to prevent false
positives on short brand names such as `ups` or `dhl`, where coincidental
matches against ordinary words would be common.

---

## 7. Implementation

**Language and stack.** Python 3.13. `dnspython` for DNS, `dkimpy` for
cryptographic DKIM verification, `cryptography` for RSA public-key parsing (key
size reporting), Flask for the web interface, `pytest` for tests. All are
free, open-source and installed from PyPI; the project uses no paid service,
no API key and no account.

**Offline reproducibility.** DNS is the one external dependency the tool cannot
avoid, and laboratory or examination environments frequently lack internet
access. `dns_utils.Resolver` therefore supports three modes — `live`, `offline`
and `auto` (live with fallback). The fixture file
`samples/dns_fixtures.json` contains 23 TXT, 3 A, 2 MX and 2 PTR records
covering every domain referenced by the sample corpus. The generator script
`tools/generate_fixtures.py` mints real RSA keypairs when building it, so
reported DKIM key sizes (2048-bit for the legitimate domains, 1024-bit for the
attacker's) are genuine rather than fabricated.

**Interfaces.** Three front-ends share one engine: a Flask web application with
a paste box and one-click sample loading; a CLI supporting single files, stdin,
batch directories, JSON output and a configurable exit-status threshold for
pipeline use; and a JSON API.

**Security of the tool itself.** Input is capped at 1 MB. The sample loader
reduces any supplied name with `os.path.basename` and verifies the resolved path
remains inside the samples directory — a path-traversal attempt is covered by
the test suite. Analysis failures are caught and surfaced as messages rather
than stack traces. No pasted content is transmitted anywhere.

---

## 8. Testing and results

### 8.1 Methodology

Validation used two complementary approaches.

**Unit and integration testing.** 87 `pytest` cases covering domain utilities,
header repair and parsing, SPF mechanism evaluation (including the lookup
budget, macro expansion and include recursion), DKIM auditing, DMARC alignment
in both modes, individual heuristics, end-to-end classification, and all web
routes. The suite runs against offline fixtures, so results are deterministic
and require no network.

**Corpus validation.** Eight messages were constructed, each representing a
distinct and realistic attack or legitimate-mail pattern, with the expected
classification recorded in advance.

### 8.2 Results

```
pytest -v   →   87 passed in 0.38s
```

| # | Sample | Risk | Verdict | Grade | SPF | DKIM | DMARC | Findings |
|---|---|---:|---|:-:|---|---|---|---:|
| 01 | Legitimate Google security alert | 0 | Authentic | A | pass | neutral | pass | 2 |
| 02 | Spoofed PayPal, domain at `p=reject` | 100 | Highly Likely Spoofed | A | fail | none | fail | 10 |
| 03 | Look-alike domain, fully authenticated | 65 | Likely Spoofed | B | **pass** | **neutral** | **pass** | 6 |
| 04 | BEC / CEO fraud with `Reply-To` redirect | 100 | Highly Likely Spoofed | C | softfail | none | fail | 9 |
| 05 | Fabricated `Received:` chain | 100 | Highly Likely Spoofed | F | none | none | none | 11 |
| 06 | Legitimate newsletter via an ESP | 0 | Authentic | B | pass | neutral | pass* | 4 |
| 07 | Internal spoof, domain has no DMARC | 59 | Likely Spoofed | D | fail | none | none | 4 |
| 08 | Legitimate bank alert, strict alignment | 0 | Authentic | A | pass | neutral | pass | 3 |

\* provisional — the DKIM leg was accepted structurally because only headers were supplied.

**All eight classified correctly. No false positives on the three legitimate
samples; no false negatives on the five malicious ones.**

### 8.3 Analysis of individual cases

**Sample 02 — classical spoofing (risk 100).** The attacker set both the
envelope and header sender to `service@paypal.com` and sent from a rented
Russian VPS. PayPal publishes `-all`, so SPF fails; no DKIM signature exists;
DMARC fails with `p=reject`. The heuristic layer adds a `Reply-To` pointing at
Gmail, an urgency subject line, PHPMailer and PHP-originating-script
fingerprints, a single-hop path and a `Message-ID` from the VPS hostname. This
is the case every tool catches — included as a baseline.

**Sample 03 — the case that justifies the project (risk 65).** The attacker
registered `icici-netbanking-secure.com`, published `v=spf1 ip4:45.133.1.0/24
-all`, signed with DKIM from a valid selector, and published
`v=DMARC1; p=quarantine`. **SPF passes. DKIM is structurally valid. DMARC
passes.** Any analyser that stops at authentication reports this message as
clean. This tool classifies it as *Likely Spoofed* because:

* the display name "ICICI Bank Alerts" claims a brand the sending domain does
  not own (high);
* the domain embeds the brand name `icici` as a leading label (high);
* two independent high-severity identity findings suppress all authentication
  credit, per section 5.5;
* the subject uses an account-suspension threat (medium);
* the DKIM key is only 1024 bits, below the RFC 8301 recommendation (medium).

The domain grade of B is itself informative: the attacker's DMARC posture is
better configured than many legitimate organisations'.

**Sample 04 — business email compromise (risk 100).** The display name asserts
"Rajesh Menon | Managing Director", the `From:` is the real corporate domain,
and the subject is the two-word opener BEC operators use to start a conversation
before making a request. The decisive finding is `Reply-To:` pointing at a Gmail
address while the sender claims a corporate domain — rated critical because it
is the mechanism by which the conversation is captured. SPF softfails (the
domain publishes `~all`), and DMARC fails but with `p=none`, so a real receiver
would still deliver it. The tool reports the disposition honestly as "deliver
(monitoring only)", which is precisely why `p=none` is flagged as a weakness.

**Sample 05 — fabricated relay chain (risk 100).** The strongest finding is a
timestamp reversal: hop 2 is stamped 569 seconds *before* hop 1. Mail cannot
travel backwards in time, so at least one `Received:` header was inserted by
hand. Supporting findings: a `Date:` 2.5 hours later than the first relay, a
private-IP origin behind a generic `localhost` HELO, no `Message-ID`, no
authentication of any kind, and a PHP originating-script header.

**Sample 06 — legitimate mail that superficially resembles spoofing (risk 0).**
The newsletter is relayed through SendGrid, so the `Return-Path` is
`bounces@sendgrid.net` while the `From:` is `news@brightlearn.io`. SPF passes —
but for SendGrid's domain, which is *not* aligned with the visible sender.
Naively this looks like the "SPF pass on a spoofed From" pattern. DMARC resolves
it correctly: the DKIM signature carries `d=brightlearn.io`, which *is* aligned,
so the DKIM leg satisfies DMARC. The `Return-Path` mismatch is reported at
medium severity with an explicit note that DKIM alignment compensates. This
sample exists specifically to test that the tool does not generate false
positives on the most common legitimate pattern that resembles an attack.

**Sample 07 — the cost of having no DMARC (risk 59).** An external host sends
mail claiming to be from the campus HR department. SPF fails cleanly. But
`sfo-campus.in` publishes no DMARC record, so there is no policy instructing
receivers to act on that failure, and the message would be delivered. The
verdict is *Likely Spoofed* rather than the maximum, reflecting that the
evidence is strong but the deception itself is unsophisticated — and the
domain-owner recommendations lead with publishing a DMARC record.

### 8.4 Observations

1. **Authentication is necessary but not sufficient.** Sample 03 passes all
   three standards and is a phishing attack. Any detection system that treats
   DMARC pass as a terminal verdict can be defeated by a $10 domain
   registration.
2. **SPF alone is weak.** Samples 04 and 07 both fail SPF; in both cases the
   absence or weakness of DMARC means real receivers would deliver them anyway.
   SPF without DMARC enforcement is advisory.
3. **Alignment is the concept that actually matters**, and it is the one most
   often misunderstood. Sample 06 passes SPF for a domain the reader never sees;
   only the aligned DKIM signature makes it trustworthy.
4. **Fabricated relay chains are detectable by internal contradiction.**
   Attackers inserting fake `Received:` headers rarely make the timestamps
   consistent, because doing so requires understanding that the chain is
   prepended rather than appended.

---

## 9. Limitations

1. **DKIM cryptographic verification requires the complete raw message.** The
   `bh=` tag hashes the body, so headers alone cannot be verified. The tool
   performs a structural audit and reports `neutral`, explicitly declining to
   claim a pass it cannot prove.
2. **SPF and DMARC are evaluated against current DNS**, not DNS as it stood at
   delivery time. A record changed since then yields a different answer. The
   tool mitigates this by comparing against the recorded
   `Authentication-Results` and flagging disagreement.
3. **`Authentication-Results` headers are forgeable** by any host upstream of
   the trusted boundary MTA. They are treated as evidence, never as proof.
4. **Organizational-domain extraction uses a curated suffix list**, not the
   complete Public Suffix List, so unusual TLDs may reduce incorrectly.
5. **The brand table is finite** (40+ entries). Impersonation of a brand outside
   it is caught only by the generic checks.
6. **Heuristics are probabilistic.** Legitimate mail sent through unusual
   infrastructure can score as suspicious. Every finding is therefore reported
   with its evidence so a human can evaluate it; the tool informs judgement
   rather than replacing it.
7. **Validation used a constructed corpus** rather than a large labelled dataset
   of real mail, so the reported accuracy demonstrates correct behaviour on
   representative cases, not a statistical false-positive rate.

---

## 10. Future scope

* **ARC evaluation** (RFC 8617) to handle forwarded and mailing-list mail, where
  SPF and DKIM legitimately break.
* **Full Public Suffix List integration** for exact organizational-domain
  resolution.
* **DMARC aggregate report (RUA) parsing** so a domain owner can use the same
  tool to audit their own sending sources.
* **Attachment and URL analysis** — extracting links, resolving redirect chains,
  and checking domain age via WHOIS.
* **Supervised classification** trained on a labelled corpus, using the current
  findings as features, with the rule-based score retained as the explanation
  layer so verdicts remain auditable.
* **IMAP integration** for continuous mailbox monitoring.
* **Mail-server deployment** as a Postfix/milter filter applying the score at
  delivery time rather than after the fact.

---

## 11. Conclusion

This project implements a complete email spoofing-detection system covering the
three standards that authenticate internet mail, and demonstrates — through a
deliberately constructed test case — that those standards alone are insufficient.
An attacker who registers their own domain can satisfy SPF, DKIM and DMARC
completely while impersonating a bank, because the standards verify domain
authorisation and not the far harder question of whether the domain is the one
the reader expects.

The system closes that gap by combining independent re-derivation of all three
authentication results from DNS with a forensic layer of sixty checks
examining sender identity consistency, relay-path integrity, timestamp
coherence and social-engineering content. Risk is aggregated into an explainable
0–100 score in which every point is attributable to a named check with its
supporting evidence, so the verdict can be audited rather than merely trusted.

Validation against eight annotated samples produced correct classification in
all eight cases, with no false positives on legitimate mail — including the ESP
relay pattern that most closely resembles an attack — and no false negatives on
the five malicious cases. 87 automated tests cover the implementation and run
offline in under a second.

The practical conclusion for a mail recipient is that authentication results
should be read as one input among several, never as a verdict. The practical
conclusion for a domain owner is that publishing DMARC with an enforcing policy
is the single highest-value action available: samples 02 and 07 differ almost
entirely in that one respect, and it is the difference between a forgery that is
refused at the SMTP transaction and one that lands in the inbox.

---

## 12. References

1. Resnick, P. (Ed.), *Internet Message Format*, RFC 5322, IETF, October 2008.
2. Kitterman, S., *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1*, RFC 7208, IETF, April 2014.
3. Crocker, D., Hansen, T., Kucherawy, M. (Eds.), *DomainKeys Identified Mail (DKIM) Signatures*, RFC 6376, IETF, September 2011.
4. Kitterman, S., *Cryptographic Algorithm and Key Usage Update to DomainKeys Identified Mail (DKIM)*, RFC 8301, IETF, January 2018.
5. Kucherawy, M., Zwicky, E. (Eds.), *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*, RFC 7489, IETF, March 2015.
6. Kucherawy, M., *Message Header Field for Indicating Message Authentication Status*, RFC 8601, IETF, May 2019.
7. Martin, F., et al., *Interoperability Issues between Domain-based Message Authentication, Reporting, and Conformance (DMARC) and Indirect Email Flows*, RFC 7960, IETF, September 2016.
8. Andersen, K., et al., *Authenticated Received Chain (ARC) Protocol*, RFC 8617, IETF, July 2019.
9. Klensin, J., *Simple Mail Transfer Protocol*, RFC 5321, IETF, October 2008.

---

## Appendix A — Running the project

```bash
pip install -r requirements.txt

python app.py                                      # web UI on :5000
python app.py --dns-mode offline                   # no internet required
python -m analyzer.cli samples/02_spoofed_paypal_dmarc_reject.eml
python -m analyzer.cli --batch samples/ --summary
pytest -v                                          # 87 tests
python tools/generate_fixtures.py                  # rebuild DNS fixtures
```

## Appendix B — Sample corpus

| File | Scenario demonstrated |
|---|---|
| `01_legit_google_alert.eml` | Genuine provider mail: SPF pass, aligned DKIM, DMARC `p=reject` pass |
| `02_spoofed_paypal_dmarc_reject.eml` | Direct forgery of a protected domain; every check fails |
| `03_lookalike_domain_authenticated.eml` | **Attacker-owned domain that passes SPF, DKIM and DMARC** |
| `04_bec_ceo_fraud.eml` | Executive impersonation with `Reply-To` redirection to free webmail |
| `05_forged_received_chain.eml` | Fabricated relay chain with reversed timestamps |
| `06_legit_newsletter_esp.eml` | Legitimate ESP relay: unaligned SPF rescued by aligned DKIM |
| `07_internal_spoof_no_dmarc.eml` | External host spoofing an internal department; no DMARC to enforce |
| `08_legit_strict_alignment.eml` | Clean baseline with strict DMARC alignment |
