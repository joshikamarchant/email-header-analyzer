"""
RFC 5322 header parsing and Received-chain reconstruction.

The parser is deliberately forgiving: headers pasted out of a webmail UI often
lose their folding whitespace, arrive with "> " quote markers, or use CRLF /
CR / LF inconsistently. `repair_headers()` normalises all of that before the
stdlib email parser sees it.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from typing import Dict, List, Optional, Tuple

from .utils import (
    EMAIL_RE,
    extract_ips,
    is_private_ip,
    is_valid_ip,
    normalise_domain,
    split_address,
    truncate,
)

HEADER_START_RE = re.compile(r"^([!-9;-~]+)[ \t]*:")
QUOTE_PREFIX_RE = re.compile(r"^(>+\s?)+")


# ---------------------------------------------------------------------------
# Input normalisation
# ---------------------------------------------------------------------------
def repair_headers(raw: str) -> str:
    """
    Clean up a pasted header block.

    * normalises line endings
    * strips mail-client quote markers ("> ")
    * re-folds continuation lines that lost their leading whitespace
    * drops a leading mbox "From " separator line
    """
    if not raw:
        return ""
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    # Strip quote markers only if the majority of non-empty lines carry them.
    non_empty = [ln for ln in lines if ln.strip()]
    quoted = [ln for ln in non_empty if QUOTE_PREFIX_RE.match(ln)]
    if non_empty and len(quoted) > len(non_empty) * 0.6:
        lines = [QUOTE_PREFIX_RE.sub("", ln) for ln in lines]

    if lines and lines[0].startswith("From ") and ":" not in lines[0].split(" ", 2)[0]:
        lines = lines[1:]

    out: List[str] = []
    in_body = False
    for line in lines:
        if in_body:
            out.append(line)
            continue
        if not line.strip():
            # Blank line ends the header block.
            in_body = True
            out.append(line)
            continue
        if line[:1] in (" ", "\t"):
            out.append(line)                       # already a continuation
        elif HEADER_START_RE.match(line):
            out.append(line)                       # new header
        elif out:
            out.append(" " + line.strip())         # lost continuation -> re-fold
        else:
            out.append(line)
    return "\n".join(out)


def decode_mime_words(value: Optional[str]) -> str:
    """Decode RFC 2047 encoded-words (=?utf-8?B?...?=) into plain text."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ReceivedHop:
    index: int                      # 1 = oldest (bottom-most header)
    raw: str
    from_host: str = ""             # HELO/EHLO name claimed by the client
    from_rdns: str = ""             # reverse-DNS name the server observed
    from_ip: str = ""
    by_host: str = ""
    protocol: str = ""
    tls: bool = False
    recipient: str = ""
    timestamp: Optional[datetime] = None
    delay_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "from_host": self.from_host,
            "from_rdns": self.from_rdns,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "protocol": self.protocol,
            "tls": self.tls,
            "recipient": self.recipient,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "delay_seconds": self.delay_seconds,
            "raw": truncate(self.raw, 400),
        }


@dataclass
class ParsedMessage:
    raw: str
    headers: List[Tuple[str, str]] = field(default_factory=list)
    hops: List[ReceivedHop] = field(default_factory=list)
    has_body: bool = False

    # Convenient extractions
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    from_count: int = 0
    return_path: str = ""
    return_path_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    to: str = ""
    subject: str = ""
    date_header: Optional[datetime] = None
    message_id: str = ""
    message_id_domain: str = ""
    x_mailer: str = ""
    client_ip: str = ""
    client_ip_source: str = ""
    helo: str = ""

    # ------------------------------------------------------------------ #
    def get(self, name: str, default: str = "") -> str:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return default

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def count(self, name: str) -> int:
        return len(self.get_all(name))

    def header_names(self) -> List[str]:
        return [k for k, _ in self.headers]

    def to_dict(self) -> Dict[str, object]:
        return {
            "from_display": self.from_display,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "return_path": self.return_path,
            "return_path_domain": self.return_path_domain,
            "reply_to": self.reply_to,
            "reply_to_domain": self.reply_to_domain,
            "to": self.to,
            "subject": self.subject,
            "date": self.date_header.isoformat() if self.date_header else None,
            "message_id": self.message_id,
            "message_id_domain": self.message_id_domain,
            "x_mailer": self.x_mailer,
            "client_ip": self.client_ip,
            "client_ip_source": self.client_ip_source,
            "helo": self.helo,
            "hop_count": len(self.hops),
            "hops": [h.to_dict() for h in self.hops],
            "has_body": self.has_body,
            "header_count": len(self.headers),
        }


# ---------------------------------------------------------------------------
# Received header parsing
# ---------------------------------------------------------------------------
_RE_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
_RE_PARENS = re.compile(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)")
_RE_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_RE_WITH = re.compile(r"\bwith\s+([A-Za-z0-9/.\-]+)", re.I)
_RE_FOR = re.compile(r"\bfor\s+<?([^\s;>]+@[^\s;>]+)>?", re.I)
_RE_BRACKET_IP = re.compile(r"\[([0-9a-fA-F:.]+)\]")


def parse_received(raw: str, index: int) -> ReceivedHop:
    """Decompose a single Received: header into its structural parts."""
    hop = ReceivedHop(index=index, raw=raw.strip())
    flat = " ".join(raw.split())

    m = _RE_FROM.search(flat)
    if m:
        hop.from_host = m.group(1).strip("[]<>").rstrip(".")

    # The parenthesised comment usually holds "rdns [ip]" or "[ip]".
    for comment in _RE_PARENS.findall(flat):
        bracket = _RE_BRACKET_IP.search(comment)
        if bracket and is_valid_ip(bracket.group(1)):
            hop.from_ip = bracket.group(1)
            rdns = comment[: bracket.start()].strip()
            rdns = rdns.split()[0] if rdns.split() else ""
            if rdns and rdns not in ("helo=", "unknown") and "=" not in rdns:
                hop.from_rdns = rdns.rstrip(".")
            break
        ips = extract_ips(comment)
        if ips:
            hop.from_ip = ips[0]
            break

    if not hop.from_ip:
        # Some MTAs write "from [1.2.3.4]" or embed the IP in the HELO token.
        ips = extract_ips(flat.split(" by ")[0] if " by " in flat else flat)
        if ips:
            hop.from_ip = ips[0]

    if hop.from_host and is_valid_ip(hop.from_host.strip("[]")):
        hop.from_ip = hop.from_ip or hop.from_host.strip("[]")

    m = _RE_BY.search(flat)
    if m:
        hop.by_host = m.group(1).strip("[]<>").rstrip(".")

    m = _RE_WITH.search(flat)
    if m:
        hop.protocol = m.group(1).upper()
        hop.tls = "S" in hop.protocol and hop.protocol.startswith("ESMTPS") or "TLS" in flat.upper()

    m = _RE_FOR.search(flat)
    if m:
        hop.recipient = m.group(1).strip("<>")

    # Timestamp: everything after the final semicolon.
    if ";" in raw:
        date_part = raw.rsplit(";", 1)[1].strip()
        date_part = re.sub(r"\(.*?\)", "", date_part).strip()
        try:
            dt = email.utils.parsedate_to_datetime(date_part)
            if dt is not None:
                hop.timestamp = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            hop.timestamp = None
    return hop


def _extract_client_ip(msg: ParsedMessage) -> Tuple[str, str]:
    """
    Determine the IP that actually injected the message.

    Priority:
      1. client-ip= / sender-ip= stated by the receiving MTA's auth results
      2. the bottom-most Received hop carrying a public IP
      3. any public IP anywhere in the Received chain
    """
    for header in msg.get_all("authentication-results") + msg.get_all("received-spf"):
        m = re.search(r"(?:client-ip|sender-ip|ip)\s*=\s*([0-9a-fA-F:.]+)", header, re.I)
        if m and is_valid_ip(m.group(1)):
            return m.group(1), "Authentication-Results/Received-SPF (client-ip)"

    for hop in msg.hops:  # hops[0] is oldest
        if hop.from_ip and not is_private_ip(hop.from_ip):
            return hop.from_ip, f"Received hop #{hop.index} (originating)"

    for hop in msg.hops:
        if hop.from_ip:
            return hop.from_ip, f"Received hop #{hop.index} (private/internal)"
    return "", "not found"


# ---------------------------------------------------------------------------
def parse_message(raw: str) -> ParsedMessage:
    """Parse raw header text (or a full RFC 822 message) into a ParsedMessage."""
    cleaned = repair_headers(raw)
    parsed = email.message_from_string(cleaned, policy=email.policy.compat32)

    msg = ParsedMessage(raw=cleaned)
    msg.headers = [(k, " ".join(str(v).split())) for k, v in parsed.items()]

    payload = parsed.get_payload()
    if isinstance(payload, str):
        msg.has_body = bool(payload.strip())
    else:
        msg.has_body = bool(payload)

    # Received chain: headers appear newest-first, so reverse for chronology.
    received_headers = msg.get_all("received")
    total = len(received_headers)
    for position, raw_hop in enumerate(received_headers):
        msg.hops.append(parse_received(raw_hop, total - position))
    msg.hops.sort(key=lambda h: h.index)

    # Inter-hop delays
    for i in range(1, len(msg.hops)):
        prev, cur = msg.hops[i - 1], msg.hops[i]
        if prev.timestamp and cur.timestamp:
            cur.delay_seconds = (cur.timestamp - prev.timestamp).total_seconds()

    # From
    from_raw = msg.get("from")
    msg.from_count = msg.count("from")
    display, addr = email.utils.parseaddr(from_raw)
    msg.from_display = decode_mime_words(display).strip()
    if not addr:
        found = EMAIL_RE.search(from_raw or "")
        addr = found.group(0) if found else ""
    msg.from_address = addr.strip().strip("<>")
    _, msg.from_domain = split_address(msg.from_address)

    # Return-Path / envelope sender
    rp = msg.get("return-path") or msg.get("x-envelope-from") or msg.get("envelope-from")
    _, rp_addr = email.utils.parseaddr(rp)
    if not rp_addr:
        found = EMAIL_RE.search(rp or "")
        rp_addr = found.group(0) if found else ""
    msg.return_path = rp_addr.strip().strip("<>")
    _, msg.return_path_domain = split_address(msg.return_path)

    # If Return-Path is absent, fall back to smtp.mailfrom in auth results.
    if not msg.return_path_domain:
        for header in msg.get_all("authentication-results") + msg.get_all("received-spf"):
            m = re.search(r"smtp\.mailfrom\s*=\s*([^\s;,()]+)", header, re.I)
            if m:
                msg.return_path = m.group(1).strip("<>")
                _, msg.return_path_domain = split_address(msg.return_path)
                if not msg.return_path_domain:
                    msg.return_path_domain = normalise_domain(m.group(1))
                break

    # Reply-To
    _, reply = email.utils.parseaddr(msg.get("reply-to"))
    msg.reply_to = reply.strip().strip("<>")
    _, msg.reply_to_domain = split_address(msg.reply_to)

    msg.to = decode_mime_words(msg.get("to"))
    msg.subject = decode_mime_words(msg.get("subject"))
    msg.x_mailer = msg.get("x-mailer") or msg.get("user-agent")

    # Date
    date_raw = msg.get("date")
    if date_raw:
        try:
            dt = email.utils.parsedate_to_datetime(date_raw)
            if dt is not None:
                msg.date_header = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            msg.date_header = None

    # Message-ID
    mid = msg.get("message-id").strip()
    msg.message_id = mid.strip("<>")
    if "@" in msg.message_id:
        msg.message_id_domain = normalise_domain(msg.message_id.rsplit("@", 1)[1])

    # HELO as claimed by the originating hop
    if msg.hops:
        msg.helo = msg.hops[0].from_host

    msg.client_ip, msg.client_ip_source = _extract_client_ip(msg)
    return msg
