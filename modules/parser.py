import email
import re
from email import policy


EMAIL_ADDR_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def is_email_address(text):
    """Return True if the entire input is just a single email address."""
    return bool(EMAIL_ADDR_RE.match(text.strip()))


def is_raw_email(text):
    """Detect if the text is a full raw email (has headers) or just a body."""
    header_patterns = [
        r'^Received:', r'^From:', r'^To:', r'^Subject:', r'^Date:',
        r'^MIME-Version:', r'^Content-Type:', r'^Message-ID:',
        r'^Return-Path:', r'^DKIM-Signature:', r'^Received-SPF:',
    ]
    lines = text.strip().splitlines()
    for line in lines[:20]:
        for pat in header_patterns:
            if re.match(pat, line, re.IGNORECASE):
                return True
    return False


def parse_email(raw_email):
    stripped = raw_email.strip()

    # Email address lookup mode
    if is_email_address(stripped):
        return {
            "from": stripped,
            "reply_to": None,
            "subject": None,
            "date": None,
            "received": None,
            "message_id": None,
            "spf": None,
            "dkim": None,
            "body": "",
            "sender_ip": None,
            "body_only": False,
            "email_lookup": True,
        }

    if not is_raw_email(raw_email):
        # Body-only mode: no headers to parse
        return {
            "from": None,
            "reply_to": None,
            "subject": None,
            "date": None,
            "received": None,
            "message_id": None,
            "spf": None,
            "dkim": None,
            "body": raw_email.strip(),
            "sender_ip": None,
            "body_only": True,
        }

    msg = email.message_from_string(raw_email, policy=policy.default)

    body = ""
    plain_part = msg.get_body(preferencelist=("plain",))
    if plain_part:
        try:
            body = plain_part.get_content()
        except Exception:
            body = ""

    data = {
        "from": msg.get("From"),
        "reply_to": msg.get("Reply-To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "received": msg.get_all("Received"),
        "message_id": msg.get("Message-ID"),
        "spf": msg.get("Received-SPF"),
        "dkim": msg.get("DKIM-Signature"),
        "body": body,
        "sender_ip": extract_sender_ip(msg.get_all("Received")),
        "body_only": False,
    }
    return data


def extract_sender_ip(received_headers):
    if not received_headers:
        return None
    for header in reversed(received_headers):
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
        if match:
            return match.group(1)
    return None
