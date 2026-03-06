import dns.resolver

def check_headers(email_data):
    results = {}
    sender = email_data.get("from") or ""
    domain = sender.split("@")[-1].replace(">", "").strip() if "@" in sender else None

    if domain:
        results["spf"]   = check_spf(domain)
        results["dmarc"] = check_dmarc(domain)
    else:
        results["spf"]   = "No sender domain found"
        results["dmarc"] = "No sender domain found"

    results["dkim_present"]      = bool(email_data.get("dkim"))
    results["reply_to_mismatch"] = check_reply_to_mismatch(email_data)

    return results

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            if "v=spf1" in str(r):
                return str(r)
        return "No SPF record found"
    except Exception as e:
        return f"Error: {e}"

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            if "v=DMARC1" in str(r):
                return str(r)
        return "No DMARC record found"
    except Exception as e:
        return f"Error: {e}"

def check_reply_to_mismatch(email_data):
    from_addr = email_data.get("from") or ""
    reply_to  = email_data.get("reply_to") or ""
    if reply_to and from_addr and "@" in from_addr and "@" in reply_to:
        from_domain  = from_addr.split("@")[-1].replace(">", "").strip()
        reply_domain = reply_to.split("@")[-1].replace(">", "").strip()
        return from_domain != reply_domain
    return False