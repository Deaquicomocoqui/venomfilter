import os
import base64
import datetime
from flask import Flask, render_template, request

from modules.parser           import parse_email
from modules.header_check     import check_headers
from modules.reputation       import verify_sender
from modules.attachment_check import extract_and_analyze_attachments
from modules.url_check        import extract_and_analyze_urls

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_email = None

    if "eml_file" in request.files and request.files["eml_file"].filename:
        raw_email = request.files["eml_file"].read().decode("utf-8", errors="ignore")
    elif request.form.get("raw_email"):
        raw_email = request.form.get("raw_email")

    if not raw_email or not raw_email.strip():
        return render_template("index.html", error="Please paste an email or upload a .eml file.")

    try:
        email_data   = parse_email(raw_email)
        body_only    = email_data.get("body_only", False)
        email_lookup = email_data.get("email_lookup", False)

        # Header auth
        if body_only or email_lookup:
            headers = check_headers(email_data)   # still checks SPF/DMARC via domain
        else:
            headers = check_headers(email_data)

        # Sender intelligence
        if body_only and not email_data.get("from"):
            sender_info = {
                "ip_geolocation": {},
                "abuseipdb": {},
                "domain_age_flag": "N/A — no sender info",
                "whois": {},
                "shodan": {},
                "virustotal_ip": "N/A",
                "virustotal_domain": "N/A",
            }
        else:
            sender_info = verify_sender(email_data)

        # Attachments — only in full raw email mode
        if body_only or email_lookup:
            attachments = [{"info": "Attachment analysis requires full raw email with headers"}]
        else:
            attachments = extract_and_analyze_attachments(raw_email)

        # URL analysis — skip for email address lookup
        body = email_data.get("body") or ""
        if email_lookup:
            urls = [{"info": "URL analysis not applicable for email address lookup"}]
        else:
            urls = extract_and_analyze_urls(body)

        # Enrich URLs with VirusTotal direct links
        for url in urls:
            if url.get("url"):
                url_b64 = base64.urlsafe_b64encode(url["url"].encode()).decode().strip("=")
                url["vt_link"] = f"https://www.virustotal.com/gui/url/{url_b64}"

        # Enrich attachments with direct VT / MalwareBazaar links
        for att in attachments:
            if att.get("sha256"):
                att["vt_link"] = f"https://www.virustotal.com/gui/file/{att['sha256']}"
                att["mb_link"] = f"https://bazaar.abuse.ch/sample/{att['sha256']}/"

        # Build external links for sender IP / domain
        sender_ip     = email_data.get("sender_ip") or ""
        sender_domain = ""
        raw_from = email_data.get("from") or ""
        if "@" in raw_from:
            sender_domain = raw_from.split("@")[-1].replace(">", "").strip()

        ext_links = {}
        if sender_ip:
            ext_links["vt_ip"]      = f"https://www.virustotal.com/gui/ip-address/{sender_ip}"
            ext_links["abuseipdb"]  = f"https://www.abuseipdb.com/check/{sender_ip}"
            ext_links["shodan"]     = f"https://www.shodan.io/host/{sender_ip}"
        if sender_domain:
            ext_links["vt_domain"]  = f"https://www.virustotal.com/gui/domain/{sender_domain}"
            ext_links["mxtoolbox"]  = f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{sender_domain}&run=toolpage"
            ext_links["whois"]      = f"https://whois.domaintools.com/{sender_domain}"

        risk_score, risk_flags = calculate_risk(headers, sender_info, attachments, urls)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        return render_template("results.html",
            email_data=email_data,
            headers=headers,
            sender_info=sender_info,
            attachments=attachments,
            urls=urls,
            risk_score=risk_score,
            risk_flags=risk_flags,
            timestamp=timestamp,
            body_only=body_only,
            email_lookup=email_lookup,
            ext_links=ext_links,
        )

    except Exception as e:
        import traceback
        return render_template("index.html", error=f"Analysis failed: {str(e)}")


def calculate_risk(headers, sender_info, attachments, urls):
    score = 0
    flags = []

    # Header checks
    if headers.get("reply_to_mismatch"):
        score += 20
        flags.append({"level": "high", "msg": "Reply-To domain does not match From domain"})
    if "No SPF" in str(headers.get("spf", "")):
        score += 15
        flags.append({"level": "medium", "msg": "No SPF record found on sender domain"})
    if "No DMARC" in str(headers.get("dmarc", "")):
        score += 15
        flags.append({"level": "medium", "msg": "No DMARC record found on sender domain"})
    if headers.get("dkim_present") is False:
        score += 10
        flags.append({"level": "medium", "msg": "No DKIM signature present"})

    # Domain age
    domain_age = str(sender_info.get("domain_age_flag", ""))
    if "HIGH RISK" in domain_age:
        score += 25
        flags.append({"level": "high", "msg": domain_age})
    elif "MEDIUM RISK" in domain_age:
        score += 10
        flags.append({"level": "medium", "msg": domain_age})

    # AbuseIPDB
    abuseipdb = sender_info.get("abuseipdb", {})
    abuse_score = abuseipdb.get("abuseConfidenceScore", 0) if isinstance(abuseipdb, dict) else 0
    if abuse_score and int(abuse_score) > 0:
        score += min(int(abuse_score), 20)
        flags.append({"level": "high", "msg": f"AbuseIPDB confidence score: {abuse_score}%"})

    # Attachments
    for att in attachments:
        if "HIGH RISK" in str(att.get("extension_flag", "")):
            score += 20
            flags.append({"level": "high", "msg": f"Dangerous attachment: {att.get('filename')}"})
        vt_att = att.get("virustotal", {})
        vt_verdict = vt_att.get("verdict", "") if isinstance(vt_att, dict) else str(vt_att)
        if "MALICIOUS" in str(vt_verdict):
            score += 30
            flags.append({"level": "critical", "msg": f"Malicious attachment detected: {att.get('filename')}"})

    # URLs
    for url in urls:
        if url.get("shortened"):
            score += 10
            flags.append({"level": "medium", "msg": f"Shortened URL detected: {url.get('url')}"})
        vt_url = url.get("virustotal", {})
        vt_url_verdict = vt_url.get("verdict", "") if isinstance(vt_url, dict) else str(vt_url)
        if "MALICIOUS" in str(vt_url_verdict):
            score += 25
            flags.append({"level": "critical", "msg": f"Malicious URL detected: {url.get('url')}"})
        kw = str(url.get("suspicious_keywords", ""))
        if "SUSPICIOUS" in kw:
            score += 10
            flags.append({"level": "medium", "msg": kw})

    score = min(score, 100)
    return score, flags


if __name__ == "__main__":
    app.run(debug=True, port=5000)
