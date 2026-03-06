import re
import requests
import base64
from config import VIRUSTOTAL_API_KEY, URLSCAN_API_KEY

def extract_and_analyze_urls(body):
    urls = extract_urls(body)
    if not urls:
        return [{"info": "No URLs found in email body"}]

    results = []
    for url in urls:
        result = {
            "url": url,
            "shortened": is_shortened(url),
            "virustotal": check_virustotal_url(url),
            "urlscan": submit_urlscan(url),
            "suspicious_keywords": check_suspicious_keywords(url)
        }
        results.append(result)

    return results

def extract_urls(body):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(pattern, body)
    return list(set(urls))  # deduplicate

def is_shortened(url):
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
    ]
    return any(s in url for s in shorteners)

def check_virustotal_url(url):
    # VT requires base64 encoded URL
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(endpoint, headers=headers)
        if r.status_code == 404:
            # Not scanned yet - submit it
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            return "Submitted to VT for first scan - check back shortly"
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "detection_ratio": f"{malicious}/{total}",
            "verdict": "MALICIOUS" if malicious > 0 else "CLEAN",
            "stats": stats
        }
    except Exception as e:
        return {"error": str(e)}

def submit_urlscan(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"url": url, "visibility": "private"}
    try:
        r = requests.post("https://urlscan.io/api/v1/scan/", 
                         headers=headers, json=payload)
        data = r.json()
        return {
            "scan_id": data.get("uuid"),
            "result_url": data.get("result"),
            "verdict": "Check result_url after ~30 seconds"
        }
    except Exception as e:
        return {"error": str(e)}

def check_suspicious_keywords(url):
    keywords = [
        "login", "signin", "verify", "account", "secure",
        "update", "confirm", "banking", "paypal", "apple",
        "amazon", "microsoft", "password", "credential"
    ]
    found = [kw for kw in keywords if kw.lower() in url.lower()]
    if found:
        return f"SUSPICIOUS - Keywords found: {', '.join(found)}"
    return "No suspicious keywords detected"
