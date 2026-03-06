import requests
import socket

try:
    from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY
except ImportError:
    VIRUSTOTAL_API_KEY = "your_key_here"
    ABUSEIPDB_API_KEY  = "your_key_here"
    SHODAN_API_KEY     = "your_key_here"


def verify_sender(email_data):
    """Main entry point called by app.py"""
    results = {}
    ip     = email_data.get("sender_ip")
    sender = email_data.get("from") or ""
    domain = sender.split("@")[-1].replace(">", "").strip() if "@" in sender else None

    results["ip_geolocation"]   = get_ip_geo(ip) if ip else {}
    results["abuseipdb"]        = check_abuseipdb(ip) if ip else {}
    results["domain_age_flag"]  = check_domain_age(domain) if domain else "No domain found"
    results["whois"]            = get_whois(domain) if domain else {}
    results["shodan"]           = check_shodan(ip) if ip else {}
    results["virustotal_ip"]    = check_virustotal_ip(ip) if ip else "No IP found"
    results["virustotal_domain"]= check_virustotal_domain(domain) if domain else "No domain found"

    return results


def get_ip_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        return {
            "country": data.get("country", "N/A"),
            "city":    data.get("city", "N/A"),
            "isp":     data.get("isp", "N/A"),
            "org":     data.get("org", "N/A"),
        }
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip):
    if ABUSEIPDB_API_KEY == "your_key_here":
        return {"abuseConfidenceScore": 0, "info": "No API key configured"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}


def check_domain_age(domain):
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            import datetime
            age_days = (datetime.datetime.now() - creation).days
            if age_days < 30:
                return f"HIGH RISK - Domain only {age_days} days old"
            elif age_days < 180:
                return f"MEDIUM RISK - Domain {age_days} days old"
            else:
                return f"OK - Domain {age_days} days old"
        return "Domain age unknown"
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


def get_whois(domain):
    try:
        import whois
        w = whois.whois(domain)
        return {
            "registrar":      w.registrar or "N/A",
            "creation_date":  str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date":str(w.expiration_date) if w.expiration_date else "N/A",
        }
    except Exception as e:
        return {"error": str(e)}


def check_shodan(ip):
    if SHODAN_API_KEY == "your_key_here":
        return {"open_ports": "N/A", "vulns": "None", "info": "No API key configured"}
    try:
        import shodan
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return {
            "open_ports": ", ".join(str(p) for p in host.get("ports", [])) or "None",
            "vulns":      ", ".join(host.get("vulns", [])) or "None",
            "org":        host.get("org", "N/A"),
        }
    except Exception as e:
        return {"open_ports": "N/A", "vulns": "None", "error": str(e)}


def check_virustotal_ip(ip):
    if VIRUSTOTAL_API_KEY == "your_key_here":
        return "No API key configured"
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        return f"MALICIOUS ({mal} detections)" if mal > 0 else f"CLEAN (0/{sum(stats.values())})"
    except Exception as e:
        return f"Error: {e}"


def check_virustotal_domain(domain):
    if VIRUSTOTAL_API_KEY == "your_key_here":
        return "No API key configured"
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        return f"MALICIOUS ({mal} detections)" if mal > 0 else f"CLEAN (0/{sum(stats.values())})"
    except Exception as e:
        return f"Error: {e}"