import email
import hashlib
import requests

try:
    from config import VIRUSTOTAL_API_KEY
except ImportError:
    VIRUSTOTAL_API_KEY = "your_key_here"

HIGH_RISK_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".vbe",
    ".js",  ".jse", ".ws",  ".wsf", ".wsc", ".wsh", ".ps1", ".ps2",
    ".msi", ".reg", ".jar", ".hta", ".cpl", ".inf", ".lnk"
}

MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".pdf", ".zip", ".rar", ".7z", ".iso", ".img"
}


def extract_and_analyze_attachments(raw_email):
    """Main entry point called by app.py"""
    try:
        msg = email.message_from_string(raw_email)
        attachments = []

        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unknown"
                payload  = part.get_payload(decode=True)
                if not payload:
                    continue

                ext     = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                sha256  = hashlib.sha256(payload).hexdigest()

                if ext in HIGH_RISK_EXTENSIONS:
                    ext_flag = f"HIGH RISK - {ext} files can execute code"
                elif ext in MEDIUM_RISK_EXTENSIONS:
                    ext_flag = f"MEDIUM RISK - {ext} can contain macros/exploits"
                else:
                    ext_flag = f"LOW RISK - {ext or 'unknown'} extension"

                attachments.append({
                    "filename":       filename,
                    "size_bytes":     len(payload),
                    "sha256":         sha256,
                    "extension_flag": ext_flag,
                    "virustotal":     check_virustotal_hash(sha256),
                    "malwarebazaar":  check_malwarebazaar(sha256),
                })

        if not attachments:
            return [{"info": "No attachments found"}]

        return attachments

    except Exception as e:
        return [{"info": f"Attachment analysis error: {e}"}]


def check_virustotal_hash(sha256):
    if VIRUSTOTAL_API_KEY == "your_key_here":
        return {"verdict": "No API key configured"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if r.status_code == 404:
            return {"verdict": "Not found in VT database"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious", 0)
        return {
            "verdict":          "MALICIOUS" if mal > 0 else "CLEAN",
            "detection_ratio":  f"{mal}/{sum(stats.values())}",
        }
    except Exception as e:
        return {"error": str(e)}


def check_malwarebazaar(sha256):
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=10
        )
        data = r.json()
        if data.get("query_status") == "hash_not_found":
            return "Not found in MalwareBazaar"
        if data.get("query_status") == "ok":
            info = data["data"][0]
            return f"FOUND - {info.get('file_type','?')} | Tags: {', '.join(info.get('tags') or ['none'])}"
        return "Unknown status"
    except Exception as e:
        return f"Error: {e}"