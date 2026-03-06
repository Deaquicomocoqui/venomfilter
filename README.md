# 🐍 VenomFilter

A Flask-based email security analysis tool that neutralizes threats before they reach you — detecting phishing, spoofing, malicious URLs, and suspicious attachments.

---

## 🔍 Features

| Feature | Requires API Key |
|---|---|
| Email header parsing (From, Subject, Date) | ❌ No |
| SPF / DMARC / DKIM validation (DNS-based) | ❌ No |
| Reply-To mismatch detection | ❌ No |
| Sender IP extraction & geolocation | ❌ No |
| Domain age check (WHOIS) | ❌ No |
| URL extraction & keyword scanning | ❌ No |
| Attachment extension risk flagging | ❌ No |
| Risk score calculation & report | ❌ No |
| VirusTotal URL / IP / file hash lookup | ✅ Yes |
| AbuseIPDB IP reputation check | ✅ Yes |
| URLScan.io submission | ✅ Yes |

The app runs in **degraded mode** without API keys — all DNS and local checks still work.

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/venomfilter.git
cd venomfilter
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API keys (optional)
Edit `config.py` and add your keys:
```python
VIRUSTOTAL_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY  = "your_key_here"
URLSCAN_API_KEY    = "your_key_here"
```

> 💡 Leave keys as `"your_key_here"` to skip API calls gracefully.

### 4. Run the app
```bash
python app.py
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 📁 Project Structure

```
venomfilter/
├── app.py                  # Flask app & route handlers
├── config.py               # API keys configuration
├── requirements.txt        # Python dependencies
├── modules/
│   ├── parser.py           # Email parsing (headers, body, attachments)
│   ├── header_check.py     # SPF / DMARC / DKIM validation
│   ├── reputation.py       # VirusTotal, AbuseIPDB, domain age (WHOIS)
│   ├── url_check.py        # URL extraction & VirusTotal scanning
│   ├── attachment_check.py # Attachment hash checking & extension risk
│   ├── ip_lookup.py        # IP geolocation
│   └── report.py           # Report generation
├── templates/
│   └── index.html          # Web UI
└── static/                 # CSS / JS assets
```

---

## 🔑 Getting API Keys

- **VirusTotal** — [https://www.virustotal.com/gui/sign-in](https://www.virustotal.com/gui/sign-in) → API Key in your profile
- **AbuseIPDB** — [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register) → API Keys tab
- **URLScan.io** — [https://urlscan.io/user/signup](https://urlscan.io/user/signup) → API Key in settings

---

## 🛡️ Risk Scoring

The analyzer produces a risk score from 0–100:

| Score | Risk Level |
|---|---|
| 0–30 | 🟢 Low |
| 31–60 | 🟡 Medium |
| 61–80 | 🟠 High |
| 81–100 | 🔴 Critical |

---

## 📦 Dependencies

```
flask
dnspython
requests
python-whois
```

---

## ⚠️ Disclaimer

This tool is for **educational and defensive security purposes only**. Always handle email data responsibly and in compliance with applicable privacy laws.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
# venomfilter
