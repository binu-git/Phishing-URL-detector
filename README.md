# Phishing URL Detector

A rule-based phishing URL detector in which URLs are analyzed against 9 detection rules, each contributing a weighted
score. The final score maps to one of three verdicts: Safe, Suspicious, or Likely Phishing.

---

## Demo

| URL | Score | Verdict |
|---|---|---|
| `https://google.com` | 0 | ✅ Safe |
| `http://free-account-update.com/verify` | 45 | ⚠️ Suspicious |
| `http://paypal.com.secure-login.verify.xyz` | 105 | 🚨 Likely Phishing |
| `http://192.168.1.1/admin/login` | 65 | 🚨 Likely Phishing |

---

## How It Works

Each URL is passed through 9 independent rule functions.
Every rule that fires adds its weight to a running score.
No rule on its own can definitively classify a URL —
the power comes from combining multiple weak signals.

### Scoring thresholds
| Verdict | Score range |
|---|---|
| Safe | 0 – 29 |
| Suspicious | 30 – 59 |
| Likely Phishing | 60+ |

### Detection rules
| Rule | Weight | What it catches |
|---|---|---|
| IP address as host | 40pts | `http://192.168.1.1/login` |
| Brand name in subdomain | 35pts | `paypal.com.evil.xyz` |
| Brand name in domain | 30pts | `amazon-verify.tk` |
| Excessive subdomains | 25pts | `a.b.c.d.e.com` |
| Regex phishing patterns | 20pts | Free TLDs, PHP kits, action phrases |
| Special char abuse | 20pts | `@` symbol, 3+ dashes, `%xx` encoding |
| Suspicious keywords | 15pts | login, verify, update, secure, account |
| Abnormal URL length | 10pts | URLs longer than 75 characters |
| HTTP not HTTPS | 10pts | Plain HTTP with no encryption |

### Trusted domain whitelist
Real brand domains (google.com, paypal.com, microsoftonline.com, etc.)
are whitelisted so brand/subdomain rules skip them entirely.
This prevents false positives on legitimate login pages like
`accounts.google.com` or `secure.paypal.com`.

---

## Project Structure
```
phishing-url-detector/
├── detector/
│   ├── __init__.py
│   ├── rules.py          # 9 individual rule functions
│   └── analyzer.py       # Scoring engine + verdict logic
├── api/
│   └── app.py            # Flask REST API (3 endpoints)
├── frontend/
│   └── index.html        # Self-contained UI — no build tools
├── tests/
│   ├── test_rules.py     # 20 test cases (Safe / Suspicious / Phishing)
│   └── RESULTS.md        # Test results + known limitations
├── research/
│   └── phishing_patterns.md
├── screenshots/
├── REFLECTION.md
└── README.md
```

---

## Setup & Running

### Requirements
- Python 3.8+
- pip

### Install dependencies
```bash
python -m venv venv

# Windows
venv\Scripts\activate


pip install flask flask-cors
```

### Start the API server
```bash
python api/app.py
```
Server runs at `http://localhost:5000`

### Open the frontend
Open `frontend/index.html` directly in your browser.
Make sure the Flask server is running first.

### Run the test suite
```bash
python tests/test_rules.py
```
Expected: 20/20 passed

---

## API Reference

### POST /analyze
Analyzes a URL and returns a scored report.

**Request:**
```json
{ "url": "http://example.com/login/verify" }
```

**Response:**
```json
{
  "url": "http://example.com/login/verify",
  "score": 45,
  "verdict": "Suspicious",
  "flags": [
    {
      "rule": "has_suspicious_keywords",
      "reason": "Suspicious keywords found: ['login', 'verify']",
      "weight": 15
    }
  ]
}
```

### GET /health
Returns server status.
```json
{ "status": "ok", "message": "Phishing detector API is running" }
```

### GET /history
Returns the last 10 analyzed URLs (most recent first).
```json
{
  "count": 2,
  "history": [
    { "url": "...", "verdict": "Safe", "score": 0 },
    { "url": "...", "verdict": "Likely Phishing", "score": 85 }
  ]
}
```

---

## Known Limitations

**What this detector cannot catch:**
- Homoglyph attacks — `pаypal.com` using Cyrillic characters looks
  identical but bypasses all string checks
- URL shorteners — `bit.ly/abc123` scores 0 because the destination
  is unknown without following the redirect
- Compromised legitimate domains — a phishing page hosted on a clean
  domain scores low because the domain itself looks trustworthy
- Zero-day domains — brand new domains with no keywords or brand
  tricks score 0 with rule-based detection alone
- Domain age — a domain registered yesterday is high risk but we
  have no way to check without a WHOIS API call

**What this detector is good at:**
- Classic impersonation attacks (brand in subdomain/domain)
- IP-based phishing pages
- Phishing kit URLs (PHP query strings, free TLDs)
- Obvious keyword stuffing in URLs


