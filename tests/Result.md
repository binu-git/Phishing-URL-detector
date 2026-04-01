# Test Results — Step 5

## Run date: April 1, 2026
## Result: 20/20 passing

## Passing categories
- Safe baselines: 6/6
- Suspicious: 3/3
- Likely Phishing: 7/7
- Edge cases: 4/4

---

## Progress log

### 18/20 (starting point)
Two failures after adding has_brand_in_domain rule:
- http://login.microsoftonline.com → Got: Suspicious (expected: Safe)
- http://update-your-details.com/form → Got: Safe (expected: Suspicious)

### 18/20 → 19/20 (Fix 1)
Change: Added TRUSTED_DOMAINS whitelist + get_root_domain() helper.
Added whitelist guard to has_misleading_domain, has_excessive_subdomains,
and has_brand_in_domain so they skip real brand domains entirely.
Fixed: login.microsoftonline.com dropped from 55pts to 10pts → Safe ✓
Remaining failure: http://update-your-details.com/form still at 25pts

### 19/20 → 20/20 (Fix 2)
Attempted: Lowering dash threshold from > 3 to > 2 — had no effect.
URL only has 2 dashes so > 2 still did not fire.
Actual fix: Added action-phrase regex pattern to has_phishing_regex_patterns
that catches verb-your-noun.com domain structures.
Pattern: (update|verify|confirm|secure|login|account)-(your|my)-\w+\.
Fixed: update-your-details.com jumped from 25pts to 45pts → Suspicious ✓

---

## Test case breakdown

### Safe baselines — 6/6
| URL | Score | Result |
|---|---|---|
| https://google.com | 0 | ✓ Safe |
| https://github.com/login | 15 | ✓ Safe |
| https://stackoverflow.com/questions | 0 | ✓ Safe |
| https://www.bbc.com/news | 0 | ✓ Safe |
| https://linkedin.com/in/username | 0 | ✓ Safe |
| https://docs.python.org/3/library | 0 | ✓ Safe |

### Suspicious — 3/3
| URL | Score | Result |
|---|---|---|
| http://free-account-update.com/verify | 45 | ✓ Suspicious |
| https://secure-login-portal.com/signin | 35 | ✓ Suspicious |
| http://update-your-details.com/form | 45 | ✓ Suspicious |

### Likely Phishing — 7/7
| URL | Score | Result |
|---|---|---|
| http://192.168.1.1/admin/login | 65 | ✓ Likely Phishing |
| http://10.0.0.1/secure/verify | 65 | ✓ Likely Phishing |
| http://paypal.com.secure-login.verify.xyz | 105 | ✓ Likely Phishing |
| http://amazon-account-verify.com/signin | 75 | ✓ Likely Phishing |
| https://amazon-secure-login-verify-now.tk | 85 | ✓ Likely Phishing |
| http://microsoft.com.login.evil.xyz/update | 105 | ✓ Likely Phishing |
| http://apple-id-verify-account.com/signin | 75 | ✓ Likely Phishing |

### Edge cases — 4/4
| URL | Score | Result | Why it is tricky |
|---|---|---|---|
| https://github.com/login/verify-email | 15 | ✓ Safe | Real site with phish-y path words |
| https://accounts.google.com/signin | 15 | ✓ Safe | Brand in subdomain but real Google domain |
| https://secure.paypal.com/login | 15 | ✓ Safe | Real PayPal secure portal |
| http://login.microsoftonline.com | 10 | ✓ Safe | Real Microsoft login, not in obvious whitelist |

---

## Rule weights reference

| Rule | Weight | Justification |
|---|---|---|
| has_ip_address | 40pts | Legitimate sites never expose raw IPs to users |
| has_misleading_domain | 35pts | Brand in subdomain is a near-conclusive signal |
| has_brand_in_domain | 30pts | Brand embedded in fake domain is very reliable |
| has_excessive_subdomains | 25pts | 4+ levels almost always means obfuscation |
| has_phishing_regex_patterns | 20pts | Structural patterns tied to known phishing kits |
| has_special_char_abuse | 20pts | @ symbol and dash chains are rare in real URLs |
| has_suspicious_keywords | 15pts | Weak alone — too common on real sites |
| has_abnormal_length | 10pts | Padding is common but not conclusive |
| has_http_not_https | 10pts | Weak alone — some legacy tools still use HTTP |

## Verdict thresholds
- Safe:            score 0  – 29
- Suspicious:      score 30 – 59
- Likely Phishing: score 60+

---

## Known limitations

### False positives we can't fully eliminate
- URLs with brand names in subdomains of the REAL site
  (e.g. secure.paypal.com) — fixed with TRUSTED_DOMAINS whitelist
  but whitelist must be manually maintained as brands add new domains
- Long URLs on legitimate sites (e.g. deep GitHub paths)
  — mitigated by keeping length rule weight low at 10pts
- Legitimate hyphenated domains (e.g. my-business-name.com)
  — dash threshold kept at > 2 to avoid over-flagging

### False negatives — what we miss
- Brand-new phishing domains with no keywords or brand tricks
  (e.g. xk92ja.com/a) — no signals to detect, scores 0
- Punycode/homoglyph attacks (e.g. pаypal.com with Cyrillic 'а')
  — characters look identical visually but our string check misses them
  — fix would require unicode normalization before analysis
- URL shorteners (bit.ly, tinyurl) hiding phishing destinations
  — short URL scores 0 because destination is unknown
  — fix would require following redirects and analyzing the final URL
- Phishing pages on compromised legitimate domains
  (e.g. https://trusted-news-site.com/evil/login)
  — root domain is clean so most rules skip it
- Zero-day phishing domains registered hours ago
  — no keywords, no brand tricks, no suspicious TLD
  — fix would require WHOIS domain age lookup

### Weight tuning decisions made during this step
- Keywords weight kept at 15pts (not higher) because too many
  legitimate sites use words like 'login' and 'account'
- HTTP weight kept at 10pts because some legacy internal tools
  still use HTTP on private networks
- Dash threshold set to > 2 (not > 1) because single-dash domains
  like my-bank.com are very common and legitimate
- Action-phrase regex chosen over lowering dash threshold because
  it is more precise — targets the specific verb-your-noun pattern
  rather than bluntly counting all dashes

---
