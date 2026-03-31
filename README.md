 ## Detection Rules

| Rule | Weight | Why this weight? |
|---|---|---|
| IP address as host | 40 | Legitimate sites never use raw IPs |
| Brand name in subdomain | 35 | Classic impersonation — very reliable signal |
| Brand name in domain | 30 | Strong signal — attackers often register fake domains |
| Excessive subdomains (4+) | 25 | Obscures real domain |
| Regex phishing patterns | 20 | Targets known phishing kit conventions |
| Special char abuse (@, dashes, %) | 20 | Rare in legitimate URLs |
| Suspicious keywords | 15 | Weak alone — most real sites have these too |
| URL length > 75 chars | 10 | Padding is common in phishing |
| HTTP not HTTPS | 10 | Very weak alone but corroborates others |

