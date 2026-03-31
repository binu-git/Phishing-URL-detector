from detector.rules import (
    has_ip_address,
    has_suspicious_keywords,
    has_excessive_subdomains,
    has_misleading_domain,
    has_brand_in_domain,
    has_abnormal_length,
    has_special_char_abuse,
    has_http_not_https,
    has_phishing_regex_patterns,
)

# (rule_function, weight)
# Weight reflects how strongly that rule alone indicates phishing.
# A single 40pt rule (IP address) won't cross the 60pt "Likely Phishing"
# threshold — it needs corroboration. This is intentional.
RULES = [
    (has_ip_address,              40),
    (has_misleading_domain,       35),
    (has_brand_in_domain,         30),
    (has_excessive_subdomains,    25),
    (has_phishing_regex_patterns, 20),
    (has_special_char_abuse,      20),
    (has_suspicious_keywords,     15),
    (has_abnormal_length,         10),
    (has_http_not_https,          10),
]

# Score thresholds — tune these after running your test cases
VERDICT_THRESHOLDS = {
    "Likely Phishing": 60,
    "Suspicious":      30,
    "Safe":             0,
}


def analyze_url(url: str) -> dict:
    """
    Runs all rules against a URL and returns a scored report.

    Returns:
        {
          "url":     original URL,
          "score":   integer risk score,
          "verdict": "Safe" | "Suspicious" | "Likely Phishing",
          "flags":   list of { rule, reason, weight }
        }
    """
    triggered = []
    score = 0

    for rule_fn, weight in RULES:
        try:
            flagged, reason = rule_fn(url)
            if flagged and reason:
                triggered.append({
                    "rule":   rule_fn.__name__,
                    "reason": reason,
                    "weight": weight,
                })
                score += weight
        except Exception as e:
            # Never let one bad rule crash the whole analysis
            triggered.append({
                "rule":   rule_fn.__name__,
                "reason": f"Rule error: {str(e)}",
                "weight": 0,
            })

    # Determine verdict from highest matching threshold
    verdict = "Safe"
    for label, threshold in VERDICT_THRESHOLDS.items():
        if score >= threshold:
            verdict = label
            break

    return {
        "url":     url,
        "score":   score,
        "verdict": verdict,
        "flags":   triggered,
    }
