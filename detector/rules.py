import re
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'paypal.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'stackoverflow.com', 'python.org',
    'microsoftonline.com', 'live.com', 'outlook.com', 'icloud.com',
}

def get_root_domain(url: str) -> str:

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


# ── Rules ──────────────────────────────────────────────────────────────────────

def has_ip_address(url: str):
    pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    match = re.match(pattern, url)
    return bool(match), "Uses IP address instead of domain name"


def has_suspicious_keywords(url: str):
    keywords = [
        'login', 'verify', 'update', 'secure', 'account',
        'banking', 'confirm', 'signin', 'password', 'credential',
        'validate', 'authenticate', 'webscr', 'ebayisapi'
    ]
    url_lower = url.lower()
    found = [kw for kw in keywords if kw in url_lower]
    return bool(found), f"Suspicious keywords found: {found}"


def has_excessive_subdomains(url: str):
    # Skip entirely for trusted domains — accounts.google.com is safe
    if get_root_domain(url) in TRUSTED_DOMAINS:
        return False, ""

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = [p for p in hostname.split('.') if p]
    return len(parts) > 4, f"Too many subdomains ({len(parts)} parts): {hostname}"


def has_misleading_domain(url: str):
    # Skip if this IS the real brand's own domain (e.g. secure.paypal.com)
    if get_root_domain(url) in TRUSTED_DOMAINS:
        return False, ""

    trusted_brands = [
        'paypal', 'amazon', 'google', 'apple', 'microsoft',
        'facebook', 'netflix', 'instagram', 'twitter', 'bank',
        'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays'
    ]
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split('.')

    if len(parts) <= 2:
        return False, ""

    subdomain_str = '.'.join(parts[:-2]).lower()
    found = [brand for brand in trusted_brands if brand in subdomain_str]
    return bool(found), f"Brand name '{found}' in subdomain, not in real domain"


def has_brand_in_domain(url: str):
    # Skip if this IS the real brand's own domain (e.g. amazon.com)
    if get_root_domain(url) in TRUSTED_DOMAINS:
        return False, ""

    trusted_brands = [
        'paypal', 'amazon', 'google', 'apple', 'microsoft',
        'facebook', 'netflix', 'instagram', 'twitter', 'bank',
        'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays'
    ]
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split('.')

    if len(parts) < 2:
        return False, ""

    registered_domain = parts[-2].lower()
    found = [
        brand for brand in trusted_brands
        if brand in registered_domain and brand != registered_domain
    ]
    return bool(found), f"Brand name '{found}' embedded in domain (not the real site)"


def has_abnormal_length(url: str):
    return len(url) > 75, f"URL is suspiciously long: {len(url)} characters"


def has_special_char_abuse(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    dash_count    = hostname.count('-')
    at_count      = url.count('@')
    encoded_count = url.count('%')

    reasons = []
    if at_count > 0:      reasons.append(f"@ symbol (credential trick)")
    if dash_count > 2:    reasons.append(f"{dash_count} dashes in hostname")  
    if encoded_count > 5: reasons.append(f"{encoded_count} percent-encoded chars")

    flagged = at_count > 0 or dash_count > 2 or encoded_count > 5
    return flagged, f"Special char abuse: {', '.join(reasons)}" if reasons else ""


def has_http_not_https(url: str):
    return url.startswith('http://'), "Uses HTTP instead of HTTPS (no encryption)"


def has_phishing_regex_patterns(url: str):
    patterns = [
        (r'[a-z0-9\-]+\.(tk|ml|ga|cf|gq|pw|top|xyz|club|online)\b',
         "Suspicious free/throwaway TLD"),

        (r'\.php\?[a-z]+=',
         "PHP query string (common in phishing kits)"),

        (r'\d{6,}',
         "Long numeric sequence in URL"),

        (r'(secure|login|verify|update|account)[\-_]\w+\.',
         "Phishing-style prefix in domain name"),

        (r'https?://[^/]+/.*//.*',
         "Double slashes in path (obfuscation)"),

        (r'(update|verify|confirm|secure|login|account)[\-_](your|my)[\-_]\w+\.',
         "Action-phrase domain structure"),
    ]

    for pattern, reason in patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True, f"Regex match: {reason}"

    return False, ""