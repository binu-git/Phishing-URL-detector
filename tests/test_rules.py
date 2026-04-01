import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detector.analyzer import analyze_url

# Format: (url, expected_verdict, description)
TEST_CASES = [

    # ── Safe baselines ─────────────────────────────────────────────────────
    # These must NEVER be flagged — they are well-known legitimate sites.
    # If any of these fail, your weights are too aggressive.
    ("https://google.com",                            "Safe", "Google homepage"),
    ("https://github.com/login",                      "Safe", "GitHub login (has keyword but is safe)"),
    ("https://stackoverflow.com/questions",           "Safe", "Stack Overflow"),
    ("https://www.bbc.com/news",                      "Safe", "BBC News"),
    ("https://linkedin.com/in/username",              "Safe", "LinkedIn profile"),
    ("https://docs.python.org/3/library",             "Safe", "Python docs"),

    # ── Suspicious (score 30–59) ───────────────────────────────────────────
    # Mixed signals — concerning but not conclusive.
    ("http://free-account-update.com/verify",         "Suspicious", "HTTP + keywords + prefix"),
    ("https://secure-login-portal.com/signin",        "Suspicious", "Keywords + regex, no brand"),
    ("http://update-your-details.com/form",           "Suspicious", "HTTP + keywords + dashes"),

    # ── Likely Phishing (score 60+) ────────────────────────────────────────
    # These should always be caught — clear phishing signals.
    ("http://192.168.1.1/admin/login",                "Likely Phishing", "Raw IP address"),
    ("http://10.0.0.1/secure/verify",                 "Likely Phishing", "Private IP + keywords"),
    ("http://paypal.com.secure-login.verify.xyz",     "Likely Phishing", "Brand in subdomain"),
    ("http://amazon-account-verify.com/signin",       "Likely Phishing", "Brand in domain + keywords"),
    ("https://amazon-secure-login-verify-now.tk",     "Likely Phishing", "Brand + free TLD"),
    ("http://microsoft.com.login.evil.xyz/update",    "Likely Phishing", "Microsoft brand trick"),
    ("http://apple-id-verify-account.com/signin",     "Likely Phishing", "Apple brand + keywords"),

    # ── Edge cases ─────────────────────────────────────────────────────────
    # These are the tricky ones — study any failures carefully.
    ("https://github.com/login/verify-email",         "Safe",           "Real site with phish-y path"),
    ("https://accounts.google.com/signin",            "Safe",           "Real Google signin page"),
    ("https://secure.paypal.com/login",               "Safe",           "Real PayPal login"),
    ("http://login.microsoftonline.com",              "Safe",           "Real Microsoft login portal"),
]


def run_tests():
    passed = failed = 0
    failures = []

    print(f"\n{'URL':<52} {'EXPECTED':<18} {'GOT':<18} {'SCORE':<7} {'PASS?'}")
    print("─" * 105)

    for url, expected, desc in TEST_CASES:
        result  = analyze_url(url)
        actual  = result["verdict"]
        score   = result["score"]
        ok      = actual == expected
        mark    = "✓" if ok else "✗"

        if ok:
            passed += 1
        else:
            failed += 1
            failures.append((url, expected, actual, score, desc, result["flags"]))

        print(f"{url:<52} {expected:<18} {actual:<18} {score:<7} {mark}")

    # ── Summary ──
    total = passed + failed
    print(f"\n{'─' * 105}")
    print(f"Result: {passed}/{total} passed", end="")
    if failed == 0:
        print("  — all tests passing!")
    else:
        print(f"  — {failed} failure(s) need attention\n")

    # ── Failure details ──
    if failures:
        print("FAILURES — diagnosis:\n")
        for url, expected, actual, score, desc, flags in failures:
            print(f"  [{desc}]")
            print(f"  URL      : {url}")
            print(f"  Expected : {expected}")
            print(f"  Got      : {actual}  (score: {score})")
            if flags:
                print(f"  Flags fired:")
                for f in flags:
                    print(f"    [{f['weight']:>3}pts] {f['reason']}")
            else:
                print(f"  No flags fired — rules missed this entirely")
            print()

    return passed, failed


if __name__ == "__main__":
    run_tests()