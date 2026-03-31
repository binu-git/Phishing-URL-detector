import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detector.analyzer import analyze_url

test_urls = [
    # --- Expected: Safe ---
    ("https://google.com",                                     "Safe"),
    ("https://github.com/login",                               "Safe"),

    # --- Expected: Suspicious ---
    ("http://free-account-update.com/verify",                 "Suspicious"),
    ("https://secure-login-portal.com/signin",                "Suspicious"),

    # --- Expected: Likely Phishing ---
    ("http://192.168.1.1/admin/login",                         "Likely Phishing"),
    ("http://paypal.com.secure-login.verify.xyz/update",       "Likely Phishing"),
    ("https://amazon-secure-login-verify-now.tk/account",      "Likely Phishing"),
    ("http://amazon-account-verify.com/signin",                "Likely Phishing"),
]

print(f"\n{'URL':<55} {'EXPECTED':<18} {'GOT':<18} {'SCORE':<6} {'PASS?'}")
print("─" * 110)

passed = 0
for url, expected in test_urls:
    result  = analyze_url(url)
    verdict = result["verdict"]
    score   = result["score"]
    ok      = verdict == expected
    passed += int(ok)
    mark    = "✓" if ok else "✗"
    print(f"{url:<55} {expected:<18} {verdict:<18} {score:<6} {mark}")
    if not ok:
        for f in result["flags"]:
            print(f"    [{f['weight']:>3}pts] {f['reason']}")

print(f"\n{passed}/{len(test_urls)} passed")