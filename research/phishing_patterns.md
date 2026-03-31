 # Phishing URL Pattern Research

## Sample URLs for Analysis

### URL 1
**URL:** `http://192.168.1.1/secure/login/verify`  
**Red flags I spotted:**
- Uses a raw IP address instead of a domain name
- Contains keywords: "secure", "login", "verify"
- Uses HTTP not HTTPS  
**Most suspicious part:** The IP address — no legitimate service uses this

### URL 2
**URL:** `http://paypal.com.account-update.verify-secure.tk/signin`  
**Red flags I spotted:**
- PayPal brand name buried in subdomain
- Real domain is `.tk` — free domains often abused
- Keywords: "update", "verify", "signin"  
**Most suspicious part:** Fake domain with PayPal in subdomain

### URL 3
**URL:** `http://amazon-account-verify-now.com/login?session=abc`  
**Red flags I spotted:**
- Fake domain using "amazon" keyword
- Hyphenated domain looks suspicious
- Keyword "verify" in path  
**Most suspicious part:** Domain is not amazon.com

### URL 4
**URL:** `http://secure-banking.login-verify.xyz/update`  
**Red flags I spotted:**
- Generic domain "login-verify.xyz"
- Keywords: "secure", "banking", "update"
- Uses HTTP not HTTPS  
**Most suspicious part:** Domain is generic, not tied to a real bank

### URL 5
**URL:** `http://login.microsoft.com.evil-domain.net/verify`  
**Red flags I spotted:**
- Microsoft brand name buried in subdomain
- Real domain is `evil-domain.net`
- Keyword "verify" in path  
**Most suspicious part:** Fake domain, Microsoft only in subdomain

### URL 6
**URL:** `http://bit.ly/3xAb92k`  
**Red flags I spotted:**
- URL shortener hides destination
- No clue what site it leads to  
**Most suspicious part:** Shortened link disguises phishing

### URL 7
**URL:** `https://google.com`  
**Red flags I spotted:**  
- None — legitimate domain, HTTPS, no suspicious keywords  
**Most suspicious part:** None — safe baseline

### URL 8
**URL:** `https://github.com/login`  
**Red flags I spotted:**  
- Contains "login" but domain is correct (github.com)  
**Most suspicious part:** None — safe, legitimate login page

### URL 9
**URL:** `http://facebook-secure-login.com/account/verify`  
**Red flags I spotted:**
- Fake domain using "facebook" keyword
- Hyphenated domain looks suspicious
- Keywords: "secure", "login", "verify"  
**Most suspicious part:** Domain is not facebook.com

### URL 10
**URL:** `http://203.0.113.42/paypal/verify-account`  
**Red flags I spotted:**
- Raw IP address instead of domain
- Contains PayPal keyword in path
- Keyword "verify-account"  
**Most suspicious part:** IP address — not a real PayPal domain

---

### URL 11
**URL:** `http://bankofamerica.verify-login.com/update`  
**Red flags I spotted:**
- Fake domain with "bankofamerica" keyword
- Real domain is `verify-login.com`
- Keyword "update"  
**Most suspicious part:** Brand name only in subdomain

### URL 12
**URL:** `http://secure.appleid-login.net/verify`  
**Red flags I spotted:**
- Fake domain using "appleid"
- Keyword "secure" and "verify"
- Uses HTTP not HTTPS  
**Most suspicious part:** Domain is not apple.com

### URL 13
**URL:** `http://ebay.account-security-check.com/login`  
**Red flags I spotted:**
- Fake domain with "ebay" keyword
- Real domain is `account-security-check.com`
- Keyword "security"  
**Most suspicious part:** Brand name buried in subdomain

### URL 14
**URL:** `http://yahoo-login.verify-account.org/update`  
**Red flags I spotted:**
- Fake domain with "yahoo" keyword
- Real domain is `verify-account.org`
- Keywords: "login", "update"  
**Most suspicious part:** Domain is not yahoo.com

### URL 15
**URL:** `http://dropbox.secure-file-login.com/auth`  
**Red flags I spotted:**
- Fake domain with "dropbox" keyword
- Real domain is `secure-file-login.com`
- Keyword "secure"  
**Most suspicious part:** Brand name only in subdomain

### URL 16
**URL:** `http://linkedin.account-verify-login.net/check`  
**Red flags I spotted:**
- Fake domain with "linkedin" keyword
- Real domain is `account-verify-login.net`
- Keyword "verify"  
**Most suspicious part:** Domain is not linkedin.com

### URL 17
**URL:** `http://instagram.secure-login-update.com/verify`  
**Red flags I spotted:**
- Fake domain with "instagram" keyword
- Real domain is `secure-login-update.com`
- Keywords: "secure", "update"  
**Most suspicious part:** Domain is not instagram.com

### URL 18
**URL:** `http://twitter.account-check-secure.org/login`  
**Red flags I spotted:**
- Fake domain with "twitter" keyword
- Real domain is `account-check-secure.org`
- Keyword "secure"  
**Most suspicious part:** Domain is not twitter.com

### URL 19
**URL:** `http://netflix.verify-account-login.com/update`  
**Red flags I spotted:**
- Fake domain with "netflix" keyword
- Real domain is `verify-account-login.com`
- Keyword "update"  
**Most suspicious part:** Domain is not netflix.com

### URL 20
**URL:** `http://spotify.secure-login-check.net/auth`  
**Red flags I spotted:**
- Fake domain with "spotify" keyword
- Real domain is `secure-login-check.net`
- Keyword "secure"  
**Most suspicious part:** Domain is not spotify.com

