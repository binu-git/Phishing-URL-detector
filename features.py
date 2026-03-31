# features.py
import math
import re
import tldextract
import pandas as pd

from sklearn.preprocessing import LabelEncoder


def url_length(url):
    return len(url)

def num_dots(url):
    return url.count('.')

def has_https(url):
    return int(url.startswith('https'))

def has_ip(url):
    # returns 1 if IP in URL, else 0
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

def num_subdirs(url):
    return url.count('/') - 2  # ignoring http://

def num_params(url):
    return url.count('?')

def suspicious_words(url):
    words = ['login', 'secure', 'update', 'verify', 'bank']
    return sum(word in url for word in words)

def special_char_count(url):
    return sum(not c.isalnum() for c in url)

def digits_count(url):
    return sum(c.isdigit() for c in url)

def entropy(url):
    from collections import Counter
    import math
    prob = [v/len(url) for v in Counter(url).values()]
    return -sum(p*math.log2(p) for p in prob)

# Main feature extractor
def extract_features(url, tld_encoder):
    parsed = tldextract.extract(url)
    tld = parsed.suffix
    features = [
        url_length(url),
        num_dots(url),
        has_https(url),
        has_ip(url),
        num_subdirs(url),
        num_params(url),
        suspicious_words(url),
        special_char_count(url),
        digits_count(url),
        entropy(url)
    ]
    # Encode TLD as numeric
    tld_num = tld_encoder.transform([tld])[0]
    features.append(tld_num)
    return features