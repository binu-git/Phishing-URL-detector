def extract_features(url):
    return[
        len(url),
        url.count('.'),
        int('https' in url),
        int('@' in url),
        int('-' in url),
    ]