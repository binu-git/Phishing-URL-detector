import joblib
import numpy as np
from features import extract_features

# Load the trained model and encoder
model = joblib.load('model.pkl')
tld_encoder = joblib.load('tld_encoder.pkl')

def predict_url(url):
    # Extract features
    features = extract_features(url, tld_encoder)
    # Align features
    features_aligned = np.array(features).reshape(1, -1)
    # Predict
    prediction = model.predict(features_aligned)
    return "Phishing" if prediction[0] else "Safe"

if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "http://example-login-security-alert.com",
        "https://www.google.com",
        "http://secure-login-paypal.com/verify-account"
    ]
    for url in test_urls:
        result = predict_url(url)
        print(f"The URL {url} is {result}")
