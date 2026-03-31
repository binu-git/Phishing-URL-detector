import sys
import os

# Make sure Python can find your detector/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, jsonify
from flask_cors import CORS
from detector.analyzer import analyze_url

app = Flask(__name__)
CORS(app)  # Allows your HTML frontend to call this API without being blocked

# In-memory history — stores last 10 scans, resets when server restarts
scan_history = []


# ─── Helper ───────────────────────────────────────────────────────────────────

def clean_url(url: str) -> str:
    """
    Normalizes the incoming URL.
    If someone types 'google.com' without a scheme, we add 'http://'
    so urlparse can correctly split the hostname from the path.
    """
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    return url


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """
    Quick sanity-check endpoint.
    Call this first to confirm the server is running before testing /analyze.
    """
    return jsonify({"status": "ok", "message": "Phishing detector API is running"})


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Main detection endpoint.

    Expects JSON body:  { "url": "http://example.com" }
    Returns JSON:       { url, score, verdict, flags }
    """
    # 1. Parse the request body
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    if len(url) > 2048:
        return jsonify({"error": "URL too long (max 2048 characters)"}), 400

    # 2. Normalize and analyze
    url = clean_url(url)
    result = analyze_url(url)

    # 3. Save to history (keep only last 10)
    scan_history.insert(0, {
        "url":     result["url"],
        "verdict": result["verdict"],
        "score":   result["score"],
    })
    if len(scan_history) > 10:
        scan_history.pop()

    # 4. Return full result
    return jsonify(result)


@app.route('/history', methods=['GET'])
def history():
    """
    Returns the last 10 analyzed URLs (most recent first).
    Resets when the server restarts — this is in-memory only.
    """
    return jsonify({"history": scan_history, "count": len(scan_history)})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n Phishing Detector API")
    print(" Running at: http://localhost:5000")
    print(" Endpoints:")
    print("   GET  /health")
    print("   POST /analyze   body: { url: '...' }")
    print("   GET  /history\n")
    app.run(debug=True, port=5000)
