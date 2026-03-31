 # API Reference

## Base URL
http://localhost:5000

## Endpoints

### GET /health
Returns server status.
Response: { "status": "ok", "message": "..." }

### POST /analyze
Analyzes a URL for phishing indicators.

Request body:
{
  "url": "http://example.com"
}

Response:
{
  "url":     "http://example.com",
  "score":   45,
  "verdict": "Suspicious",
  "flags": [
    { "rule": "has_suspicious_keywords", "reason": "...", "weight": 15 },
    ...
  ]
}

Verdicts:
  Safe           → score 0–29
  Suspicious     → score 30–59
  Likely Phishing→ score 60+

### GET /history
Returns last 10 analyzed URLs (most recent first).
Response: { "count": 2, "history": [...] }
