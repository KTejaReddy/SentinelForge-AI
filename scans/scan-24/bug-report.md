# Bug Report

## Unhandled exception on malformed input

- Severity: MEDIUM · Confidence: 0.65
- Reproduction: {"method": "GET", "path": "/api/search", "params": {"q": "'"}, "body": null, "expect": {"status": 500}, "steps": ["GET /api/search"], "tool": "dynamic"}

GET http://127.0.0.1:3000/api/search returns HTTP 500 with malformed parameters (payload: "'").

---
## Discovered 1 form(s) in the UI

- Severity: INFO · Confidence: 0.9
- Reproduction: {"steps": ["Browse the application"], "tool": "browser"}

Forms discovered by the browser agent: form → /search [GET] (q)

---