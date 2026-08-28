# Limitations

- Trivy found no known vulnerabilities (DB may be stale or unreachable)
- Gitleaks unavailable or produced no output - used built-in regex secret scanner
- Gitleaks failed: [WinError 1920] The file cannot be accessed by the system: 'T:\\SentinelForge AI\\workspaces\\scan-1\\working-copy\\node_modules\\.bin\\mime'
- OWASP ZAP unavailable - docker pull ghcr.io/zaproxy/zaproxy  (large image) - or the built-in Dynamic Probes analyzer covers passive checks
- Security Agent: rate limited (429)
- Root Cause Agent: rate limited (429)
- Repair Agent: rate limited (429)

## Security boundary

All active testing was restricted to the uploaded project and its sandboxed runtime. No arbitrary external targets were tested.