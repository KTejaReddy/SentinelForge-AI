# Limitations

- Trivy unavailable - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
- OSV-Scanner unavailable - https://github.com/google/osv-scanner/releases (official binaries) | scoop install osv-scanner
- Gitleaks unavailable - used built-in regex secret scanner
- OWASP ZAP unavailable - docker pull ghcr.io/zaproxy/zaproxy  (large image) - or the built-in Dynamic Probes analyzer covers passive checks
- Root Cause Agent: rate limited (429)
- Repair Agent: rate limited (429)

## Security boundary

All active testing was restricted to the uploaded project and its sandboxed runtime. No arbitrary external targets were tested.