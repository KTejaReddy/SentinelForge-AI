# Limitations

- Application did not start; dynamic/browser/fuzz steps will be limited
- Trivy unavailable - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
- OSV-Scanner unavailable - https://github.com/google/osv-scanner/releases (official binaries) | scoop install osv-scanner
- Gitleaks unavailable - used built-in regex secret scanner
- No project-native test command detected
- Dynamic testing skipped (disabled or app not running)
- Browser testing skipped (disabled or app not running)
- Root Cause Agent: rate limited (429)
- Auto-repair skipped: application not running, cannot reproduce

## Security boundary

All active testing was restricted to the uploaded project and its sandboxed runtime. No arbitrary external targets were tested.