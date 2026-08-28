# Limitations

- Application did not start; dynamic/browser/fuzz steps will be limited
- Gitleaks unavailable or produced no output - used built-in regex secret scanner
- No project-native test command detected
- Dynamic testing skipped (disabled or app not running)
- Browser testing skipped (disabled or app not running)
- Security Agent: rate limited (429)
- Root Cause Agent: rate limited (429)
- Auto-repair skipped: application not running, cannot reproduce

## Security boundary

All active testing was restricted to the uploaded project and its sandboxed runtime. No arbitrary external targets were tested.