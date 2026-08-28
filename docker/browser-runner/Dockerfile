# SentinelForge Browser Runner
# Playwright + Chromium for browser-based security testing
FROM mcr.microsoft.com/playwright:v1.48.0-jammy

WORKDIR /workspace

# Install additional dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js tools for web testing
RUN npm install -g puppeteer-core axios

# Verify Playwright installation
RUN npx playwright install --with-deps chromium 2>/dev/null || true

# Create a test script
RUN echo '#!/bin/bash\necho "=== Browser Runner ==="\necho "Playwright installed"\nnpx playwright install --list 2>/dev/null | head -5\necho "======================"' > /usr/local/bin/verify-browser.sh && chmod +x /usr/local/bin/verify-browser.sh

CMD ["/bin/bash"]
