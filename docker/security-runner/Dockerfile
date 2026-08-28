# SentinelForge Security Runner
# Contains all security scanning tools in one container.
# The backend mounts the target project and runs tools against it.
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git unzip ca-certificates gnupg \
    nodejs npm \
    gcc g++ make pkg-config \
    ruby \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install --no-cache-dir semgrep bandit pip-audit safety

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_amd64.tar.gz" \
      -o /tmp/gitleaks.tgz && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm -f /tmp/gitleaks.tgz \
    || echo "gitleaks install failed (optional)"

# Install Nuclei
RUN curl -sfL https://github.com/projectdiscovery/nuclei/releases/download/v3.4.3/nuclei_3.4.3_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin && rm -f /tmp/nuclei.zip \
    || echo "nuclei install failed (optional)"

# Install ffuf
RUN curl -sfL "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
      -o /tmp/ffuf.tgz && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf && rm -f /tmp/ffuf.tgz \
    || echo "ffuf install failed (optional)"

# Install OSV-Scanner
RUN curl -sfL "https://github.com/google/osv-scanner/releases/download/v1.8.5/osv-scanner_1.8.5_linux_amd64" \
      -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner \
    || echo "osv-scanner install failed (optional)"

# Install Grype
RUN curl -sfL "https://github.com/anchore/grype/releases/download/v0.82.0/grype_0.82.0_linux_amd64.tar.gz" \
      -o /tmp/grype.tgz && tar -xzf /tmp/grype.tgz -C /usr/local/bin grype && rm -f /tmp/grype.tgz \
    || echo "grype install failed (optional)"

# Checkov (optional - large install)
RUN pip install --no-cache-dir checkov 2>/dev/null || echo "checkov install failed (optional)"

# Hadolint (optional)
RUN curl -sfL "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64" \
      -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint \
    || echo "hadolint install failed (optional)"

# ShellCheck (optional)
RUN apt-get update && apt-get install -y --no-install-recommends shellcheck 2>/dev/null || echo "shellcheck install failed (optional)" \
    && rm -rf /var/lib/apt/lists/*

# Go security tools (optional)
RUN curl -sfL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | tar -C /usr/local -xz 2>/dev/null || true \
    && export PATH=$PATH:/usr/local/go/bin:/root/go/bin \
    && go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null || echo "gosec install failed (optional)"

WORKDIR /workspace

# Tool verification script
RUN echo '#!/bin/bash\necho "=== Security Runner Tools ==="\nsemgrep --version 2>/dev/null && echo "✅ Semgrep" || echo "❌ Semgrep"\nbandit --version 2>/dev/null && echo "✅ Bandit" || echo "❌ Bandit"\ntrivy --version 2>/dev/null && echo "✅ Trivy" || echo "❌ Trivy"\ngitleaks version 2>/dev/null && echo "✅ Gitleaks" || echo "❌ Gitleaks"\nnuclei -version 2>/dev/null && echo "✅ Nuclei" || echo "❌ Nuclei"\nffuf -V 2>/dev/null && echo "✅ ffuf" || echo "❌ ffuf"\nosv-scanner --version 2>/dev/null && echo "✅ OSV-Scanner" || echo "❌ OSV-Scanner"\ngrype version 2>/dev/null && echo "✅ Grype" || echo "❌ Grype"\necho "=============================="' > /usr/local/bin/verify-tools.sh && chmod +x /usr/local/bin/verify-tools.sh

CMD ["/bin/bash"]
