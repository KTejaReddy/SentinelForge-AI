# SentinelForge sandbox image — runs uploaded (untrusted) projects in
# isolation. Contains runtimes + security tools. The backend launches one
# container per scan with restricted caps, memory/CPU/pids limits, and no
# privileged mode.
FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl ca-certificates \
    gcc g++ make pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages semgrep 2>/dev/null || pip3 install --no-cache-dir semgrep

# Trivy (dependency/config scanning)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    || echo "trivy install failed (optional)"

# Gitleaks (secrets) — use a stable known-good release
ARG GITLEAKS_VER=8.18.4
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_amd64.tar.gz" \
      -o /tmp/gitleaks.tgz \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tgz \
    || echo "gitleaks install failed (optional — built-in regex scanner covers gap)"

WORKDIR /workspace
ENV PYTHONUNBUFFERED=1 \
    CI=1 \
    HOST=127.0.0.1

CMD ["/bin/bash"]
