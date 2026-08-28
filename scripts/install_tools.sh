#!/usr/bin/env bash
# Installer for the optional security toolchain used by SentinelForge AI.
#
#   bash scripts/install_tools.sh
#
# Supports Linux, macOS and Windows (Git Bash / MSYS2). On Windows all
# binaries are placed in <repo>/tools/bin (which the backend adds to PATH
# automatically). On Linux/macOS they go to /usr/local/bin.
#
# The platform works without these tools (built-in fallback analyzers), but
# installing them adds real depth to scans.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

BIN_DIR="$ROOT/tools/bin"
mkdir -p "$BIN_DIR"

is_win() { [[ "$OS" == MINGW* || "$OS" == MSYS* || "$OS" == CYGWIN* ]]; }

# Latest GitHub release tag for a repo, via redirect header.
latest_tag() { curl -sIL -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" | sed 's|.*/tag/||'; }

install_binary() {
  # install_binary <name> <url>
  local name="$1" url="$2"
  if command -v "$name" >/dev/null 2>&1; then
    echo "    $name already on PATH: $(command -v "$name")"
    return 0
  fi
  echo "==> Installing $name"
  local tmp; tmp="$(mktemp -d)"
  local dest
  if is_win; then dest="$BIN_DIR"; else dest="/usr/local/bin"; fi
  if (cd "$tmp" && curl -sfL -o "$name.zip" "$url" && unzip -o -q "$name.zip"); then
    if is_win; then
      mv -f "$tmp"/*.exe "$dest/$name.exe" 2>/dev/null || mv -f "$tmp"/* "$dest/$name.exe" 2>/dev/null || true
    else
      find "$tmp" -type f -name "$name" -exec mv -f {} "$dest/$name" \;
    fi
  fi
  rm -rf "$tmp"
  if command -v "$name" >/dev/null 2>&1 || [ -x "$dest/$name.exe" ] || [ -x "$dest/$name" ]; then
    echo "    $name installed -> $dest"
  else
    echo "    ! $name install failed (optional)"
  fi
}

echo "==> Installing optional security tools (OS=$OS ARCH=$ARCH)"

# --- Python tooling (into the active venv when present, else user) ----------
PY="python"
[ -x "$ROOT/.venv/Scripts/python" ] && PY="$ROOT/.venv/Scripts/python"
[ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
echo "==> Installing Python tools (semgrep, bandit, pip-audit) with $PY"
"$PY" -m pip install -q semgrep bandit pip-audit 2>/dev/null || echo "    ! python tools install failed (optional)"
# make them visible on PATH for non-venv shells
if [ -x "$ROOT/.venv/Scripts" ] && is_win; then
  export PATH="$ROOT/.venv/Scripts:$PATH"
elif [ -x "$ROOT/.venv/bin" ]; then
  export PATH="$ROOT/.venv/bin:$PATH"
fi

# --- Playwright + Chromium ----------------------------------------------------
echo "==> Installing Playwright Chromium (browser agent)"
"$PY" -m pip install -q playwright 2>/dev/null || true
"$PY" -m playwright install chromium 2>/dev/null || echo "    ! playwright browser install failed (optional)"

# --- Gitleaks -----------------------------------------------------------------
if is_win; then
  GITLEAKS_VER="$(latest_tag gitleaks/gitleaks)"
  install_binary gitleaks "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_windows_${ARCH}.zip"
else
  install_binary gitleaks "https://github.com/gitleaks/gitleaks/releases/download/$(latest_tag gitleaks/gitleaks)/gitleaks_$(latest_tag gitleaks/gitleaks | tr -d v)_${OS,,}_${ARCH}.tar.gz"
fi

# --- Trivy --------------------------------------------------------------------
if is_win; then
  TRIVY_VER="$(latest_tag aquasecurity/trivy)"
  install_binary trivy "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_windows-64bit.zip"
else
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || echo "    ! trivy install failed (optional)"
fi

# --- Nuclei -------------------------------------------------------------------
if is_win; then
  NUCLEI_VER="$(latest_tag projectdiscovery/nuclei)"
  echo "==> Installing Nuclei"
  if [ -x "$BIN_DIR/nuclei.exe" ]; then
    echo "    nuclei already installed"
  else
    tmp="$(mktemp -d)"
    if (cd "$tmp" && curl -sfL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_windows_${ARCH}.zip" && unzip -o -q nuclei.zip); then
      mv -f "$tmp"/nuclei.exe "$BIN_DIR/nuclei.exe" 2>/dev/null || true
    fi
    rm -rf "$tmp"
    if [ -x "$BIN_DIR/nuclei.exe" ]; then
      echo "    nuclei installed -> $BIN_DIR"
      echo "    NOTE: on Windows, Windows Defender may quarantine nuclei.exe (false positive)."
      echo "          Add an exclusion if needed:  Add-MpPreference -ExclusionPath '$BIN_DIR'"
    else
      echo "    ! nuclei install failed (optional, Windows Defender may have blocked it)"
    fi
  fi
else
  install_binary nuclei "https://github.com/projectdiscovery/nuclei/releases/download/$(latest_tag projectdiscovery/nuclei)/nuclei_$(latest_tag projectdiscovery/nuclei | tr -d v)_${OS,,}_${ARCH}.tar.gz"
fi

# --- ffuf ---------------------------------------------------------------------
if is_win; then
  FFUF_VER="$(latest_tag ffuf/ffuf)"
  install_binary ffuf "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_windows_${ARCH}.zip"
else
  install_binary ffuf "https://github.com/ffuf/ffuf/releases/download/$(latest_tag ffuf/ffuf)/ffuf_$(latest_tag ffuf/ffuf | tr -d v)_${OS,,}_${ARCH}.zip"
fi

# --- OSV-Scanner ---------------------------------------------------------------
if is_win; then
  OSV_VER="$(latest_tag google/osv-scanner)"
  if [ -x "$BIN_DIR/osv-scanner.exe" ]; then
    echo "    osv-scanner already installed"
  else
    echo "==> Installing OSV-Scanner"
    curl -sfL -o "$BIN_DIR/osv-scanner.exe" "https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_windows_${ARCH}.exe" \
      && echo "    osv-scanner installed -> $BIN_DIR" || echo "    ! osv-scanner install failed (optional)"
  fi
else
  curl -sfL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/$(latest_tag google/osv-scanner)/osv-scanner_$(latest_tag google/osv-scanner | tr -d v)_${OS,,}_${ARCH}" \
    && chmod +x /usr/local/bin/osv-scanner || echo "    ! osv-scanner install failed (optional)"
fi

echo ""
echo "Done. Installed toolchain:"
if is_win; then
  for t in semgrep bandit pip-audit gitleaks trivy nuclei ffuf osv-scanner; do
    if command -v "$t" >/dev/null 2>&1 || [ -x "$BIN_DIR/$t.exe" ]; then
      echo "  ✓ $t"
    else
      echo "  ✗ $t (not available)"
    fi
  done
fi
echo ""
echo "The backend detects tools automatically. Refresh the Security Tools page."
echo "Platform runs fine without these - built-in fallback analyzers cover the gaps."
