#!/usr/bin/env bash
#
# install-tools.sh — install the external CLI tools ReconEcoboost shells out to.
#
# These are NOT Python packages and do NOT live in the venv: they are Go/Rust
# binaries resolved from $PATH at runtime (see config/tools.yaml). The Python deps
# (incl. arjun) come from `pip install -e .` instead — run that separately.
#
# Idempotent: already-present tools are skipped. Re-run any time to add what's missing.
#
# Requirements: Go (>=1.21) for the `go install` tools; curl + unzip for feroxbuster;
# apt/gem for whatweb. Go binaries land in $(go env GOPATH)/bin (usually ~/go/bin) and
# feroxbuster in ~/.local/bin — make sure BOTH are on your PATH:
#   export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

set -uo pipefail

GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
skip() { printf '  \033[33m•\033[0m %s (already present)\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

go_install() {  # name  module@version
    local name="$1" module="$2"
    # Check the Go install target specifically, NOT `command -v` — a venv Python shim
    # (e.g. the `httpx` library's CLI) can shadow the real Go binary on PATH and trick
    # us into skipping it, leaving the ProjectDiscovery binary uninstalled.
    if [ -x "$GOBIN_DIR/$name" ]; then skip "$name"; return; fi
    if ! have go; then fail "$name — Go not installed (https://go.dev/dl/)"; return; fi
    echo "  installing $name ..."
    if GOBIN="$GOBIN_DIR" go install -v "$module" >/dev/null 2>&1; then
        ok "$name"
    else
        fail "$name (go install failed: $module)"
    fi
}

echo "ReconEcoboost — external tool installer"
echo

echo "ProjectDiscovery + Go tools:"
go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install dnsx      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install alterx    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
go_install nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install gau       "github.com/lc/gau/v2/cmd/gau@latest"
go_install ffuf      "github.com/ffuf/ffuf/v2@latest"
go_install tlsx      "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
go_install github-subdomains "github.com/gwen001/github-subdomains@latest"

echo
echo "feroxbuster (recursive dir brute-force):"
if have feroxbuster; then
    skip feroxbuster
else
    if have curl && have unzip; then
        tmp="$(mktemp -d)"
        if curl -sSL "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" \
                -o "$tmp/ferox.zip" && unzip -o "$tmp/ferox.zip" -d "$tmp" >/dev/null 2>&1; then
            install -m 0755 "$tmp/feroxbuster" "$LOCAL_BIN/feroxbuster" && ok "feroxbuster -> $LOCAL_BIN"
        else
            fail "feroxbuster (download/unzip failed — see github.com/epi052/feroxbuster)"
        fi
        rm -rf "$tmp"
    else
        fail "feroxbuster — need curl + unzip (or install via cargo/apt/snap)"
    fi
fi

echo
echo "trufflehog (GitHub leaked-secret scan):"
if have trufflehog; then
    skip trufflehog
elif have curl; then
    echo "  installing trufflehog ..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | sh -s -- -b "$LOCAL_BIN" >/dev/null 2>&1; then
        ok "trufflehog -> $LOCAL_BIN"
    else
        fail "trufflehog (installer failed — see github.com/trufflesecurity/trufflehog)"
    fi
else
    fail "trufflehog — need curl (or 'go install github.com/trufflesecurity/trufflehog/v3@latest')"
fi

echo
echo "whatweb (tech fingerprint):"
if have whatweb; then
    skip whatweb
elif have apt-get; then
    echo "  installing via apt (needs sudo) ..."
    if sudo apt-get install -y whatweb >/dev/null 2>&1; then ok whatweb; else fail "whatweb (apt failed; try: gem install whatweb)"; fi
else
    fail "whatweb — install via your package manager or 'gem install whatweb'"
fi

echo
echo "Python tools (arjun, framework) come from the venv:"
echo "  python -m venv .venv && . .venv/bin/activate && pip install -e ."
echo
echo "Done. Verify everything resolves:"
echo "  for t in subfinder httpx katana dnsx alterx nuclei gau ffuf feroxbuster tlsx github-subdomains trufflehog whatweb arjun; do \\"
echo "      command -v \$t >/dev/null && echo \"ok \$t\" || echo \"MISSING \$t\"; done"
