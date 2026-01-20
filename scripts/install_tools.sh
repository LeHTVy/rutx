#!/bin/bash
# SNODE Security Tools Installation Script
# =========================================
# Installs all security tools required by SNODE AI Agent
# Supports: Ubuntu/Debian Linux

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}⚠️  Running as root. Some tools may need sudo for installation.${NC}"
fi

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     SNODE Security Tools Installation Script                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install if not exists
install_if_missing() {
    local cmd=$1
    local install_cmd=$2
    
    if command_exists "$cmd"; then
        echo -e "${GREEN}✓${NC} $cmd is already installed"
        return 0
    else
        echo -e "${YELLOW}⚠${NC}  Installing $cmd..."
        eval "$install_cmd"
        if command_exists "$cmd"; then
            echo -e "${GREEN}✓${NC} $cmd installed successfully"
            return 0
        else
            echo -e "${RED}✗${NC} Failed to install $cmd"
            return 1
        fi
    fi
}

# Update package list
echo -e "${BLUE}[1/8]${NC} Updating package list..."
sudo apt update -qq

# Install basic dependencies
echo -e "${BLUE}[2/8]${NC} Installing basic dependencies..."
sudo apt install -y \
    curl \
    wget \
    git \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    ruby \
    ruby-dev \
    gem \
    snapd \
    ca-certificates \
    gnupg \
    lsb-release \
    > /dev/null 2>&1

# Install Go if not present
echo -e "${BLUE}[3/8]${NC} Checking Go installation..."
if ! command_exists go; then
    echo -e "${YELLOW}⚠${NC}  Go not found. Installing Go 1.21+..."
    GO_VERSION="1.21.5"
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    
    # Add Go to PATH
    if ! grep -q 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:~/go/bin
    
    echo -e "${GREEN}✓${NC} Go installed. Version: $(go version)"
else
    echo -e "${GREEN}✓${NC} Go is already installed. Version: $(go version)"
    export PATH=$PATH:$(go env GOPATH)/bin
fi

# Install pipx for isolated Python tools
echo -e "${BLUE}[4/8]${NC} Installing pipx..."
if ! command_exists pipx; then
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    export PATH=$PATH:~/.local/bin
fi

# ============================================================
# APT PACKAGES (System packages)
# ============================================================
echo -e "${BLUE}[5/8]${NC} Installing APT packages..."

APT_TOOLS=(
    "whois"
    "dnsutils"  # dig
    "nmap"
    "masscan"
    "nikto"
    "sqlmap"
    "gobuster"
    "whatweb"
    "hydra"
    "medusa"
    "john"
    "hashcat"
    "crackmapexec"
    "metasploit-framework"
    "exploitdb"  # searchsploit
    "dnsrecon"
    "recon-ng"
    "enum4linux"
    "nbtscan"
    "smbclient"
    "netcat-openbsd"  # nc
    "responder"
    "tcpdump"
    "cloudflared"
    "docker.io"
)

for tool in "${APT_TOOLS[@]}"; do
    if dpkg -l | grep -q "^ii  $tool "; then
        echo -e "${GREEN}✓${NC} $tool is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing $tool..."
        sudo apt install -y "$tool" > /dev/null 2>&1 || echo -e "${RED}✗${NC} Failed to install $tool (may not be available)"
    fi
done

# ============================================================
# GO TOOLS (ProjectDiscovery & others)
# ============================================================
echo -e "${BLUE}[6/8]${NC} Installing Go tools..."

# Ensure Go bin is in PATH
export PATH=$PATH:~/go/bin
mkdir -p ~/go/bin

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/gitleaks/gitleaks/v8@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    tool_name=$(basename "$tool" | cut -d'/' -f1)
    if command_exists "$tool_name"; then
        echo -e "${GREEN}✓${NC} $tool_name is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing $tool_name..."
        go install "$tool" 2>&1 | grep -v "go: downloading" || true
        if command_exists "$tool_name"; then
            echo -e "${GREEN}✓${NC} $tool_name installed successfully"
        else
            echo -e "${RED}✗${NC} Failed to install $tool_name"
        fi
    fi
done

# Install nuclei templates
if command_exists nuclei; then
    echo -e "${YELLOW}⚠${NC}  Updating nuclei templates..."
    nuclei -update-templates -silent > /dev/null 2>&1 || true
    echo -e "${GREEN}✓${NC} Nuclei templates updated"
fi

# ============================================================
# PYTHON TOOLS (pip/pipx)
# ============================================================
echo -e "${BLUE}[7/8]${NC} Installing Python tools..."

# pipx tools (isolated)
PIPX_TOOLS=(
    "bbot"
)

for tool in "${PIPX_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing $tool via pipx..."
        pipx install "$tool" > /dev/null 2>&1 || true
    fi
done

# pip tools (global or user)
PIP_TOOLS=(
    "git+https://github.com/laramies/theHarvester.git"
    "wafw00f"
    "arjun"
    "dirsearch"
    "fierce"
    "spiderfoot"
    "emailharvester"
    "shodan"
    "trufflehog"
    "prowler"
    "scoutsuite"
)

for tool in "${PIP_TOOLS[@]}"; do
    tool_name=$(echo "$tool" | sed 's/.*\///' | sed 's/@.*//' | sed 's/\.git//')
    if command_exists "$tool_name"; then
        echo -e "${GREEN}✓${NC} $tool_name is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing $tool_name..."
        pip3 install --user "$tool" > /dev/null 2>&1 || true
    fi
done

# ============================================================
# SNAP PACKAGES
# ============================================================
echo -e "${BLUE}[8/8]${NC} Installing Snap packages..."

SNAP_TOOLS=(
    "amass"
)

for tool in "${SNAP_TOOLS[@]}"; do
    if snap list | grep -q "^$tool "; then
        echo -e "${GREEN}✓${NC} $tool is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing $tool via snap..."
        sudo snap install "$tool" > /dev/null 2>&1 || true
    fi
done

# ============================================================
# RUBY GEMS
# ============================================================
echo -e "${BLUE}[9/8]${NC} Installing Ruby gems..."

if command_exists gem; then
    if gem list | grep -q "^wpscan "; then
        echo -e "${GREEN}✓${NC} wpscan is already installed"
    else
        echo -e "${YELLOW}⚠${NC}  Installing wpscan..."
        sudo gem install wpscan > /dev/null 2>&1 || true
    fi
else
    echo -e "${YELLOW}⚠${NC}  Ruby/gem not available, skipping wpscan"
fi

# ============================================================
# VERIFICATION
# ============================================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Installation Summary                     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# List of critical tools to verify
CRITICAL_TOOLS=(
    "subfinder"
    "httpx"
    "nuclei"
    "nmap"
    "whois"
    "dig"
    "amass"
    "theHarvester"
    "nikto"
    "sqlmap"
    "gobuster"
    "ffuf"
    "hydra"
    "masscan"
)

echo -e "${BLUE}Verifying critical tools...${NC}"
missing_tools=()
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool"
    else
        echo -e "${RED}✗${NC} $tool (MISSING)"
        missing_tools+=("$tool")
    fi
done

echo ""
if [ ${#missing_tools[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All critical tools are installed!${NC}"
else
    echo -e "${YELLOW}⚠️  Some tools are missing: ${missing_tools[*]}${NC}"
    echo -e "${YELLOW}   You may need to install them manually or check your PATH.${NC}"
fi

# ============================================================
# POST-INSTALLATION
# ============================================================
echo ""
echo -e "${BLUE}Post-installation steps:${NC}"

# Initialize nuclei templates
if command_exists nuclei; then
    echo -e "${YELLOW}⚠${NC}  Initializing nuclei templates (first run)..."
    nuclei -update-templates -silent > /dev/null 2>&1 || true
fi

# Initialize shodan (if installed)
if command_exists shodan; then
    if [ ! -f ~/.shodan/api_key ]; then
        echo -e "${YELLOW}⚠${NC}  Shodan installed but not initialized."
        echo -e "${YELLOW}   Run: shodan init YOUR_API_KEY${NC}"
    fi
fi

# SecurityTrails API key reminder
echo -e "${YELLOW}⚠${NC}  SecurityTrails: Set SECURITYTRAILS_API_KEY in .env file"
echo -e "${YELLOW}   Get free key: https://securitytrails.com/app/signup${NC}"

# Add Go bin to PATH reminder
if ! grep -q 'export PATH=$PATH:~/go/bin' ~/.bashrc 2>/dev/null; then
    echo -e "${YELLOW}⚠${NC}  Add Go tools to PATH:"
    echo -e "${YELLOW}   Add to ~/.bashrc: export PATH=\$PATH:~/go/bin${NC}"
fi

echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
echo -e "${BLUE}   Restart your terminal or run: source ~/.bashrc${NC}"
echo ""
