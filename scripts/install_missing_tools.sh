#!/bin/bash
# Install Missing Security Tools
# Fixes installation issues for tools not available via standard repos

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Installing Missing Security Tools                     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. CrackMapExec (NetExec - fork)
echo -e "${BLUE}[1/6]${NC} Installing CrackMapExec (NetExec)..."
if command_exists crackmapexec || command_exists netexec; then
    echo -e "${GREEN}✓${NC} crackmapexec/netexec already installed"
else
    echo -e "${YELLOW}⚠${NC}  crackmapexec removed from PyPI, installing NetExec (fork)..."
    # Try pipx first
    if pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null; then
        echo -e "${GREEN}✓${NC} NetExec installed via pipx"
        # Create alias for crackmapexec
        sudo ln -sf ~/.local/bin/netexec /usr/local/bin/crackmapexec 2>/dev/null || true
    else
        # Fallback: install in venv
        if [ -f /opt/snode/venv/bin/activate ]; then
            source /opt/snode/venv/bin/activate
            pip install git+https://github.com/Pennyw0rth/NetExec >/dev/null 2>&1
            echo -e "${GREEN}✓${NC} NetExec installed in venv"
            sudo ln -sf /opt/snode/venv/bin/netexec /usr/local/bin/crackmapexec 2>/dev/null || true
        else
            echo -e "${RED}✗${NC} Failed to install NetExec"
        fi
    fi
fi

# 2. ExploitDB (searchsploit)
echo -e "${BLUE}[2/6]${NC} Installing ExploitDB (searchsploit)..."
if command_exists searchsploit; then
    echo -e "${GREEN}✓${NC} searchsploit already installed"
else
    echo -e "${YELLOW}⚠${NC}  Installing exploitdb..."
    cd /tmp
    if [ -d /opt/exploitdb ]; then
        sudo rm -rf /opt/exploitdb
    fi
    sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb >/dev/null 2>&1
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    echo -e "${GREEN}✓${NC} searchsploit installed"
fi

# 3. Recon-ng
echo -e "${BLUE}[3/6]${NC} Installing recon-ng..."
if command_exists recon-ng; then
    echo -e "${GREEN}✓${NC} recon-ng already installed"
else
    echo -e "${YELLOW}⚠${NC}  Installing recon-ng..."
    cd /tmp
    if [ -d /opt/recon-ng ]; then
        sudo rm -rf /opt/recon-ng
    fi
    sudo git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng >/dev/null 2>&1
    cd /opt/recon-ng
    
    # Install requirements in venv or with --break-system-packages
    if [ -f /opt/snode/venv/bin/activate ]; then
        source /opt/snode/venv/bin/activate
        pip install -r REQUIREMENTS >/dev/null 2>&1 || true
    else
        sudo pip3 install --break-system-packages -r REQUIREMENTS >/dev/null 2>&1 || true
    fi
    
    sudo ln -sf /opt/recon-ng/recon-ng /usr/local/bin/recon-ng
    echo -e "${GREEN}✓${NC} recon-ng installed"
fi

# 4. Enum4linux
echo -e "${BLUE}[4/6]${NC} Installing enum4linux..."
if command_exists enum4linux || command_exists enum4linux-ng; then
    echo -e "${GREEN}✓${NC} enum4linux already installed"
else
    # Try apt first
    if sudo apt install -y enum4linux >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} enum4linux installed via apt"
    else
        # Install enum4linux-ng from GitHub
        echo -e "${YELLOW}⚠${NC}  Installing enum4linux-ng from GitHub..."
        cd /tmp
        if [ -d /opt/enum4linux-ng ]; then
            sudo rm -rf /opt/enum4linux-ng
        fi
        sudo git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng >/dev/null 2>&1
        cd /opt/enum4linux-ng
        
        # Install requirements
        if [ -f /opt/snode/venv/bin/activate ]; then
            source /opt/snode/venv/bin/activate
            pip install -r requirements.txt >/dev/null 2>&1 || true
        else
            sudo pip3 install --break-system-packages -r requirements.txt >/dev/null 2>&1 || true
        fi
        
        sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
        sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux
        echo -e "${GREEN}✓${NC} enum4linux-ng installed"
    fi
fi

# 5. Responder
echo -e "${BLUE}[5/6]${NC} Installing responder..."
if command_exists responder; then
    echo -e "${GREEN}✓${NC} responder already installed"
else
    echo -e "${YELLOW}⚠${NC}  Installing responder..."
    cd /tmp
    if [ -d /opt/responder ]; then
        sudo rm -rf /opt/responder
    fi
    sudo git clone https://github.com/lgandx/Responder.git /opt/responder >/dev/null 2>&1
    sudo ln -sf /opt/responder/Responder.py /usr/local/bin/responder
    sudo chmod +x /opt/responder/Responder.py
    echo -e "${GREEN}✓${NC} responder installed"
fi

# 6. Cloudflared
echo -e "${BLUE}[6/6]${NC} Installing cloudflared..."
if command_exists cloudflared; then
    echo -e "${GREEN}✓${NC} cloudflared already installed"
else
    echo -e "${YELLOW}⚠${NC}  Installing cloudflared..."
    cd /tmp
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -O /tmp/cloudflared.deb
    if [ -f /tmp/cloudflared.deb ]; then
        sudo dpkg -i /tmp/cloudflared.deb >/dev/null 2>&1 || sudo apt-get install -f -y >/dev/null 2>&1
        rm -f /tmp/cloudflared.deb
        echo -e "${GREEN}✓${NC} cloudflared installed"
    else
        echo -e "${RED}✗${NC} Failed to download cloudflared"
    fi
fi

# Summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Installation Summary                     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOOLS=("crackmapexec" "netexec" "searchsploit" "recon-ng" "enum4linux" "enum4linux-ng" "responder" "cloudflared")
missing=()

for tool in "${TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool"
    else
        echo -e "${RED}✗${NC} $tool (MISSING)"
        missing+=("$tool")
    fi
done

echo ""
if [ ${#missing[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All tools installed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  Some tools are missing: ${missing[*]}${NC}"
fi

echo ""
echo -e "${BLUE}Note:${NC}"
echo -e "  - crackmapexec: Use 'netexec' (alias created)"
echo -e "  - enum4linux: Use 'enum4linux-ng' (newer version)"
echo ""
