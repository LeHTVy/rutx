# 🔧 SNODE Security Tools Installation Guide

Script tự động cài đặt tất cả security tools cần thiết cho SNODE AI Agent.

## 📋 Yêu cầu

- Ubuntu/Debian Linux
- Quyền sudo
- Kết nối internet

## 🚀 Cách sử dụng

### Cách 1: Chạy trực tiếp

```bash
cd /home/hellrazor/rutx
bash install_tools.sh
```

### Cách 2: Chạy với quyền root (nếu cần)

```bash
sudo bash install_tools.sh
```

## 📦 Tools được cài đặt

### APT Packages (System packages)
- `whois` - Domain registration lookup
- `dnsutils` - DNS tools (dig)
- `nmap` - Port scanner
- `masscan` - Fast port scanner
- `nikto` - Web vulnerability scanner
- `sqlmap` - SQL injection scanner
- `gobuster` - Directory/DNS brute force
- `whatweb` - Web technology fingerprinting
- `hydra` - Network login cracker
- `medusa` - Parallel password cracker
- `john` - Password hash cracker
- `hashcat` - GPU password cracker
- `crackmapexec` - Network protocol attacks
- `metasploit-framework` - Exploitation framework
- `exploitdb` - Exploit database (searchsploit)
- `dnsrecon` - DNS enumeration
- `recon-ng` - OSINT framework
- `enum4linux` - SMB/Samba enumeration
- `nbtscan` - NetBIOS scanner
- `smbclient` - SMB client
- `netcat-openbsd` - Network utility (nc)
- `responder` - LLMNR/NBT-NS poisoner
- `tcpdump` - Packet capture
- `cloudflared` - Cloudflare tunnel
- `docker.io` - Container runtime

### Go Tools (ProjectDiscovery & others)
- `subfinder` - Subdomain enumeration
- `httpx` - HTTP probing
- `nuclei` - Template-based vulnerability scanner
- `katana` - Web crawler
- `ffuf` - Web fuzzer
- `gitleaks` - Git secrets scanner

### Python Tools (pip/pipx)
- `bbot` - All-in-one reconnaissance (pipx)
- `theHarvester` - Email/subdomain harvesting
- `wafw00f` - WAF detection
- `arjun` - HTTP parameter discovery
- `dirsearch` - Web path scanner
- `fierce` - DNS reconnaissance
- `spiderfoot` - OSINT automation
- `emailharvester` - Email discovery
- `shodan` - Internet search engine
- `trufflehog` - Secrets detection
- `prowler` - AWS security auditor
- `scoutsuite` - Multi-cloud security auditing

### Snap Packages
- `amass` - Advanced subdomain enumeration

### Ruby Gems
- `wpscan` - WordPress vulnerability scanner

## ⚙️ Cấu hình sau khi cài đặt

### 1. Shodan API Key

```bash
shodan init YOUR_API_KEY
```

Lấy API key miễn phí tại: https://account.shodan.io/

### 2. SecurityTrails API Key

Thêm vào file `.env`:

```bash
SECURITYTRAILS_API_KEY=your_api_key_here
```

Lấy API key miễn phí tại: https://securitytrails.com/app/signup (50 queries/month)

### 3. Go Tools PATH

Nếu Go tools không được tìm thấy, thêm vào `~/.bashrc`:

```bash
export PATH=$PATH:~/go/bin
export PATH=$PATH:~/.local/bin  # For pipx tools
```

Sau đó reload:

```bash
source ~/.bashrc
```

### 4. Nuclei Templates

Nuclei templates sẽ được tự động cập nhật khi chạy script. Nếu cần cập nhật thủ công:

```bash
nuclei -update-templates
```

## ✅ Kiểm tra cài đặt

Sau khi chạy script, kiểm tra các tools quan trọng:

```bash
# Kiểm tra Go tools
subfinder -version
httpx -version
nuclei -version

# Kiểm tra system tools
nmap --version
whois --version
dig -v

# Kiểm tra Python tools
theHarvester --version
shodan --version
```

## 🔍 Troubleshooting

### Go tools không được tìm thấy

```bash
# Kiểm tra Go installation
go version

# Kiểm tra PATH
echo $PATH | grep go

# Thêm vào PATH nếu thiếu
export PATH=$PATH:~/go/bin
```

### Python tools không được tìm thấy

```bash
# Kiểm tra pipx
pipx list

# Kiểm tra user Python packages
python3 -m pip list --user

# Thêm vào PATH
export PATH=$PATH:~/.local/bin
```

### Một số tools cần sudo

Một số tools như `nmap -sS` (SYN scan) và `masscan` cần quyền root:

```bash
sudo nmap -sS target.com
sudo masscan -p80 target.com
```

## 📝 Lưu ý

- Script sẽ cài đặt tất cả tools có sẵn trong repositories
- Một số tools có thể không có sẵn trên một số distro
- Script sẽ bỏ qua các tools không thể cài đặt và tiếp tục
- Sau khi cài đặt, restart terminal hoặc chạy `source ~/.bashrc`

## 🎯 Tools tích hợp sẵn (không cần cài đặt)

Các tools sau đã được tích hợp sẵn trong SNODE và không cần cài đặt riêng:

- `clatscope` - Intelligent OSINT (Python-based, trong app/osint/)
- `cpanelbrute` - cPanel brute force (trong app/tools/custom/)
- `passgen` - Password generator (trong app/tools/custom/)
- `credcheck` - Credential leak checker (trong app/tools/custom/)

## 📞 Hỗ trợ

Nếu gặp vấn đề khi cài đặt, kiểm tra:

1. Log output của script để xem tool nào failed
2. Kiểm tra internet connection
3. Kiểm tra quyền sudo
4. Kiểm tra disk space
