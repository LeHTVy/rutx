# 🚀 Integrated Security Agent v2.0 - Nikto Edition

## ✨ Tính năng mới

Chương trình đã được nâng cấp thành công với **Nikto Web Scanner**!

### Trước đây (v1.0):
- ✅ Nmap (18 tools) - Network scanning

### Bây giờ (v2.0):
- ✅ Nmap (18 tools) - Network scanning
- ✅ **Nikto (10 tools) - Web vulnerability scanning** 🆕
- ✅ **AI intelligent tool selection** 🆕
- ✅ **English output for professional reports** 🆕

---

## 🎯 Cách hoạt động

```
┌─────────────────────────────────────────────────────┐
│  User nhập prompt (Vietnamese hoặc English)         │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│  Ollama AI (llama3.2:3b) phân tích ngữ cảnh        │
│  - Phát hiện keywords                               │
│  - Xác định mục đích scan                          │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│  Chọn tool thông minh:                             │
│  ├─ "web", "HTTP" → Nikto                          │
│  ├─ "port", "network" → Nmap                       │
│  └─ "comprehensive" → Both Nmap + Nikto            │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│  Thực thi scan                                     │
│  - Nmap: Network reconnaissance                    │
│  - Nikto: Web vulnerability detection              │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│  Trả kết quả (ENGLISH)                             │
│  - Findings & vulnerabilities                       │
│  - Risk assessment                                  │
│  - Recommendations                                  │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Files đã tạo/cập nhật

### ✅ Core Files (Updated/Created)

1. **nikto_tools.py** 🆕
   - 10 Nikto scanning functions
   - Tool definitions for Ollama
   - Execute dispatcher

2. **integrated_security_agent.py** (UPDATED)
   - Import Nikto tools
   - Unified tool dispatcher
   - Enhanced system prompts
   - Intelligent tool selection

3. **nmap_tools.py** (Existing, no changes)
   - 18 Nmap scanning functions

### 📚 Documentation Files (Created)

4. **examples_usage.md** 🆕
   - English usage guide
   - 10+ example scenarios
   - Installation instructions

5. **HUONG_DAN.md** 🆕
   - Vietnamese user guide
   - Ví dụ chi tiết
   - Tips & tricks

6. **demo_scenarios.py** 🆕
   - 10 test scenarios
   - Quick test commands
   - Expected behavior

7. **CHANGELOG.md** 🆕
   - Version history
   - Feature documentation

8. **README_NIKTO.md** 🆕
   - This file
   - Quick start guide

---

## 🚀 Quick Start

### Bước 1: Kiểm tra dependencies

```bash
# Check Nmap
nmap --version

# Check Nikto
nikto -Version

# Check Ollama
ollama list
```

### Bước 2: Cài Nikto (nếu chưa có)

**Windows:**
```bash
# Download: https://github.com/sullo/nikto
# Giải nén và thêm vào PATH
```

**Linux:**
```bash
sudo apt-get update
sudo apt-get install nikto
```

### Bước 3: Chạy agent

```bash
python integrated_security_agent.py
```

---

## 💡 Ví dụ sử dụng

### Ví dụ 1: Quét network (Nmap)

```
[Command]: Tìm các thiết bị trong mạng 192.168.1.0/24
```

**Kết quả:**
```
I'll discover live hosts in the network 192.168.1.0/24...

[Nmap ping scan results]
Found 5 live hosts:
- 192.168.1.1 (Gateway)
- 192.168.1.10
- 192.168.1.50
- 192.168.1.100
- 192.168.1.200

Recommendation: Perform service detection on discovered hosts.
```

---

### Ví dụ 2: Quét web vulnerability (Nikto)

```
[Command]: Quét lỗ hổng web của 192.168.1.100
```

**Kết quả:**
```
I'll perform web vulnerability scanning on 192.168.1.100...

[Nikto scan results]
Target: 192.168.1.100:80

Findings:
1. Server: Apache/2.4.41 (Ubuntu)
   Severity: Low
   Issue: Server version disclosure

2. Missing Headers:
   - X-Frame-Options (Clickjacking protection)
   - X-Content-Type-Options
   - Strict-Transport-Security (HSTS)
   Severity: Medium

3. Directory Listing: /backup/
   Severity: Medium
   Risk: Information disclosure

4. Admin Panel: /admin/login.php
   Severity: High
   Risk: Potential brute force target

Overall Risk: MEDIUM-HIGH

Recommendations:
1. Disable server version in Apache config
2. Implement security headers
3. Disable directory listing
4. Protect admin panel with IP whitelist
5. Implement rate limiting for login attempts
```

---

### Ví dụ 3: Comprehensive scan (Both tools)

```
[Command]: Quét toàn diện 192.168.1.100
```

**Kết quả:**
```
I'll perform comprehensive security assessment on 192.168.1.100...

=== NETWORK RECONNAISSANCE (Nmap) ===
Host: 192.168.1.100
Status: UP
Latency: 2.5ms

Open Ports:
- 22/tcp   SSH     OpenSSH 8.2p1 Ubuntu
- 80/tcp   HTTP    Apache 2.4.41
- 443/tcp  HTTPS   Apache 2.4.41

OS Detection: Linux 5.4.x
Device Type: General purpose

=== WEB VULNERABILITY ASSESSMENT (Nikto) ===

Port 80 (HTTP):
- Missing security headers
- Outdated jQuery (1.11.0)
- TRACE method enabled
- Admin panel accessible

Port 443 (HTTPS):
- SSL Certificate: Valid
- TLS Version: TLSv1.2, TLSv1.3
- Cipher Strength: Strong
- Same vulnerabilities as port 80

=== RISK ASSESSMENT ===
Overall Risk: MEDIUM-HIGH

Critical Issues: 0
High: 2
Medium: 5
Low: 3

=== RECOMMENDATIONS ===
Immediate Actions:
1. Patch Apache to latest version
2. Update jQuery library
3. Disable TRACE method
4. Implement WAF for admin panel

Medium Priority:
5. Add security headers
6. Enable HSTS on HTTPS
7. Implement CSP policy

Low Priority:
8. Disable server version disclosure
9. Review SSL cipher suites
10. Enable audit logging

=== COMPLIANCE ===
OWASP Top 10:
- A5: Security Misconfiguration ⚠️
- A9: Using Components with Known Vulnerabilities ⚠️

Next Steps:
- Apply security patches
- Implement monitoring
- Schedule regular scans
```

---

## 🎓 Tool Selection Examples

| Prompt (Vietnamese) | Tools Selected | Reason |
|---------------------|----------------|--------|
| "Quét port của 192.168.1.1" | `nmap_quick_scan` | Keyword: "port" |
| "Check web security của localhost" | `nikto_scan` | Keyword: "web security" |
| "Scan lỗ hổng HTTPS của example.com" | `nikto_ssl_scan` | Keywords: "HTTPS", "lỗ hổng" |
| "Tìm thiết bị trong mạng" | `nmap_ping_scan` | Keywords: "thiết bị", "mạng" |
| "Quét toàn diện 10.0.0.1" | `nmap_aggressive_scan` + `nikto_full_scan` | Keyword: "toàn diện" |
| "Kiểm tra XSS trên website" | `nikto_vulnerability_scan` | Keyword: "XSS" |

---

## 🎯 Các lệnh có sẵn

### Interactive Mode (Recommended)
```bash
python integrated_security_agent.py
```

### Command Line Mode
```bash
# Investigate IP
python integrated_security_agent.py investigate 192.168.1.100

# Scan network
python integrated_security_agent.py scan 192.168.1.0/24

# Custom task
python integrated_security_agent.py custom "Your custom prompt here"
```

### Demo Mode
```bash
# Show all example scenarios
python demo_scenarios.py
```

---

## 📊 Tool Comparison

| Feature | Nmap | Nikto |
|---------|------|-------|
| **Purpose** | Network reconnaissance | Web vulnerability |
| **Speed** | Fast (seconds-minutes) | Slower (5-30 min) |
| **Depth** | Port, Service, OS | HTTP, HTTPS, Web apps |
| **Use Case** | Infrastructure mapping | Web security audit |
| **Output** | Port lists, versions | Vulnerabilities, risks |
| **Best For** | Discovery, enumeration | Vulnerability assessment |

### When to use what?

**Use Nmap when:**
- Finding live hosts
- Discovering open ports
- Identifying services
- OS fingerprinting
- Network mapping

**Use Nikto when:**
- Testing web applications
- Finding web misconfigurations
- Checking HTTP headers
- Detecting known vulnerabilities
- SSL/TLS testing

**Use Both when:**
- Comprehensive security assessment
- Unknown target (need full picture)
- Professional pentest report
- Compliance requirements

---

## ⚙️ Configuration

### Model Settings (in integrated_security_agent.py)
```python
OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2:3b"
```

### Timeout Settings
- Nmap: 600 seconds (10 minutes)
- Nikto: 1800 seconds (30 minutes)
- Ollama: 300 seconds (5 minutes)

### Max Iterations
- Agent loop: 15 iterations
- Prevents infinite loops

---

## 🐛 Troubleshooting

### Lỗi: "nikto command not found"
```bash
# Windows: Add to PATH
setx PATH "%PATH%;C:\path\to\nikto"

# Linux: Install
sudo apt-get install nikto
```

### Lỗi: "nmap command not found"
```bash
# Install Nmap
# Windows: https://nmap.org/download.html
# Linux: sudo apt-get install nmap
```

### Lỗi: "Cannot connect to Ollama"
```bash
# Start Ollama
ollama serve

# Pull model if needed
ollama pull llama3.2:3b
```

### Agent không chọn đúng tool
- Dùng từ khóa cụ thể hơn
- Thêm "nmap" hoặc "nikto" vào prompt
- Ví dụ: "Dùng nikto quét web server"

### Scan quá lâu
- Dùng quick scan variants
- `nikto_quick_scan` thay vì `nikto_full_scan`
- `nmap_quick_scan` thay vì `nmap_aggressive_scan`

---

## 🔒 Security & Ethics

⚠️ **QUAN TRỌNG:**
- Chỉ quét hệ thống bạn có quyền
- Không quét mạng công cộng
- Tuân thủ luật pháp địa phương
- Sử dụng cho mục đích hợp pháp

**Authorized Use Cases:**
- ✅ Testing your own infrastructure
- ✅ Authorized penetration testing
- ✅ Security research (with permission)
- ✅ Educational purposes (on own systems)
- ✅ CTF competitions

**Prohibited:**
- ❌ Unauthorized network scanning
- ❌ Attacking production systems
- ❌ Scanning without permission
- ❌ Malicious activities

---

## 📈 Performance Tips

### Optimize Scan Speed
1. Use quick variants for initial recon
2. Target specific ports instead of all
3. Use parallel scanning when possible
4. Schedule long scans during off-hours

### Optimize Results Quality
1. Use full scans for critical systems
2. Combine multiple tools
3. Verify findings manually
4. Document everything

---

## 🎉 Summary

### What was achieved:

✅ **Nikto Integration Complete**
- 10 new web scanning tools
- Full integration with AI agent
- Intelligent tool selection

✅ **Enhanced Capabilities**
- Network scanning (Nmap)
- Web vulnerability scanning (Nikto)
- Combined comprehensive assessments

✅ **Professional Output**
- All results in English
- Structured reports
- Risk assessments
- Actionable recommendations

✅ **Documentation**
- Vietnamese guide (HUONG_DAN.md)
- English guide (examples_usage.md)
- Demo scenarios
- This README

---

## 📚 Next Steps

1. **Install Nikto** (if not already)
2. **Run demo scenarios** to familiarize yourself
3. **Test on safe targets** (your own systems)
4. **Read documentation** for advanced usage
5. **Start scanning!** 🚀

---

## 📞 Support Resources

- **Nmap Documentation**: https://nmap.org/docs.html
- **Nikto Documentation**: https://github.com/sullo/nikto/wiki
- **Ollama Documentation**: https://ollama.ai/docs

---

## 📝 License & Credits

- **Nmap**: GPL v2 - Gordon Lyon
- **Nikto**: GPL v2 - CIRT.net/Sullo
- **Ollama**: MIT - Ollama Team

---

**Version**: 2.0
**Status**: Production Ready ✅
**Last Updated**: 2025

**Chúc bạn scan thành công! 🎯🔒**
# rutx
