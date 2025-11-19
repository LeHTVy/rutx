# Integrated Security Agent - Usage Examples

## Overview
Hệ thống kết hợp Nmap (network scanning) và Nikto (web vulnerability scanning) với AI agent để phân tích thông minh.

## Cài đặt

### Requirements
1. **Ollama** - AI model server
   ```bash
   # Install Ollama from https://ollama.ai
   ollama pull llama3.2:3b
   ```

2. **Nmap** - Network scanner
   ```bash
   # Windows: Download from https://nmap.org/download.html
   # Linux: apt-get install nmap
   ```

3. **Nikto** - Web scanner
   ```bash
   # Windows: Download from https://github.com/sullo/nikto
   # Linux: apt-get install nikto
   ```

## Usage Modes

### 1. Interactive Mode
```bash
python integrated_security_agent.py
```

### 2. Command Line Mode

#### Investigate an IP
```bash
python integrated_security_agent.py investigate 192.168.1.100
```

#### Scan a network
```bash
python integrated_security_agent.py scan 192.168.1.0/24
```

#### Custom task
```bash
python integrated_security_agent.py custom "Scan web vulnerabilities on 192.168.1.100"
```

## Example Prompts (Vietnamese Input → English Output)

### Example 1: Network Discovery
**Input (Vietnamese):**
```
Tìm tất cả các thiết bị trong mạng 192.168.1.0/24
```

**Agent will:**
1. Use `nmap_ping_scan` to discover live hosts
2. Report results in English
3. Provide recommendations

**Expected Output (English):**
```
I'll scan the network 192.168.1.0/24 to discover live hosts...

[Scan results]
Found 5 live hosts:
- 192.168.1.1
- 192.168.1.10
- 192.168.1.50
...

Recommendation: Perform service detection on discovered hosts.
```

---

### Example 2: Web Vulnerability Scan
**Input (Vietnamese):**
```
Quét lỗ hổng web trên 192.168.1.100 port 80
```

**Agent will:**
1. Use `nikto_scan` on port 80
2. Analyze vulnerabilities
3. Report in English

**Expected Output (English):**
```
I'll perform web vulnerability scanning on 192.168.1.100:80...

[Nikto scan results]
Found vulnerabilities:
- Server: Apache/2.4.41
- Missing security headers
- Outdated software version
...

Severity: Medium
Recommendation: Update Apache and configure security headers.
```

---

### Example 3: Comprehensive Scan (Both Nmap + Nikto)
**Input (Vietnamese):**
```
Quét toàn diện 192.168.1.100
```

**Agent will:**
1. First use `nmap_quick_scan` to find open ports
2. Identify web ports (80, 443, 8080, etc.)
3. Use `nikto_scan` on web ports
4. Correlate results
5. Provide comprehensive report in English

**Expected Output (English):**
```
I'll perform comprehensive scanning on 192.168.1.100...

Step 1: Network reconnaissance
[Nmap results]
Open ports: 22, 80, 443

Step 2: Web vulnerability assessment
[Nikto results on port 80 and 443]

Analysis:
- SSH service detected (port 22)
- HTTP server with vulnerabilities (port 80)
- HTTPS with SSL issues (port 443)

Risk Level: High
Recommendations:
1. Update SSH to latest version
2. Apply security headers on HTTP
3. Renew SSL certificate
```

---

### Example 4: SSL/HTTPS Scanning
**Input (Vietnamese):**
```
Kiểm tra bảo mật HTTPS của example.com
```

**Agent will:**
1. Use `nikto_ssl_scan` on port 443
2. Check SSL/TLS configuration
3. Report vulnerabilities

---

### Example 5: Multiple Targets
**Input (Vietnamese):**
```
Quét các IP: 192.168.1.10, 192.168.1.20, 192.168.1.30
```

**Agent will:**
1. Scan each IP sequentially
2. Use appropriate tools based on findings
3. Provide comparative analysis

---

## Tool Selection Logic

The AI agent intelligently selects tools based on your prompt:

| Keywords in Prompt | Tools Selected |
|-------------------|----------------|
| "web", "HTTP", "HTTPS", "website" | Nikto tools |
| "port", "network", "hosts", "scan" | Nmap tools |
| "comprehensive", "full", "thorough" | Both Nmap + Nikto |
| IP address without context | Nmap first, then Nikto for web ports |

## Tips for Best Results

1. **Be specific**: "Scan web vulnerabilities on port 80" is better than "scan the server"
2. **Use Vietnamese freely**: The agent understands Vietnamese but outputs in English
3. **Trust the agent**: It will select the right tools automatically
4. **Review results**: Always verify findings manually for critical systems

## Important Notes

⚠️ **Output Language**: All scan results and analysis will be in **ENGLISH** regardless of input language. This ensures:
- Consistent technical documentation
- Professional security reports
- International standard compliance

⚠️ **Authorization**: Only scan networks and systems you have permission to test!

⚠️ **Performance**:
- Nmap scans: seconds to minutes depending on scope
- Nikto scans: 5-30 minutes depending on target size
- Comprehensive scans: Can take 30+ minutes

## Troubleshooting

### "nikto command not found"
- Install Nikto: https://github.com/sullo/nikto
- Add to PATH

### "nmap command not found"
- Install Nmap: https://nmap.org
- Add to PATH

### "Cannot connect to Ollama"
- Start Ollama service
- Run: `ollama serve`
- Verify: `ollama list`

### Agent not selecting right tool
- Be more specific in your prompt
- Mention "nmap" or "nikto" explicitly
- Example: "Use nikto to scan the web server"

## Example Session

```bash
$ python integrated_security_agent.py

[Command]: Quét IP 192.168.1.100 và kiểm tra web

--- Iteration 1 ---
[Agent performing 1 security operation(s)]
Operation: nmap_quick_scan
Target: {"target": "192.168.1.100"}
Status: Complete

--- Iteration 2 ---
[Agent performing 1 security operation(s)]
Operation: nikto_scan
Target: {"target": "192.168.1.100", "port": "80"}
Status: Complete

--- Iteration 3 ---
[Analysis Complete]

I've completed the security assessment of 192.168.1.100.

Network Scan Results:
- Host is up
- Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Services: OpenSSH 8.2, Apache 2.4.41

Web Vulnerability Scan Results:
- Server disclosure: Apache/2.4.41 (Ubuntu)
- Missing headers: X-Frame-Options, X-Content-Type-Options
- Directory listing enabled in /backup/
- Found admin panel at /admin/

Threat Assessment: MEDIUM
The server has several security misconfigurations that could be exploited.

Recommendations:
1. Disable server version disclosure
2. Implement security headers
3. Disable directory listing
4. Restrict access to /admin/ panel
5. Update Apache to latest version
```

## Advanced Features

### Custom Nikto Options
```python
# In code or via custom prompt
"Use nikto with tuning 9 (vulnerability tests only)"
```

### Custom Nmap Options
```python
# Stealth scan with specific ports
"Use nmap stealth scan on ports 1-1000"
```

### Combining Results
The agent automatically correlates findings from both tools for comprehensive analysis.
