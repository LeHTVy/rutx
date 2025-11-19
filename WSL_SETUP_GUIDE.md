# 🐧 Hướng dẫn chạy Agent từ WSL Ubuntu

## ✅ Bạn đã cài Nikto trên WSL - Tuyệt vời!

Bây giờ làm theo các bước sau để chạy agent:

---

## 📝 Bước 1: Kiểm tra Nikto

```bash
# Trong WSL Ubuntu terminal
nikto -Version

# Kết quả mong đợi:
# Nikto v2.x.x
```

✅ Nếu thấy version → OK, tiếp tục bước 2
❌ Nếu lỗi → Cài lại: `sudo apt install nikto -y`

---

## 📁 Bước 2: Truy cập thư mục dự án

```bash
# Drive E:\ của Windows = /mnt/e trong WSL
cd /mnt/e/Wireless

# Kiểm tra files
ls -la

# Bạn sẽ thấy:
# ollama_agents.py
# integrated_security_agent.py
# nmap_tools.py
# nikto_tools.py
# etc.
```

---

## 🐍 Bước 3: Cài Python và dependencies

### Check Python

```bash
python3 --version
# Nên có Python 3.8+
```

### Cài pip (nếu chưa có)

```bash
sudo apt update
sudo apt install python3-pip -y
```

### Cài requests library

```bash
pip3 install requests

# Hoặc
python3 -m pip install requests
```

---

## 🔌 Bước 4: Kết nối tới Ollama (chạy trên Windows)

### Option A: Ollama listen all interfaces (Khuyến nghị)

**Trên Windows PowerShell:**

```powershell
# Stop Ollama nếu đang chạy
taskkill /F /IM ollama.exe

# Set environment variable
setx OLLAMA_HOST "0.0.0.0:11434"

# Start Ollama
ollama serve
```

**Trong WSL:**

```bash
# Lấy IP của Windows host
export WINDOWS_HOST=$(ip route | grep default | awk '{print $3}')
echo $WINDOWS_HOST

# Test connection
curl http://$WINDOWS_HOST:11434/api/tags
```

### Option B: Dùng localhost (WSL2 auto-forward)

Nếu bạn dùng WSL2 (mặc định trên Windows 11), localhost tự động forward:

```bash
# Test
curl http://localhost:11434/api/tags

# Nếu thành công → Dùng localhost OK
```

---

## 🚀 Bước 5: Chạy agent!

### Test Nikto trước

```bash
cd /mnt/e/Wireless

# Test scan đơn giản
nikto -h example.com -Tuning 1

# Nếu chạy → OK!
```

### Chạy agent với Nikto

```bash
# Chạy agent đầy đủ (Nmap + Nikto)
python3 ollama_agents.py

# Hoặc agent SOC
python3 integrated_security_agent.py
```

---

## 💡 Ví dụ sử dụng

### Test 1: Network scan (chỉ dùng Nmap)

```bash
python3 ollama_agents.py

[You]: Scan network 192.168.1.0/24

# Agent sẽ dùng nmap (có sẵn)
```

### Test 2: Web vulnerability scan (dùng Nikto!)

```bash
python3 ollama_agents.py

[You]: Check web vulnerabilities on example.com

# Agent sẽ dùng Nikto!
```

### Test 3: Comprehensive scan

```bash
python3 ollama_agents.py

[You]: Comprehensive scan of google.com

# Agent sẽ dùng:
# 1. Nmap để tìm ports
# 2. Nikto để scan web
```

---

## 🐛 Troubleshooting

### Lỗi: "nikto command not found"

```bash
# Cài lại Nikto
sudo apt update
sudo apt install nikto -y

# Kiểm tra PATH
which nikto
# Kết quả: /usr/bin/nikto
```

---

### Lỗi: "Cannot connect to Ollama"

**Kiểm tra Ollama đang chạy trên Windows:**

```powershell
# Trên Windows
ollama list
```

**Fix connection từ WSL:**

```bash
# Option 1: Dùng Windows host IP
export WINDOWS_HOST=$(ip route | grep default | awk '{print $3}')
echo "Windows host: $WINDOWS_HOST"

# Test
curl http://$WINDOWS_HOST:11434/api/tags
```

**Nếu vẫn lỗi, update file agent:**

Sửa trong `ollama_agents.py` hoặc `integrated_security_agent.py`:

```python
# Tìm dòng này:
OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"

# Đổi thành (lấy IP từ lệnh trên):
OLLAMA_ENDPOINT = "http://172.x.x.x:11434/api/chat"
```

---

### Lỗi: "nmap command not found"

```bash
# Cài Nmap
sudo apt update
sudo apt install nmap -y

# Test
nmap --version
```

---

### Lỗi: "No module named 'requests'"

```bash
# Cài requests
pip3 install requests

# Hoặc
python3 -m pip install --user requests
```

---

## 🎯 Script tự động setup (Copy & paste)

Tạo file `setup_wsl.sh`:

```bash
#!/bin/bash

echo "🚀 Setting up Wireless Security Agent in WSL"

# Update packages
echo "📦 Updating packages..."
sudo apt update

# Install Nikto
echo "🔧 Installing Nikto..."
sudo apt install nikto -y

# Install Nmap
echo "🔧 Installing Nmap..."
sudo apt install nmap -y

# Install Python pip
echo "🐍 Installing Python pip..."
sudo apt install python3-pip -y

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip3 install requests

# Get Windows host IP
export WINDOWS_HOST=$(ip route | grep default | awk '{print $3}')

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Summary:"
nikto -Version
nmap --version
python3 --version
echo ""
echo "🌐 Windows host IP: $WINDOWS_HOST"
echo ""
echo "🎯 Test Ollama connection:"
echo "   curl http://localhost:11434/api/tags"
echo ""
echo "🚀 Ready to run:"
echo "   cd /mnt/e/Wireless"
echo "   python3 ollama_agents.py"
```

**Chạy script:**

```bash
cd /mnt/e/Wireless
chmod +x setup_wsl.sh
./setup_wsl.sh
```

---

## 📊 So sánh: Windows vs WSL

| Tính năng | Windows native | WSL Ubuntu |
|-----------|---------------|------------|
| Nikto | ❌ Khó cài | ✅ Dễ (`apt install`) |
| Nmap | ✅ OK | ✅ OK |
| Performance | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Ổn định | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Tools ecosystem | Limited | Full Linux tools |

---

## 🎓 Tips & Best Practices

### Tip 1: Tạo alias

Thêm vào `~/.bashrc`:

```bash
# Thêm vào cuối file
alias scan='cd /mnt/e/Wireless && python3 ollama_agents.py'
alias soc='cd /mnt/e/Wireless && python3 integrated_security_agent.py'

# Reload
source ~/.bashrc
```

Sau đó chỉ cần gõ:
```bash
scan
# Hoặc
soc
```

---

### Tip 2: Script wrapper

Tạo file `scan.sh`:

```bash
#!/bin/bash
cd /mnt/e/Wireless
python3 ollama_agents.py "$@"
```

Sử dụng:
```bash
chmod +x scan.sh
./scan.sh
```

---

### Tip 3: Ollama auto-start

Nếu Ollama chưa chạy, tạo script check:

```bash
#!/bin/bash

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "⚠️  Ollama is not running!"
    echo "Please start Ollama on Windows:"
    echo "  1. Open PowerShell"
    echo "  2. Run: ollama serve"
    exit 1
fi

echo "✅ Ollama is running"
cd /mnt/e/Wireless
python3 ollama_agents.py
```

---

## ✅ Checklist trước khi chạy

- [ ] Nikto installed: `nikto -Version`
- [ ] Nmap installed: `nmap --version`
- [ ] Python3 installed: `python3 --version`
- [ ] Requests installed: `pip3 list | grep requests`
- [ ] Ollama running: `curl http://localhost:11434/api/tags`
- [ ] In project directory: `cd /mnt/e/Wireless`

Nếu tất cả OK → Chạy thôi! 🚀

---

## 🎯 Quick Start Commands

```bash
# 1. Mở WSL Ubuntu
wsl

# 2. Đi tới project
cd /mnt/e/Wireless

# 3. Chạy agent
python3 ollama_agents.py

# 4. Test với Nikto
[You]: Check web vulnerabilities on example.com
```

---

## 🎉 Kết luận

Bạn đã có:
- ✅ Nikto trên WSL Ubuntu
- ✅ Nmap
- ✅ Python + dependencies
- ✅ Access tới Windows files
- ✅ Connection tới Ollama

**Sẵn sàng scan với full tools! 🔒**

---

**Version:** 2.0
**Platform:** WSL Ubuntu
**Status:** ✅ Ready
