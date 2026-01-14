# Multi-Model Architecture Guide

## 📌 Tổng quan

SNODE hỗ trợ multi-model architecture để tối ưu hiệu suất cho từng loại task:

| Nhiệm vụ | Model phù hợp | Mục đích |
|----------|---------------|----------|
| **Planner** | FunctionGemma, nemotron-mini | Tool selection với function calling |
| **Analyzer** | deepseek-r1, qwen3, nemotron-3-nano | Phân tích output và đề xuất next steps |
| **Executor** | qwen2.5-coder, codellama, starcoder2 | Generate code/commands |
| **Reasoning** | deepseek-r1, qwen3, llama3 | Complex reasoning tasks |

## 🎯 Model Selection Strategy

### 1. Planner Model (Tool Selection)
**Mục đích**: Chọn tools phù hợp để chạy

**Model được khuyến nghị**:
- ✅ **FunctionGemma** (301MB) - Chuyên về function calling, nhanh, tốn ít tài nguyên
- ✅ **nemotron-mini** - Nhẹ, phù hợp cho tool selection

**Khi nào dùng**: Khi user yêu cầu scan/recon/exploit, hệ thống cần chọn tools phù hợp

**Ví dụ**:
```bash
/model planner functiongemma:latest
```

### 2. Analyzer Model (Output Analysis)
**Mục đích**: Phân tích kết quả từ tools và đề xuất next steps

**Model được khuyến nghị**:
- ✅ **deepseek-r1** - Reasoning tốt, phù hợp cho analysis
- ✅ **qwen3** - Balanced performance
- ✅ **nemotron-3-nano** - Nhẹ hơn nhưng vẫn tốt

**Khi nào dùng**: Sau khi tools chạy xong, cần phân tích output và suggest next tool

**Ví dụ**:
```bash
/model analyzer deepseek-r1:latest
```

### 3. Executor Model (Code/Command Generation)
**Mục đích**: Generate code hoặc commands phức tạp

**Model được khuyến nghị**:
- ✅ **qwen2.5-coder** - Chuyên về coding
- ✅ **codellama** - Code generation tốt
- ✅ **starcoder2** - Large code model

**Khi nào dùng**: Khi cần generate custom scripts, complex commands, hoặc code snippets

**Ví dụ**:
```bash
/model executor qwen2.5-coder:latest
```

### 4. Reasoning Model (Complex Reasoning)
**Mục đích**: Xử lý các task cần reasoning sâu

**Model được khuyến nghị**:
- ✅ **deepseek-r1** - Reasoning tốt nhất
- ✅ **qwen3** - Balanced
- ✅ **llama3** - Alternative

**Khi nào dùng**: Khi cần reasoning phức tạp, multi-step planning, hoặc analysis sâu

**Ví dụ**:
```bash
/model reasoning deepseek-r1:latest
```

## 🚀 Setup nhanh

### Setup đầy đủ (Recommended)
```bash
# Pull các models
ollama pull functiongemma:latest
ollama pull deepseek-r1:latest
ollama pull qwen2.5-coder:latest

# Configure trong SNODE
/model planner functiongemma:latest
/model analyzer deepseek-r1:latest
/model executor qwen2.5-coder:latest
/model reasoning deepseek-r1:latest
```

### Setup tối thiểu (Resource-constrained)
```bash
# Chỉ cần 2 models
ollama pull functiongemma:latest
ollama pull nemotron-3-nano:latest

# Configure
/model planner functiongemma:latest
/model analyzer nemotron-3-nano:latest
# Executor và Reasoning sẽ dùng default model
```

## 📊 Auto-Detection

Hệ thống tự động detect và set models khi khởi động:

1. **FunctionGemma** → Planner model
2. **nemotron-3-nano** hoặc **deepseek-r1** → Analyzer model
3. **qwen2.5-coder** hoặc **codellama** → Executor model
4. **deepseek-r1** hoặc **qwen3** → Reasoning model

## 🔧 CLI Commands

### Xem config hiện tại
```bash
/model
```

### Set từng model
```bash
/model planner functiongemma:latest
/model analyzer deepseek-r1:latest
/model executor qwen2.5-coder:latest
/model reasoning deepseek-r1:latest
```

### Set default model
```bash
/model mistral:latest
```

## 💡 Best Practices

### 1. Resource Management
- **FunctionGemma** (301MB) - Nhẹ nhất, dùng cho planner
- **nemotron-3-nano** - Nhẹ, dùng cho analyzer nếu thiếu RAM
- **deepseek-r1** - Nặng nhưng reasoning tốt, dùng cho analyzer/reasoning

### 2. Performance vs Quality
- **Fast path**: FunctionGemma (planner) + nemotron-3-nano (analyzer)
- **Quality path**: FunctionGemma (planner) + deepseek-r1 (analyzer/reasoning)

### 3. Use Cases

**Simple pentest flow**:
- Planner: FunctionGemma
- Analyzer: nemotron-3-nano

**Complex multi-step attack**:
- Planner: FunctionGemma
- Analyzer: deepseek-r1
- Reasoning: deepseek-r1

**Code-heavy tasks**:
- Executor: qwen2.5-coder

## 🎨 Architecture Flow

```
User Query
    ↓
Intent Classifier (default model)
    ↓
Planner (FunctionGemma) → Select tools via function calling
    ↓
Executor (qwen2.5-coder) → Generate commands if needed
    ↓
Tools Execute
    ↓
Analyzer (deepseek-r1) → Analyze output, suggest next steps
    ↓
Response to User
```

## 📝 Notes

- Nếu model không được set, hệ thống sẽ dùng default model
- Auto-detection chỉ chạy khi khởi động
- Có thể override bất kỳ lúc nào bằng CLI commands
- FunctionGemma tự động sử dụng function calling format khi được set làm planner
