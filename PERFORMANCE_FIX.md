# Performance Fix: Multi-Model Optimization

## 🐛 Vấn đề

deepseek-r1:latest quá chậm (296-297s timeout) cho các task đơn giản:
- "who are you" → timeout
- "attack hellogroup" → timeout ở intent classification

## ✅ Giải pháp

### 1. Tách biệt model theo task complexity

| Task Type | Model | Lý do |
|-----------|-------|-------|
| **Intent Classification** | FunctionGemma/nemotron (planner) | Task đơn giản, cần nhanh |
| **Question Answering** | Default model (lightweight) | Câu hỏi đơn giản |
| **Tool Selection (Planner)** | FunctionGemma | Function calling, nhanh |
| **Output Analysis (Analyzer)** | nemotron-3-nano/deepseek-r1 | Cần reasoning nhưng có thể dùng lightweight |
| **Complex Reasoning** | deepseek-r1 | Chỉ khi thực sự cần |

### 2. Auto-detect ưu tiên lightweight models

Default model sẽ **KHÔNG BAO GIỜ** là deepseek-r1 hoặc qwen3 (quá chậm).

Ưu tiên:
1. mistral, nemotron, functiongemma, qwen2.5, llama3.2, phi, gemma
2. Các model khác (nhưng cảnh báo nếu là slow model)

### 3. Intent Classifier dùng Planner Model

Intent classification là task đơn giản → dùng FunctionGemma (planner model) thay vì default model.

### 4. Intelligence Layer dùng Planner Model

Intelligence layer cũng dùng planner model (FunctionGemma) cho các task nhanh.

## 📊 Model Usage Map

```
User Query
    ↓
Intent Classifier → FunctionGemma (FAST) ✅
    ↓
Question Tool → Default model (lightweight) ✅
    ↓
Planner → FunctionGemma (function calling) ✅
    ↓
Executor → qwen2.5-coder (nếu có) ✅
    ↓
Analyzer → nemotron-3-nano (FAST) hoặc deepseek-r1 (nếu cần reasoning sâu) ✅
    ↓
Reasoning → deepseek-r1 (chỉ khi thực sự cần) ✅
```

## 🚀 Kết quả

- ✅ Intent classification: **Nhanh** (FunctionGemma)
- ✅ Question answering: **Nhanh** (default lightweight model)
- ✅ Tool selection: **Nhanh** (FunctionGemma với function calling)
- ✅ Output analysis: **Nhanh** (nemotron-3-nano) hoặc **Chất lượng** (deepseek-r1 khi cần)
- ✅ Complex reasoning: **Chất lượng** (deepseek-r1)

## ⚙️ Configuration

### Current Setup (từ log)
```
Planner: functiongemma:270m ✅ (FAST)
Analyzer: nemotron-3-nano:30b ✅ (FAST)
Reasoning: deepseek-r1:latest ✅ (QUALITY)
Default: mistral ✅ (FAST - từ config.json)
```

### Recommended
```bash
# Đảm bảo default model là lightweight
/model mistral:latest  # hoặc nemotron-mini, qwen2.5, etc.

# Planner đã có FunctionGemma ✅
# Analyzer đã có nemotron-3-nano ✅
# Reasoning đã có deepseek-r1 ✅
```

## 🔍 Debug

Nếu vẫn chậm, kiểm tra:
1. Default model có phải là deepseek-r1 không?
   ```bash
   /model
   ```
2. Intent classifier có dùng planner model không?
   - Check log: "Thinking (functiongemma:270m)" thay vì "Thinking (deepseek-r1:latest)"
3. Question tool có dùng default model lightweight không?

## 📝 Notes

- Default model **KHÔNG BAO GIỜ** nên là deepseek-r1 cho simple tasks
- deepseek-r1 chỉ dùng cho:
  - Analyzer (nếu cần reasoning sâu)
  - Reasoning model (complex reasoning tasks)
- FunctionGemma là lựa chọn tốt nhất cho planner (function calling + nhanh)
