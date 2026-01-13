# UI Module - Beautiful Interface Components

Module này cung cấp các components và formatters để cải thiện giao diện hiển thị của SNODE.

## Cấu trúc

```
app/ui/
├── __init__.py          # Module exports
├── console.py           # Console manager với Rich
├── themes.py            # Theme và color schemes
├── components.py        # Reusable UI components
├── formatters.py        # High-level formatting functions
└── autochain.py         # AutoChain mode specific components
```

## Components

### 1. TargetInfoCard
Hiển thị thông tin target với company info:
```python
from app.ui import TargetInfoCard, get_console

card = TargetInfoCard()
console = get_console()
console.print(card.render("example.com", company_info))
```

### 2. CompanyInfoCard
Hiển thị thông tin công ty:
```python
from app.ui import CompanyInfoCard

card = CompanyInfoCard()
console.print(card.render(company_info))
```

### 3. FindingCard
Hiển thị một finding (subdomain, port, vulnerability):
```python
from app.ui import FindingCard

card = FindingCard()
console.print(card.render("vulnerability", {"cve": "CVE-2024-1234"}, severity="high"))
```

### 4. ToolResultCard
Hiển thị kết quả tool execution:
```python
from app.ui import ToolResultCard

card = ToolResultCard()
console.print(card.render("nmap", output, success=True))
```

### 5. AnalysisCard
Hiển thị analysis results:
```python
from app.ui import AnalysisCard

card = AnalysisCard()
console.print(card.render(analysis_dict))
```

### 6. ProgressIndicator
Hiển thị progress bar:
```python
from app.ui import ProgressIndicator

indicator = ProgressIndicator()
console.print(indicator.render(3, 5, "AutoChain Progress"))
```

## Formatters (Convenience Functions)

### format_target_info()
```python
from app.ui import format_target_info

format_target_info("example.com", company_info)
```

### format_company_info()
```python
from app.ui import format_company_info

format_company_info(company_info)
```

### format_findings()
```python
from app.ui import format_findings

format_findings(findings_list, finding_type="Vulnerability")
```

### format_tool_results()
```python
from app.ui import format_tool_results

format_tool_results({"nmap": {"success": True, "output": "..."}})
```

### format_analysis()
```python
from app.ui import format_analysis

format_analysis({"findings": [...], "summary": "..."})
```

## Themes

Customize colors và icons:
```python
from app.ui import Theme, set_theme

custom_theme = Theme(
    primary="blue",
    success="green",
    error="red"
)
set_theme(custom_theme)
```

## AutoChain Components

### AutoChainProgress
```python
from app.ui import AutoChainProgress

progress = AutoChainProgress()
progress.render_header(1, 5)
progress.render_iteration_summary(1, "Summary text", tools=["nmap"], failed=[])
progress.render_completion()
```

## Ví dụ sử dụng

### Trong target_verification_tool.py:
```python
from app.ui import format_target_info, format_company_info

# Hiển thị target info với company details
format_target_info(domain, company_info)
```

### Trong analyzer_tool.py:
```python
from app.ui import format_analysis, format_findings

# Hiển thị analysis results
format_analysis(analysis_dict)
```

### Trong CLI:
```python
from app.ui import get_console, format_tool_results

console = get_console()
format_tool_results(results)
```

## Lợi ích

1. **Consistent styling**: Tất cả output đều có cùng style
2. **Reusable**: Components có thể dùng lại ở nhiều nơi
3. **Maintainable**: Dễ maintain và update
4. **Beautiful**: Output đẹp hơn với Rich library
5. **Customizable**: Có thể customize theme và colors
